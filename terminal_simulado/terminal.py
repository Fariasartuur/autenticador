import asyncio
import base64
import hmac
import json
import sys
from pathlib import Path

import websockets
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

SERVIDOR = "ws://127.0.0.1:8000/ws/terminal"
PASTA = Path(__file__).parent
CHAVE_PRIVADA = PASTA / "terminal_priv.pem"
CHAVE_PUBLICA = PASTA.parent / "servidor" / "terminal_pub.pem"
MAX_TENTATIVAS = 3

# Segredos cadastrados no terminal (no ESP32 ficam na memória dele)
CADASTRO = {
    "cartao": "A1B2C3D4",
    "pin": "1234",
    "gesto": "esquerda,frente,direita",
}

PERGUNTAS = {
    "cartao": "Aproxime o cartão (digite o UID): ",
    "pin": "Digite o PIN: ",
    "gesto": "Faça a sequência (ex.: esquerda,frente,direita): ",
}

# ---------- Chaves ----------

def carregar_ou_criar_chave():
    if CHAVE_PRIVADA.exists():
        return serialization.load_pem_private_key(CHAVE_PRIVADA.read_bytes(), password=None)

    chave = ec.generate_private_key(ec.SECP256R1())
    CHAVE_PRIVADA.write_bytes(chave.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    CHAVE_PUBLICA.write_bytes(chave.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    print(f"Par de chaves criado. Chave pública salva em {CHAVE_PUBLICA}")
    return chave

def assinar(chave, texto: str) -> str:
    assinatura = chave.sign(texto.encode(), ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(assinatura).decode()

# ---------- Etapas ----------

async def perguntar(texto: str) -> str:
    resposta = await asyncio.to_thread(input, texto)
    return resposta.strip()

async def executar_etapas(etapas: list[str]) -> tuple[str, list[str]]:
    concluidas = []
    for etapa in etapas:
        for tentativa in range(1, MAX_TENTATIVAS + 1):
            resposta = await perguntar(PERGUNTAS[etapa])
            if resposta.lower() == "n":            # botão de negar
                return "negado", concluidas
            if hmac.compare_digest(resposta.encode(), CADASTRO[etapa].encode()):
                print("  ✓ ok")
                concluidas.append(etapa)
                break
            print(f"  ✗ incorreto ({tentativa}/{MAX_TENTATIVAS})")
        else:
            return "bloqueado", concluidas
    return "aprovado", concluidas

# ---------- Comunicação ----------

MODO_ATAQUE = "--ataque" in sys.argv
fila = []   # pedidos que chegaram enquanto esperávamos um resultado

def montar_resposta(chave, pedido, decisao, etapas, decisao_assinada=None):
    # decisao_assinada != decisao só no ataque de resposta alterada
    assinada = decisao_assinada or decisao
    texto = f"{pedido['pedido_id']}|{pedido['nonce']}|{assinada}|{','.join(etapas)}"
    return {
        "tipo": "resposta",
        "pedido_id": pedido["pedido_id"],
        "decisao": decisao,
        "etapas": etapas,
        "assinatura": assinar(chave, texto),
    }

async def enviar_e_aguardar(ws, resposta: dict) -> dict:
    await ws.send(json.dumps(resposta))
    while True:
        msg = json.loads(await ws.recv())
        if msg["tipo"] == "resultado":
            return msg
        fila.append(msg)

def mostrar_resultado(resultado: dict, decisao: str):
    if resultado["ok"] and decisao == "aprovado":
        print("🟢 Acesso liberado pelo servidor")
    elif resultado["ok"]:
        print(f"🔴 Pedido {decisao} (registrado no servidor)")
    else:
        print(f"🔴 Recusado pelo servidor: {resultado['motivo']}")

# ---------- Ataques (para a demonstração) ----------

MENU_ATAQUE = """Modo de ataque:
  [Enter] fluxo normal
  r  reenviar a resposta do pedido anterior (repetição)
  a  assinar 'negado' e enviar 'aprovado' (resposta alterada)
  p  aprovar pulando a última etapa exigida
Escolha: """

async def executar_ataque(ws, chave, pedido, opcao: str, ultima_resposta):
    if opcao == "r":
        if not ultima_resposta:
            print("  Ainda não há resposta anterior para repetir.")
            return
        print("  Reenviando a resposta antiga...")
        resultado = await enviar_e_aguardar(ws, ultima_resposta)

    elif opcao == "a":
        print("  Assinando 'negado' e trocando para 'aprovado'...")
        resposta = montar_resposta(chave, pedido, "aprovado", pedido["etapas"],
                                   decisao_assinada="negado")
        resultado = await enviar_e_aguardar(ws, resposta)

    elif opcao == "p":
        etapas = pedido["etapas"][:-1]
        print(f"  Aprovando só com: {', '.join(etapas) or 'nenhuma etapa'}...")
        resposta = montar_resposta(chave, pedido, "aprovado", etapas)
        resultado = await enviar_e_aguardar(ws, resposta)

    else:
        print("  Opção inválida.")
        return

    mostrar_resultado(resultado, "aprovado")

# ---------- Principal ----------

async def atender_pedido(ws, chave, pedido, ultima_resposta):
    print(f"\n=== Pedido de {pedido['acao']} — {pedido['usuario']} ===")
    print(f"Etapas: {', '.join(pedido['etapas'])}")

    if MODO_ATAQUE:
        while (opcao := (await perguntar(MENU_ATAQUE)).lower()):
            await executar_ataque(ws, chave, pedido, opcao, ultima_resposta)
        print("Fluxo normal:")

    decisao, concluidas = await executar_etapas(pedido["etapas"])
    resposta = montar_resposta(chave, pedido, decisao, concluidas)
    resultado = await enviar_e_aguardar(ws, resposta)
    mostrar_resultado(resultado, decisao)
    return resposta

async def main():
    chave = carregar_ou_criar_chave()

    async with websockets.connect(SERVIDOR) as ws:
        desafio = json.loads(await ws.recv())
        await ws.send(json.dumps({
            "tipo": "hello",
            "assinatura": assinar(chave, f"terminal|{desafio['nonce']}"),
        }))
        print("Terminal conectado. Aguardando pedidos... (digite 'n' para negar)")
        if MODO_ATAQUE:
            print("Modo de ataque ativado.")

        ultima_resposta = None
        while True:
            msg = fila.pop(0) if fila else json.loads(await ws.recv())
            if msg["tipo"] == "pedido":
                ultima_resposta = await atender_pedido(ws, chave, msg, ultima_resposta)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nTerminal encerrado.")
    except websockets.ConnectionClosed as e:
        print(f"Conexão encerrada pelo servidor: {e.reason or e}")
    except OSError:
        print("Não consegui conectar. O servidor está rodando?")
