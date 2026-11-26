import asyncio
import base64
import hmac
import json
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

# ---------- Principal ----------

async def main():
    chave = carregar_ou_criar_chave()

    async with websockets.connect(SERVIDOR) as ws:
        desafio = json.loads(await ws.recv())
        await ws.send(json.dumps({
            "tipo": "hello",
            "assinatura": assinar(chave, f"terminal|{desafio['nonce']}"),
        }))
        print("Terminal conectado. Aguardando pedidos... (digite 'n' para negar)")
        decisao = None

        async for bruto in ws:
            msg = json.loads(bruto)

            if msg["tipo"] == "pedido":
                print(f"\n=== Pedido de {msg['acao']} — {msg['usuario']} ===")
                print(f"Etapas: {', '.join(msg['etapas'])}")

                decisao, concluidas = await executar_etapas(msg["etapas"])
                texto = f"{msg['pedido_id']}|{msg['nonce']}|{decisao}|{','.join(concluidas)}"
                await ws.send(json.dumps({
                    "tipo": "resposta",
                    "pedido_id": msg["pedido_id"],
                    "decisao": decisao,
                    "etapas": concluidas,
                    "assinatura": assinar(chave, texto),
                }))

            elif msg["tipo"] == "resultado":
                if msg["ok"] and decisao == "aprovado":
                    print("🟢 Acesso liberado pelo servidor")
                elif msg["ok"]:
                    print(f"🔴 Pedido {decisao} (registrado no servidor)")
                else:
                    print(f"🔴 Recusado pelo servidor: {msg['motivo']}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nTerminal encerrado.")
    except OSError:
        print("Não consegui conectar. O servidor está rodando?")