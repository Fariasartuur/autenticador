import asyncio
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from db import conectar, iniciar_banco
from seguranca import (carregar_chave_terminal, gerar_nonce, gerar_token, hash_senha,
                       montar_mensagem, verificar_assinatura, verificar_senha)

ETAPAS_VALIDAS = ["cartao", "pin", "gesto"]
VALIDADE_PEDIDO = 120      # segundos para confirmar no terminal
VALIDADE_SESSAO = 3600     # 1 hora logado

# ---------- Funções auxiliares ----------

def para_lista(texto: str) -> list[str]:
    return [e for e in texto.split(",") if e]

def para_texto(lista: list[str]) -> str:
    # mantém sempre a ordem cartao -> pin -> gesto
    return ",".join(e for e in ETAPAS_VALIDAS if e in lista)

def registrar_evento(conn, tipo, usuario_id=None, pedido_id=None, detalhe=None):
    conn.execute(
        "INSERT INTO eventos (usuario_id, pedido_id, tipo, detalhe, criado_em) "
        "VALUES (?, ?, ?, ?, ?)",
        (usuario_id, pedido_id, tipo, detalhe, time.time()),
    )

def criar_pedido(conn, usuario, tipo: str, etapas_novas: str | None = None) -> str:
    agora = time.time()
    # só um pedido ativo por vez no terminal
    conn.execute("UPDATE pedidos SET status = 'expirado' WHERE status = 'pendente'")

    pedido_id = uuid.uuid4().hex
    conn.execute(
        "INSERT INTO pedidos (id, usuario_id, tipo, nonce, etapas, etapas_novas, criado_em, expira_em) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (pedido_id, usuario["id"], tipo, gerar_nonce(), usuario["etapas_ativas"],
         etapas_novas, agora, agora + VALIDADE_PEDIDO),
    )
    registrar_evento(conn, "pedido_criado", usuario["id"], pedido_id, tipo)
    return pedido_id

# ---------- Inicialização ----------

@asynccontextmanager
async def lifespan(app: FastAPI):
    iniciar_banco()
    with conectar() as conn:
        if not conn.execute("SELECT 1 FROM usuarios").fetchone():
            conn.execute(
                "INSERT INTO usuarios (email, senha_hash) VALUES (?, ?)",
                ("admin@lab.local", hash_senha("admin123")),
            )
    yield

app = FastAPI(lifespan=lifespan)

# ---------- Login ----------

class LoginEntrada(BaseModel):
    email: str
    password: str

@app.post("/api/login")
def login(dados: LoginEntrada, response: Response):
    with conectar() as conn:
        usuario = conn.execute(
            "SELECT * FROM usuarios WHERE email = ?", (dados.email,)
        ).fetchone()

        senha_ok = usuario is not None and verificar_senha(dados.password, usuario["senha_hash"])
        if senha_ok:
            pedido_id = criar_pedido(conn, usuario, "login")
        else:
            registrar_evento(conn, "senha_incorreta", detalhe=dados.email)

    if not senha_ok:
        raise HTTPException(status_code=401, detail="Email ou senha incorretos")

    response.set_cookie("pedido_login", pedido_id, httponly=True,
                        samesite="strict", max_age=VALIDADE_PEDIDO)
    return {"pedido_id": pedido_id}

@app.get("/api/login/{pedido_id}/status")
def status_pedido(pedido_id: str, request: Request, response: Response):
    with conectar() as conn:
        pedido = conn.execute(
            "SELECT * FROM pedidos WHERE id = ?", (pedido_id,)
        ).fetchone()
        if not pedido:
            raise HTTPException(status_code=404, detail="Pedido não encontrado")

        status = pedido["status"]

        if status == "pendente" and time.time() > pedido["expira_em"]:
            status = "expirado"
            conn.execute("UPDATE pedidos SET status = 'expirado' WHERE id = ?", (pedido_id,))
            registrar_evento(conn, "expirado", pedido["usuario_id"], pedido_id)

        if status == "aprovado" and pedido["tipo"] == "login":
            if request.cookies.get("pedido_login") != pedido_id:
                raise HTTPException(status_code=403, detail="Pedido de outro navegador")

            token = gerar_token()
            conn.execute(
                "INSERT INTO sessoes (token, usuario_id, expira_em) VALUES (?, ?, ?)",
                (token, pedido["usuario_id"], time.time() + VALIDADE_SESSAO),
            )
            conn.execute("UPDATE pedidos SET status = 'concluido' WHERE id = ?", (pedido_id,))
            registrar_evento(conn, "login_liberado", pedido["usuario_id"], pedido_id)

            response.set_cookie("sessao", token, httponly=True,
                                samesite="strict", max_age=VALIDADE_SESSAO)
            response.delete_cookie("pedido_login")

    if status == "concluido":
        status = "aprovado"
    return {"status": status}

# ---------- Sessão ----------

def usuario_logado(request: Request):
    token = request.cookies.get("sessao")
    if not token:
        raise HTTPException(status_code=401, detail="Não logado")

    with conectar() as conn:
        usuario = conn.execute(
            "SELECT u.* FROM sessoes s JOIN usuarios u ON u.id = s.usuario_id "
            "WHERE s.token = ? AND s.expira_em > ?",
            (token, time.time()),
        ).fetchone()

    if not usuario:
        raise HTTPException(status_code=401, detail="Sessão expirada")
    return usuario

@app.post("/api/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get("sessao")
    if token:
        with conectar() as conn:
            conn.execute("DELETE FROM sessoes WHERE token = ?", (token,))
    response.delete_cookie("sessao")
    return {"ok": True}

# ---------- Configurações ----------

class ConfigEntrada(BaseModel):
    etapas: list[str]

@app.get("/api/configuracoes")
def ler_configuracoes(usuario=Depends(usuario_logado)):
    ativas = para_lista(usuario["etapas_ativas"])
    return {"etapas": {e: {"ativa": e in ativas} for e in ETAPAS_VALIDAS}}

@app.put("/api/configuracoes")
def alterar_configuracoes(dados: ConfigEntrada, usuario=Depends(usuario_logado)):
    invalidas = set(dados.etapas) - set(ETAPAS_VALIDAS)
    if invalidas:
        raise HTTPException(status_code=400, detail=f"Etapas inválidas: {invalidas}")

    novas = set(dados.etapas) | {"cartao"}

    novas_texto = para_texto(list(novas))
    if novas_texto == usuario["etapas_ativas"]:
        raise HTTPException(status_code=400, detail="Nada mudou")

    with conectar() as conn:
        pedido_id = criar_pedido(conn, usuario, "config", etapas_novas=novas_texto)
    return {"pedido_id": pedido_id}

# ---------- Terminal ----------

DECISOES = ["aprovado", "negado", "bloqueado"]

def buscar_pedido_pendente():
    with conectar() as conn:
        return conn.execute(
            "SELECT p.*, u.email FROM pedidos p JOIN usuarios u ON u.id = p.usuario_id "
            "WHERE p.status = 'pendente' AND p.expira_em > ? "
            "ORDER BY p.criado_em DESC LIMIT 1",
            (time.time(),),
        ).fetchone()

def processar_resposta(chave, msg: dict) -> tuple[bool, str]:
    pedido_id = msg.get("pedido_id")
    decisao = msg.get("decisao")
    etapas = msg.get("etapas")
    assinatura = msg.get("assinatura", "")

    if decisao not in DECISOES:
        return False, "decisão inválida"
    if not isinstance(etapas, list) or not all(isinstance(e, str) for e in etapas):
        return False, "etapas em formato inválido"

    with conectar() as conn:
        pedido = conn.execute("SELECT * FROM pedidos WHERE id = ?", (pedido_id,)).fetchone()
        if not pedido:
            return False, "pedido desconhecido"

        uid = pedido["usuario_id"]

        if pedido["status"] != "pendente":
            registrar_evento(conn, "resposta_repetida", uid, pedido_id)
            return False, "pedido já respondido"

        if time.time() > pedido["expira_em"]:
            conn.execute("UPDATE pedidos SET status = 'expirado' WHERE id = ?", (pedido_id,))
            registrar_evento(conn, "expirado", uid, pedido_id)
            return False, "pedido expirado"

        mensagem = montar_mensagem(pedido_id, pedido["nonce"], decisao, etapas)
        if not verificar_assinatura(chave, mensagem, assinatura):
            registrar_evento(conn, "assinatura_invalida", uid, pedido_id)
            return False, "assinatura inválida"

        if decisao == "aprovado" and etapas != para_lista(pedido["etapas"]):
            registrar_evento(conn, "etapas_divergentes", uid, pedido_id, ",".join(etapas))
            return False, "etapas não conferem com a política"

        conn.execute("UPDATE pedidos SET status = ? WHERE id = ?", (decisao, pedido_id))
        registrar_evento(conn, decisao, uid, pedido_id)

        if decisao == "aprovado" and pedido["tipo"] == "config":
            conn.execute(
                "UPDATE usuarios SET etapas_ativas = ? WHERE id = ?",
                (pedido["etapas_novas"], uid),
            )
            registrar_evento(conn, "politica_alterada", uid, pedido_id,
                             f"{pedido['etapas']} -> {pedido['etapas_novas']}")

    return True, "ok"

@app.websocket("/ws/terminal")
async def ws_terminal(ws: WebSocket):
    await ws.accept()

    # 1. o terminal prova que tem a chave privada
    try:
        chave = carregar_chave_terminal()
    except FileNotFoundError:
        await ws.close(code=1011, reason="terminal_pub.pem não encontrado")
        return

    desafio = gerar_nonce()
    await ws.send_json({"tipo": "desafio", "nonce": desafio})
    try:
        hello = await ws.receive_json()
    except WebSocketDisconnect:
        return
    if not verificar_assinatura(chave, f"terminal|{desafio}".encode(), hello.get("assinatura", "")):
        await ws.close(code=1008, reason="terminal não autenticado")
        return

    # 2. envia pedidos pendentes e recebe respostas ao mesmo tempo
    enviados = set()

    async def enviar_pedidos():
        while True:
            pedido = buscar_pedido_pendente()
            if pedido and pedido["id"] not in enviados:
                await ws.send_json({
                    "tipo": "pedido",
                    "pedido_id": pedido["id"],
                    "nonce": pedido["nonce"],
                    "acao": pedido["tipo"],
                    "usuario": pedido["email"],
                    "etapas": para_lista(pedido["etapas"]),
                    "expira_em": pedido["expira_em"],
                })
                enviados.add(pedido["id"])
            await asyncio.sleep(0.5)

    tarefa = asyncio.create_task(enviar_pedidos())
    try:
        while True:
            msg = await ws.receive_json()
            if msg.get("tipo") == "resposta":
                ok, motivo = processar_resposta(chave, msg)
                await ws.send_json({"tipo": "resultado", "pedido_id": msg.get("pedido_id"),
                                    "ok": ok, "motivo": motivo})
    except WebSocketDisconnect:
        pass
    finally:
        tarefa.cancel()

# ---------- Páginas ----------

@app.get("/")
def raiz():
    return RedirectResponse("/static/login.html")

app.mount("/static", StaticFiles(directory="static"), name="static")