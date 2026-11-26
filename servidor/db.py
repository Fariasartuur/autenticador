import sqlite3
from contextlib import contextmanager

ARQUIVO = "autenticador.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    senha_hash TEXT NOT NULL,
    etapas_ativas TEXT NOT NULL DEFAULT 'cartao'
);

CREATE TABLE IF NOT EXISTS pedidos (
    id            TEXT PRIMARY KEY,
    usuario_id    INTEGER NOT NULL REFERENCES usuarios(id),
    tipo          TEXT NOT NULL,          -- 'login' ou 'config'
    nonce         TEXT NOT NULL,
    etapas        TEXT NOT NULL,          -- cópia da política na hora do pedido
    etapas_novas  TEXT,                   -- só para tipo 'config'
    status        TEXT NOT NULL DEFAULT 'pendente',
    criado_em     REAL NOT NULL,
    expira_em     REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS sessoes (
    token       TEXT PRIMARY KEY,
    usuario_id  INTEGER NOT NULL REFERENCES usuarios(id),
    expira_em   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS eventos (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id  INTEGER,
    pedido_id   TEXT,
    tipo        TEXT NOT NULL,
    detalhe     TEXT,
    criado_em   REAL NOT NULL
);
"""

@contextmanager
def conectar():
    conn = sqlite3.connect(ARQUIVO)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def iniciar_banco():
    with conectar() as conn:
        conn.executescript(SCHEMA)