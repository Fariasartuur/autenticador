import base64
import hashlib
import hmac
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# ---------- Senha ----------

def _scrypt(senha: str, sal: bytes) -> bytes:
    return hashlib.scrypt(senha.encode(), salt=sal, n=2**14, r=8, p=1)

def hash_senha(senha: str) -> str:
    sal = secrets.token_bytes(16)
    return f"{sal.hex()}${_scrypt(senha, sal).hex()}"

def verificar_senha(senha: str, armazenado: str) -> bool:
    sal_hex, hash_hex = armazenado.split("$")
    calculado = _scrypt(senha, bytes.fromhex(sal_hex)).hex()
    return hmac.compare_digest(calculado, hash_hex)

# ---------- Tokens ----------

def gerar_token() -> str:
    return secrets.token_urlsafe(32)

def gerar_nonce() -> str:
    return secrets.token_hex(16)

# ---------- Assinatura do terminal ----------

def carregar_chave_terminal(caminho: str = "terminal_pub.pem"):
    with open(caminho, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def montar_mensagem(pedido_id: str, nonce: str, decisao: str, etapas: list[str]) -> bytes:
    return f"{pedido_id}|{nonce}|{decisao}|{','.join(etapas)}".encode()

def verificar_assinatura(chave, mensagem: bytes, assinatura_b64: str) -> bool:
    try:
        assinatura = base64.b64decode(assinatura_b64)
        chave.verify(assinatura, mensagem, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False