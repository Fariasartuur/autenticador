"""
Gera um certificado autoassinado para rodar o servidor em HTTPS/WSS.

Uso:
    python gerar_certificado.py              # localhost, 127.0.0.1 e o IP da rede
    python gerar_certificado.py 192.168.0.42 # acrescenta outros IPs ou nomes

Cria:
    cert.pem  certificado público (o terminal usa para validar o servidor)
    key.pem   chave privada do servidor (não vai para o Git)
"""
import datetime
import ipaddress
import socket
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

PASTA = Path(__file__).parent
VALIDADE_DIAS = 365

def ip_da_rede() -> str | None:
    # descobre o IP do notebook na rede local (é nele que o ESP32 vai conectar)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))   # UDP: não envia nada, só escolhe a interface
            return s.getsockname()[0]
    except OSError:
        return None

def montar_nomes(extras: list[str]) -> list[x509.GeneralName]:
    nomes = {"localhost", "127.0.0.1", *extras}
    if ip := ip_da_rede():
        nomes.add(ip)

    resultado = []
    for nome in sorted(nomes):
        try:
            resultado.append(x509.IPAddress(ipaddress.ip_address(nome)))
        except ValueError:
            resultado.append(x509.DNSName(nome))
    return resultado

def main():
    nomes = montar_nomes(sys.argv[1:])
    chave = ec.generate_private_key(ec.SECP256R1())
    sujeito = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "autenticador-local")])
    agora = datetime.datetime.now(datetime.timezone.utc)

    certificado = (
        x509.CertificateBuilder()
        .subject_name(sujeito)
        .issuer_name(sujeito)                      # autoassinado: emissor = sujeito
        .public_key(chave.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(agora)
        .not_valid_after(agora + datetime.timedelta(days=VALIDADE_DIAS))
        .add_extension(x509.SubjectAlternativeName(nomes), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(chave, hashes.SHA256())
    )

    (PASTA / "key.pem").write_bytes(chave.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    (PASTA / "cert.pem").write_bytes(certificado.public_bytes(serialization.Encoding.PEM))

    print("Certificado criado para:")
    for n in nomes:
        print(f"  - {n.value}")
    print("\nRode o servidor com:")
    print("  uvicorn main:app --reload --host 0.0.0.0 --ssl-keyfile key.pem --ssl-certfile cert.pem")

if __name__ == "__main__":
    main()
