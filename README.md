# Autenticador IoT em três etapas

Servidor FastAPI + site + terminal simulado (substitui o ESP32 durante o desenvolvimento).

## Instalação

```bash
python -m venv .venv
source .venv/Scripts/activate      # Git Bash no Windows (Linux/Mac: .venv/bin/activate)
pip install -r requirements.txt
```

## Rodar com HTTPS/WSS

Uma vez só, dentro de `servidor/`:

```bash
python gerar_certificado.py
```

Isso gera `cert.pem` e `key.pem` válidos para `localhost`, `127.0.0.1` e o IP do notebook na rede.
Se o IP mudar (outra rede), gere de novo.

Terminal 1, em `servidor/`:

```bash
uvicorn main:app --reload --host 0.0.0.0 --ssl-keyfile key.pem --ssl-certfile cert.pem
```

Terminal 2, em `terminal_simulado/`:

```bash
python terminal.py            # fluxo normal
python terminal.py --ataque   # menu de ataques para a demonstração
```

Abra `https://127.0.0.1:8000`. O navegador vai avisar que o certificado é autoassinado:
clique em "Avançado" → "Continuar". O terminal não precisa disso porque confia
somente no `cert.pem` do servidor.

## Rodar sem TLS (depuração)

```bash
uvicorn main:app --reload
python terminal.py --sem-tls
```

## Usuário e segredos de teste

- Login: `admin@lab.local` / `admin123`
- Cartão `A1B2C3D4`, PIN `1234`, gesto `esquerda,frente,direita`, `n` nega o pedido
