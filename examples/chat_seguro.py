# --- No seu novo projeto (ex: chat_seguro.py) ---

# Você importa a classe cliente que desenvolvemos
from primeguard_client import PrimeGuardClient 
import json

# Você, como cliente, guarda a sua chave de API de forma segura.
# (Lendo de um ficheiro de configuração ou de uma variável de ambiente, nunca diretamente no código!)
MINHA_CHAVE_API_SECRETA = "pg_live_6bd909383130fffbda548c822b58eda6409d928b9173d5b3"

# O nome de utilizador do seu amigo (ele também se registou no painel)
DESTINATARIO = "bob_real" 

# Inicializa o cliente da API
cliente = PrimeGuardClient()

# A mensagem que você quer enviar
mensagem_secreta = {
    "de": "seu_nome_de_utilizador",
    "para": DESTINATARIO,
    "conteudo": "Wiencci, a nossa API está a funcionar! Missão cumprida. 😎"
}

try:
    print("A usar a minha chave de API para criptografar uma nova mensagem...")
    
    # 1. Usa a chave para criptografar a mensagem para o seu amigo
    pacote_cifrado = cliente.encrypt(
        api_key=MINHA_CHAVE_API_SECRETA,
        destinatario_id=DESTINATARIO,
        dados_em_bytes=json.dumps(mensagem_secreta).encode('utf-8')
    )
    
    print("✅ Mensagem criptografada com sucesso!")
    print("Enviando este pacote seguro pela rede...")
    
    # (Aqui, você enviaria o `pacote_cifrado` para o seu amigo)

except Exception as e:
    print(f"❌ Algo correu mal: {e}")