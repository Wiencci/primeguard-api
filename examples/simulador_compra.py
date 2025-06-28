# simulador_compra.py
# Este script simula uma empresa externa, a "TechCorp",
# que "comprou" o acesso à API e está a usá-la pela primeira vez.

import requests
import json
import base64

# O cliente externo só precisa de saber o endereço base da API.
API_BASE_URL = "http://127.0.0.1:5000"

def registrar_nova_empresa(nome: str) -> str:
    """
    Simula o passo de registo para obter uma chave de API.
    Retorna a chave de API se for bem-sucedido.
    """
    url = f"{API_BASE_URL}/register"
    print(f"1. A TechCorp está a fazer um pedido POST para: {url}")
    
    payload = {"nome_cliente": nome}
    response = requests.post(url, json=payload)
    
    # Verifica se o pedido foi bem-sucedido
    response.raise_for_status() 
    
    dados_resposta = response.json()
    api_key = dados_resposta.get('api_key')
    
    print("2. ✅ Resposta do servidor recebida com sucesso!")
    print(f"   -> Chave de API secreta para '{nome}': {api_key[:10]}... (o cliente deve guardar isto em segurança)")
    
    return api_key

def enviar_mensagem_segura(api_key: str, remetente: str, destinatario: str, mensagem: dict):
    """
    Usa a chave de API obtida para enviar uma mensagem criptografada.
    """
    url = f"{API_BASE_URL}/encrypt"
    print(f"\n3. A '{remetente}' está a usar a sua nova chave para enviar uma mensagem para '{destinatario}'.")
    
    headers = {"Authorization": f"Bearer {api_key}"}
    dados_em_bytes = json.dumps(mensagem).encode('utf-8')
    dados_base64 = base64.b64encode(dados_em_bytes).decode('utf-8')
    
    payload = {
        "destinatario_id": destinatario,
        "dados_base64": dados_base64
    }
    
    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    
    print(f"4. ✅ Mensagem para '{destinatario}' criptografada e enviada com sucesso!")
    print("   -> O pacote seguro foi gerado pelo servidor e retornado.")


if __name__ == "__main__":
    print("--- SIMULADOR DE CLIENTE EXTERNO (TechCorp) ---")
    
    try:
        # Passo 1: A "TechCorp" regista-se para obter a sua chave.
        NOME_EMPRESA = "techcorp"
        CHAVE_TECHCORP = registrar_nova_empresa(NOME_EMPRESA)
        
        # Passo 2: A "TechCorp" usa a sua nova chave para enviar uma proposta para "alice_real".
        # (Assumimos que "alice_real" já existe no sistema)
        DESTINATARIO_ALVO = "alice_real" 
        proposta_comercial = {
            "proposta_id": "PROP-2025-001",
            "para": "alice_real",
            "de": "techcorp",
            "detalhes": "Proposta de parceria estratégica para o projeto PrimeGuard.",
            "valor_anual": 75000.00
        }
        
        enviar_mensagem_segura(
            api_key=CHAVE_TECHCORP,
            remetente=NOME_EMPRESA,
            destinatario=DESTINATARIO_ALVO,
            mensagem=proposta_comercial
        )
        
        print("\n--- SIMULAÇÃO CONCLUÍDA COM SUCESSO ---")
        print("A TechCorp conseguiu registar-se e enviar uma mensagem encriptada sem precisar de conhecer nenhum detalhe interno da API.")

    except requests.exceptions.HTTPError as e:
        print(f"\n❌ ERRO NA API: {e.response.status_code}")
        print(f"   Detalhe: {e.response.text}")
    except requests.exceptions.RequestException as e:
        print(f"\n❌ ERRO DE CONEXÃO: Não foi possível conectar à API.")
        print(f"   Verifique se o servidor 'api_server.py' está a rodar.")