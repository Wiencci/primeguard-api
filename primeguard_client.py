# primeguard_client.py (Versão Final, Documentada e com Gestão de Credenciais)
import requests
import json
import base64
import os
import sys
import configparser

CONFIG_FILE = 'credentials.ini'

class PrimeGuardClient:
    """
    Cliente para interagir com a PrimeGuard API Híbrida.

    Esta classe abstrai os detalhes dos pedidos HTTP, permitindo uma
    interação simples e direta com os endpoints da API para registo,
    criptografia e decifragem.
    """
    def __init__(self, base_url="http://127.0.0.1:5000"):
        """
        Inicializa o cliente.

        Args:
            base_url (str, optional): O URL base do servidor da API. 
                                      Defaults to "http://127.0.0.1:5000".
        """
        self.base_url = base_url.rstrip('/')

    def _get_auth_header(self, api_key):
        """Método auxiliar para criar o cabeçalho de autorização."""
        return {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    def register(self, nome_cliente: str, email: str, senha: str) -> dict:
        """
        Regista um novo cliente no servidor através da API.

        Args:
            nome_cliente (str): O nome de utilizador desejado.
            email (str): O email do utilizador.
            senha (str): A senha do utilizador.

        Returns:
            dict: Um dicionário com a resposta da API, incluindo a nova chave.
        """
        url = f"{self.base_url}/api/register"
        headers = {"Content-Type": "application/json"}
        payload = {"nome_cliente": nome_cliente, "email": email, "senha": senha}
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()

    def encrypt(self, api_key: str, destinatario_id: str, dados_em_bytes: bytes) -> str:
        """
        Criptografa dados para um destinatário usando a API.

        Args:
            api_key (str): A chave de API do remetente.
            destinatario_id (str): O nome do cliente destinatário.
            dados_em_bytes (bytes): Os dados brutos a serem criptografados.

        Returns:
            str: O pacote seguro híbrido em formato de string JSON.
        """
        url = f"{self.base_url}/api/encrypt"
        headers = self._get_auth_header(api_key)
        dados_base64 = base64.b64encode(dados_em_bytes).decode('utf-8')
        payload = {"destinatario_id": destinatario_id, "dados_base64": dados_base64}
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()['pacote_seguro_hibrido']

    def decrypt(self, api_key: str, pacote_hibrido_json: str) -> bytes:
        """
        Decifra um pacote seguro usando a API.

        Args:
            api_key (str): A chave de API do destinatário.
            pacote_hibrido_json (str): O pacote seguro recebido.

        Returns:
            bytes: Os dados originais decifrados.
        """
        url = f"{self.base_url}/api/decrypt"
        headers = self._get_auth_header(api_key)
        payload = {"pacote_seguro_hibrido": pacote_hibrido_json}
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        dados_recuperados_base64 = response.json()['dados_recuperados_base64']
        return base64.b64decode(dados_recuperados_base64)

def obter_ou_criar_credenciais(client: PrimeGuardClient):
    """
    Verifica se o ficheiro de credenciais local existe. Se não, regista
    dois utilizadores de exemplo ('alice_real' e 'bob_real') e guarda
    as suas chaves. Se o ficheiro já existe, simplesmente lê as chaves.

    Args:
        client (PrimeGuardClient): Uma instância do cliente da API.

    Returns:
        tuple[str, str]: Uma tupla contendo a chave de API da Alice e a do Bob.
    """
    config = configparser.ConfigParser()
    
    if not os.path.exists(CONFIG_FILE):
        print(f"Ficheiro '{CONFIG_FILE}' não encontrado. A registar novos utilizadores de exemplo...")
        try:
            resposta_alice = client.register("alice_real", "alice@exemplo.com", "senha123")
            chave_alice = resposta_alice['api_key']
            print(f"✅ 'alice_real' registada com sucesso!")

            resposta_bob = client.register("bob_real", "bob@exemplo.com", "senha456")
            chave_bob = resposta_bob['api_key']
            print(f"✅ 'bob_real' registado com sucesso!")

            config['alice_real'] = {'api_key': chave_alice}
            config['bob_real'] = {'api_key': chave_bob}
            
            with open(CONFIG_FILE, 'w') as configfile:
                config.write(configfile)
            print(f"✅ Credenciais de exemplo guardadas em '{CONFIG_FILE}'.")

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 409:
                 print(f"❌ ERRO: O servidor já contém os utilizadores de exemplo.")
                 print(f"   Por favor, apague o ficheiro 'clientes.db' no servidor e tente novamente.")
                 sys.exit(1)
            else: raise e
    
    config.read(CONFIG_FILE)
    chave_alice = config['alice_real']['api_key']
    chave_bob = config['bob_real']['api_key']
    print(f"🔑 Credenciais de 'alice_real' e 'bob_real' carregadas de '{CONFIG_FILE}'.")
    return chave_alice, chave_bob