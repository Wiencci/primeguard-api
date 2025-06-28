# tests/test_api_flow.py (Versão Final Refatorada e Corrigida)

import pytest
import requests
import json
import base64
import time
from threading import Thread
from waitress import serve
from api_server import app

# --- Configuração do Ambiente de Teste ---
TEST_HOST = "127.0.0.1"
TEST_PORT = 5001 # Usamos uma porta de teste para não conflitar
BASE_URL = f"http://{TEST_HOST}:{TEST_PORT}"

def run_server():
    """Função para ser executada na thread do servidor."""
    serve(app, host=TEST_HOST, port=TEST_PORT)

@pytest.fixture(scope="session")
def api_server(tmp_path_factory):
    """
    Fixture de sessão: Inicia o servidor API antes de todos os testes
    e garante um banco de dados limpo e temporário para a sessão.
    """
    # Usa um banco de dados temporário para cada sessão de teste
    db_path = tmp_path_factory.mktemp("data") / "test_clientes.db"
    app.config['DATABASE_FILE'] = str(db_path)
    
    from gerenciar_chaves import inicializar_db
    import config
    config.DB_FILE = str(db_path)
    inicializar_db()

    server_thread = Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
    time.sleep(1) # Dar tempo para o servidor iniciar
    yield BASE_URL

@pytest.fixture(scope="session")
def setup_users(api_server):
    """
    Fixture de sessão: Regista os utilizadores de teste (Alice, Bob, Mallory)
    uma única vez e fornece as suas chaves para todos os testes.
    """
    # Registar Alice
    reg_alice = requests.post(f"{api_server}/api/register", json={"nome_cliente": "test_alice", "email": "alice@test.com", "senha": "123"})
    assert reg_alice.status_code == 201
    
    # Registar Bob
    reg_bob = requests.post(f"{api_server}/api/register", json={"nome_cliente": "test_bob", "email": "bob@test.com", "senha": "456"})
    assert reg_bob.status_code == 201
    
    # Registar Mallory
    reg_mallory = requests.post(f"{api_server}/api/register", json={"nome_cliente": "test_mallory", "email": "mallory@attack.com", "senha": "789"})
    assert reg_mallory.status_code == 201
    
    # Retorna um dicionário com os dados dos utilizadores
    return {
        "alice": {"name": "test_alice", "key": reg_alice.json()['api_key']},
        "bob": {"name": "test_bob", "key": reg_bob.json()['api_key']},
        "mallory": {"name": "test_mallory", "key": reg_mallory.json()['api_key']}
    }

def test_fluxo_completo_da_api(api_server, setup_users):
    """
    TESTE 1 (FLUXO FELIZ): Garante que a criptografia e decifragem funcionam.
    """
    # Obter os dados dos utilizadores a partir da fixture
    alice = setup_users['alice']
    bob = setup_users['bob']

    # CRIPTOGRAFAR
    mensagem_original = {"id": "fluxo123", "valor": 1000}
    dados_b64 = base64.b64encode(json.dumps(mensagem_original).encode('utf-8')).decode('utf-8')
    headers_alice = {'Authorization': f'Bearer {alice["key"]}'}
    payload_encrypt = {'destinatario_id': bob['name'], 'dados_base64': dados_b64}
    
    encrypt_resp = requests.post(f"{api_server}/api/encrypt", headers=headers_alice, json=payload_encrypt)
    assert encrypt_resp.status_code == 200
    pacote_seguro = encrypt_resp.json()['pacote_seguro_hibrido']

    # DECIFRAR
    headers_bob = {'Authorization': f'Bearer {bob["key"]}'}
    payload_decrypt = {'pacote_seguro_hibrido': pacote_seguro}
    
    decrypt_resp = requests.post(f"{api_server}/api/decrypt", headers=headers_bob, json=payload_decrypt)
    assert decrypt_resp.status_code == 200
    dados_rec_b64 = decrypt_resp.json()['dados_recuperados_base64']
    mensagem_decifrada = json.loads(base64.b64decode(dados_rec_b64))

    # VERIFICAR
    assert mensagem_decifrada == mensagem_original

def test_tentativa_de_decifragem_nao_autorizada(api_server, setup_users):
    """
    TESTE 2 (SEGURANÇA): Garante que Mallory não consegue decifrar a mensagem de Bob.
    """
    # Obter os dados dos utilizadores
    alice = setup_users['alice']
    bob = setup_users['bob']
    mallory = setup_users['mallory']

    # Alice encripta para Bob
    mensagem_secreta = {"info": "segredo do bob"}
    dados_b64 = base64.b64encode(json.dumps(mensagem_secreta).encode('utf-8')).decode('utf-8')
    headers_alice = {'Authorization': f'Bearer {alice["key"]}'}
    payload_encrypt = {'destinatario_id': bob['name'], 'dados_base64': dados_b64}
    
    encrypt_resp = requests.post(f"{api_server}/api/encrypt", headers=headers_alice, json=payload_encrypt)
    assert encrypt_resp.status_code == 200
    pacote_para_bob = encrypt_resp.json()['pacote_seguro_hibrido']

    # Mallory tenta decifrar
    print("\nSimulando ataque: Mallory tenta decifrar a mensagem de Bob...")
    headers_mallory = {'Authorization': f'Bearer {mallory["key"]}'}
    payload_ataque = {'pacote_seguro_hibrido': pacote_para_bob}
    
    ataque_resp = requests.post(f"{api_server}/api/decrypt", headers=headers_mallory, json=payload_ataque)

    # A API DEVE bloquear Mallory com um erro 403 Forbidden
    assert ataque_resp.status_code == 403
    assert "Acesso negado" in ataque_resp.json()['erro']
    print("✅ Defesa bem-sucedida! O servidor negou o acesso como esperado.")