# tests/test_app.py (Versão com Encoding Corrigido)

import pytest
from api_server import app as flask_app

@pytest.fixture
def client():
    """Cria um cliente de teste para a nossa aplicação."""
    flask_app.config['TESTING'] = True
    with flask_app.test_client() as client:
        yield client

def test_pagina_inicial_carrega(client):
    """
    TESTE 1: Garante que a página inicial ('/') carrega com sucesso.
    """
    resposta = client.get('/')
    assert resposta.status_code == 200
    
    # --- CORREÇÃO AQUI ---
    # Criamos o texto como uma string normal e depois codificamo-lo para bytes
    texto_esperado = "Bem-vindo à PrimeGuard API".encode('utf-8')
    assert texto_esperado in resposta.data

def test_pagina_de_registo_carrega(client):
    """
    TESTE 2: Garante que a página de registo ('/register') carrega.
    """
    resposta = client.get('/register')
    assert resposta.status_code == 200
    
    # --- E CORREÇÃO AQUI ---
    texto_esperado = "Criar uma Nova Conta".encode('utf-8')
    assert texto_esperado in resposta.data