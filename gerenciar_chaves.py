# gerenciar_chaves.py (Versão com Suporte a Password Reset)
"""
Ferramenta de linha de comando para administração do banco de dados da PrimeGuard.
"""
import sqlite3
import sys
import config

def inicializar_db():
    """
    Cria ou recria o banco de dados com a estrutura completa,
    incluindo campos para o fluxo de "Esqueci a Minha Senha".
    """
    conn = sqlite3.connect(config.DB_FILE)
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS clientes")
    
    cursor.execute('''
        CREATE TABLE clientes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome_cliente TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            senha_hash TEXT NOT NULL,
            chave_api TEXT NOT NULL UNIQUE,
            data_registo TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reset_token TEXT,
            reset_token_expiration TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print(f"✅ Banco de dados '{config.DB_FILE}' inicializado com a nova estrutura de contas.")

def listar_clientes():
    """Lista todos os clientes registados na base de dados."""
    conn = sqlite3.connect(config.DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT id, nome_cliente, email, data_registo FROM clientes")
    clientes = cursor.fetchall()
    conn.close()
    if not clientes:
        print("Nenhum cliente encontrado.")
        return
    
    print("--- LISTA DE CLIENTES REGISTRADOS ---")
    for id, nome, email, data in clientes:
        print(f"- ID: {id}, Nome: {nome}, Email: {email}, Registado em: {data}")
    print("-------------------------------------")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: python gerenciar_chaves.py <comando>")
        print("Comandos disponíveis: init, list")
        sys.exit(1)

    comando = sys.argv[1]

    if comando == "init":
        print("AVISO: Este comando irá apagar e recriar o seu banco de dados.")
        resposta = input("Tem a certeza que quer continuar? (s/n): ")
        if resposta.lower() == 's':
            inicializar_db()
        else:
            print("Operação cancelada.")
    elif comando == "list":
        listar_clientes()
    else:
        print(f"Comando '{comando}' desconhecido.")