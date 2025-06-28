# config.py
# Ficheiro central para todas as configurações da aplicação.

import os

# Configuração do Banco de Dados
# Procura por uma variável de ambiente primeiro, senão, usa o valor padrão.
DB_FILE = os.environ.get('DATABASE_FILE', 'clientes.db')

# Configuração do Redis
REDIS_HOST = os.environ.get('REDIS_HOST', 'localhost')
REDIS_PORT = int(os.environ.get('REDIS_PORT', 6379))

# Configuração do PrimeGuard
# Nível de segurança para a geração de primos (K1)
PRIMEGUARD_BITS = int(os.environ.get('PRIMEGUARD_BITS', 32))

# Configuração da Aplicação
# Define se a aplicação está em modo de depuração.
# NUNCA use DEBUG = True em produção.
DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 't')