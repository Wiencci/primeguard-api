# Dockerfile para a Aplicação PrimeGuard API

# --- ESTÁGIO 1: A Base ---
# Começamos com uma imagem oficial e otimizada do Python.
# Usar a versão "slim" economiza muito espaço em disco.
FROM python:3.11-slim

# --- ESTÁGIO 2: Preparar o Ambiente ---
# Definimos o diretório de trabalho dentro do contentor.
# Todos os comandos a seguir serão executados a partir desta pasta.
WORKDIR /app

# --- ESTÁGIO 3: Instalar as Dependências ---
# Copiamos primeiro apenas o ficheiro de requisitos para dentro do contentor.
COPY requirements.txt .

# Instalamos as dependências. Ao copiar o requirements.txt separadamente,
# o Docker pode usar o cache de forma inteligente. Se não mudarmos os requisitos,
# ele não precisa de reinstalar tudo sempre que alterarmos o nosso código.
RUN pip install --no-cache-dir -r requirements.txt

# --- ESTÁGIO 4: Copiar o Código da Aplicação ---
# Agora, copiamos todo o resto do nosso código para o diretório de trabalho /app.
COPY . .

# --- ESTÁGIO 5: Definir o Comando de Execução ---
# Dizemos ao Docker qual comando executar quando o contentor iniciar.
# Usamos o Waitress para servir a nossa aplicação, exatamente como fizemos localmente.
CMD ["waitress-serve", "--host=0.0.0.0", "--port=5000", "api_server:app"]