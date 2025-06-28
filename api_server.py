# api_server.py (Versão Corrigida para Passar em Todos os Testes)
import secrets
import json
import os
import base64
import sqlite3
import redis
import bcrypt
import logging
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from datetime import datetime, timedelta

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import config
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(16))

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

class PrimeGuardServer:
    def __init__(self, bits=config.PRIMEGUARD_BITS):
        self.bits = bits
        self.tamanho_indice = 257 * 257
        self.db_file = config.DB_FILE
        try:
            self.redis_client = redis.Redis(host=config.REDIS_HOST, port=config.REDIS_PORT, decode_responses=True)
            self.redis_client.ping()
            logging.info("Conectado ao servidor Redis com sucesso.")
        except redis.exceptions.ConnectionError as e:
            logging.critical(f"NÃO FOI POSSÍVEL CONECTAR AO REDIS. Detalhe: {e}")
            self.redis_client = None
        if not os.path.exists(self.db_file):
            logging.warning(f"Banco de dados '{self.db_file}' não encontrado.")

    def _is_prime(self, n, k=10):
        if n < 2: return False
        if n in (2, 3): return True
        if n % 2 == 0: return False
        r, d = 0, n - 1
        while d % 2 == 0: r += 1; d //= 2
        for _ in range(k):
            a = secrets.randbelow(n - 3) + 2
            x = pow(a, d, n)
            if x in (1, n - 1): continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1: break
            else: return False
        return True

    def _generate_large_prime(self):
        while True:
            p = secrets.randbits(self.bits)
            p |= (1 << self.bits - 1) | 1
            if self._is_prime(p): return p

    def _criar_indice_com_k1(self, k1):
        dicionario, indice, candidato = {}, 1, k1
        while indice <= self.tamanho_indice:
            if self._is_prime(candidato):
                dicionario[indice] = candidato
                indice += 1
            candidato += 1
        return dicionario

    def _encrypt_primal(self, k1, dados_chave_bytes):
        dicionario = self._criar_indice_com_k1(k1)
        posicoes = {p: i for i, p in dicionario.items()}
        if len(dados_chave_bytes) % 2 != 0: dados_chave_bytes += b'\x00'
        indices_msg = [byte + 1 for byte in dados_chave_bytes]
        pacotes_cifrados = []
        for i in range(0, len(indices_msg), 2):
            primo_a, primo_b = dicionario[indices_msg[i]], dicionario[indices_msg[i+1]]
            novo_indice = posicoes[primo_a] * posicoes[primo_b]
            cifra = dicionario.get(novo_indice)
            if not cifra: raise ValueError(f"Índice resultante ({novo_indice}) fora dos limites!")
            pacotes_cifrados.append((cifra, primo_a))
        return pacotes_cifrados

    def _decrypt_primal(self, k1, pacotes_cifrados):
        dicionario = self._criar_indice_com_k1(k1)
        posicoes = {p: i for i, p in dicionario.items()}
        bytes_recuperados = bytearray()
        for c, a in pacotes_cifrados:
            indice_b = posicoes[c] // posicoes[a]
            byte_a, byte_b = posicoes[a] - 1, indice_b - 1
            bytes_recuperados.extend([byte_a, byte_b])
        if bytes_recuperados.endswith(b'\x00'): bytes_recuperados.pop()
        return bytes(bytes_recuperados)
    
    def _autenticar_usuario(self, api_key_texto_puro: str):
        if not api_key_texto_puro: return None
        user = db_query('SELECT nome_cliente FROM clientes WHERE chave_api = ?', [api_key_texto_puro], one=True)
        return user['nome_cliente'] if user else None

    def _verificar_existencia_usuario(self, nome_cliente):
        return db_query('SELECT id FROM clientes WHERE nome_cliente = ?', [nome_cliente], one=True) is not None

    def _salvar_sessao(self, message_id, k1, dono, ttl_segundos=300):
        if not self.redis_client: return
        self.redis_client.set(message_id, json.dumps({"k1": k1, "dono": dono}), ex=ttl_segundos)

    def _recuperar_sessao(self, message_id):
        if not self.redis_client: return None
        sessao_data = self.redis_client.get(message_id)
        return json.loads(sessao_data) if sessao_data else None

    def _deletar_sessao(self, message_id):
        if not self.redis_client: return
        self.redis_client.delete(message_id)

    def encrypt_hybrid(self, api_key, destinatario_id, dados_em_bytes):
        remetente_id = self._autenticar_usuario(api_key)
        if not remetente_id: raise PermissionError("Chave de API inválida ou inexistente.")
        if not self._verificar_existencia_usuario(destinatario_id): raise ValueError(f"Destinatário '{destinatario_id}' não existe.")
        logging.info(f"Iniciando criptografia do remetente '{remetente_id}' para '{destinatario_id}'.")
        chave_sessao_aes = get_random_bytes(32)
        k1_primal = self._generate_large_prime()
        pacotes_chave_cifrada = self._encrypt_primal(k1_primal, chave_sessao_aes)
        message_id = "msg_" + secrets.token_hex(16)
        self._salvar_sessao(message_id, k1_primal, destinatario_id)
        cipher_aes = AES.new(chave_sessao_aes, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(dados_em_bytes)
        pacote_hibrido = {"message_id": message_id, "pacote_chave_primal": pacotes_chave_cifrada, "nonce_aes_b64": base64.b64encode(cipher_aes.nonce).decode('utf-8'), "tag_aes_b64": base64.b64encode(tag).decode('utf-8'), "ciphertext_b64": base64.b64encode(ciphertext).decode('utf-8')}
        logging.info(f"Criptografia para '{destinatario_id}' concluída. ID: {message_id}")
        return json.dumps(pacote_hibrido)

    def decrypt_hybrid(self, api_key, pacote_hibrido_json):
        requisitante_id = self._autenticar_usuario(api_key)
        if not requisitante_id: raise PermissionError("Chave de API inválida ou inexistente.")
        pacote = json.loads(pacote_hibrido_json)
        message_id = pacote["message_id"]
        logging.info(f"Tentativa de decifragem da mensagem '{message_id}' pelo requisitante '{requisitante_id}'.")
        sessao = self._recuperar_sessao(message_id)
        if not sessao:
            logging.warning(f"Falha na decifragem: ID da mensagem '{message_id}' inválido ou expirado.")
            raise ValueError("ID da mensagem inválido ou sessão expirada.")
        if sessao["dono"] != requisitante_id:
            logging.error(f"ACESSO NEGADO: Requisitante '{requisitante_id}' tentou decifrar a mensagem '{message_id}' que pertence a '{sessao['dono']}'.")
            raise PermissionError("Acesso negado. Você não é o destinatário autorizado desta mensagem.")
        k1_primal = sessao["k1"]
        chave_sessao_aes_recuperada = self._decrypt_primal(k1_primal, pacote["pacote_chave_primal"])
        nonce, tag, ciphertext = (base64.b64decode(pacote[k]) for k in ['nonce_aes_b64', 'tag_aes_b64', 'ciphertext_b64'])
        cipher_aes = AES.new(chave_sessao_aes_recuperada, AES.MODE_GCM, nonce=nonce)
        dados_decifrados = cipher_aes.decrypt_and_verify(ciphertext, tag)
        self._deletar_sessao(message_id)
        logging.info(f"Mensagem '{message_id}' decifrada com sucesso por '{requisitante_id}'.")
        return dados_decifrados


def db_query(query, args=(), one=False):
    conn = sqlite3.connect(config.DB_FILE)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(query, args)
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv

servidor_primeguard = PrimeGuardServer()

# --- Rotas da Interface Web ---
@app.route('/')
def index():
    return redirect(url_for('dashboard')) if 'user_id' in session else render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if request.method == 'POST':
        nome_cliente, email, senha = request.form['nome_cliente'], request.form['email'], request.form['senha']
        if db_query('SELECT * FROM clientes WHERE nome_cliente = ? OR email = ?', [nome_cliente, email], one=True):
            flash('Nome de cliente ou email já existe!', 'danger')
            return redirect(url_for('register'))
        senha_hash = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt())
        chave_api = "pg_live_" + secrets.token_hex(24)
        conn = sqlite3.connect(config.DB_FILE)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO clientes (nome_cliente, email, senha_hash, chave_api) VALUES (?, ?, ?, ?)', (nome_cliente, email, senha_hash, chave_api))
        conn.commit()
        conn.close()
        flash('Conta criada com sucesso! Por favor, faça o login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email, senha = request.form['email'], request.form['senha']
        user = db_query('SELECT * FROM clientes WHERE email = ?', [email], one=True)
        if user and bcrypt.checkpw(senha.encode('utf-8'), user['senha_hash']):
            session['user_id'], session['user_name'] = user['id'], user['nome_cliente']
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login inválido. Verifique o seu email e senha.', 'danger')
    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = db_query('SELECT * FROM clientes WHERE email = ?', [email], one=True)
        if user:
            token = secrets.token_urlsafe(32)
            expiration = datetime.utcnow() + timedelta(hours=1)
            conn = sqlite3.connect(config.DB_FILE)
            cursor = conn.cursor()
            cursor.execute('UPDATE clientes SET reset_token = ?, reset_token_expiration = ? WHERE id = ?', (token, expiration, user['id']))
            conn.commit()
            conn.close()
            reset_link = url_for('reset_password', token=token, _external=True)
            logging.info(f"RESET DE SENHA SOLICITADO PARA: {email}")
            logging.info(f"Link de Reset (copie e cole no navegador): {reset_link}")
        flash('Se o seu email estiver no nosso sistema, um link para resetar a senha foi gerado (verifique o log do servidor).', 'info')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = db_query('SELECT * FROM clientes WHERE reset_token = ?', [token], one=True)
    if not user or datetime.utcnow() > datetime.fromisoformat(user['reset_token_expiration']):
        flash('O link para resetar a senha é inválido ou expirou.', 'danger')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        nova_senha = request.form.get('nova_senha')
        if bcrypt.checkpw(nova_senha.encode('utf-8'), user['senha_hash']):
            flash('A nova senha não pode ser igual à senha antiga.', 'danger')
            return render_template('reset_password.html', token=token)
        nova_senha_hash = bcrypt.hashpw(nova_senha.encode('utf-8'), bcrypt.gensalt())
        conn = sqlite3.connect(config.DB_FILE)
        cursor = conn.cursor()
        cursor.execute('UPDATE clientes SET senha_hash = ?, reset_token = NULL, reset_token_expiration = NULL WHERE id = ?', (nova_senha_hash, user['id']))
        conn.commit()
        conn.close()
        logging.info(f"Senha resetada com sucesso para o utilizador: {user['email']}")
        flash('A sua senha foi atualizada com sucesso!', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
    user = db_query('SELECT * FROM clientes WHERE id = ?', [session['user_id']], one=True)
    return render_template('dashboard.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu da sua conta.', 'info')
    return redirect(url_for('index'))

@app.route('/regenerate_key', methods=['POST'])
def regenerate_key():
    if 'user_id' not in session: return redirect(url_for('login'))
    nova_chave_api = "pg_live_" + secrets.token_hex(24)
    user_id = session['user_id']
    conn = sqlite3.connect(config.DB_FILE)
    cursor = conn.cursor()
    cursor.execute('UPDATE clientes SET chave_api = ? WHERE id = ?', (nova_chave_api, user_id))
    conn.commit()
    conn.close()
    logging.info(f"Chave de API regenerada para o utilizador ID: {user_id}")
    flash('A sua chave de API foi regenerada com sucesso!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/delete_account', methods=['POST'])
def delete_account():
    if 'user_id' not in session: return redirect(url_for('login'))
    senha_confirm, user_id = request.form.get('senha_confirm'), session['user_id']
    user = db_query('SELECT * FROM clientes WHERE id = ?', [user_id], one=True)
    if not user:
        flash('Utilizador não encontrado.', 'danger')
        return redirect(url_for('logout'))
    if user and bcrypt.checkpw(senha_confirm.encode('utf-8'), user['senha_hash']):
        conn = sqlite3.connect(config.DB_FILE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM clientes WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        logging.info(f"Conta apagada para o utilizador ID: {user_id} ({user['nome_cliente']})")
        session.clear()
        flash('A sua conta foi permanentemente apagada.', 'success')
        return redirect(url_for('index'))
    else:
        flash('Senha incorreta. A sua conta não foi apagada.', 'danger')
        return redirect(url_for('dashboard'))

# --- Rotas da API Programática ---
def get_api_key_from_request():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None, jsonify({"erro": "Cabeçalho de autorização 'Bearer' ausente ou mal formatado"}), 401
    return auth_header.split(' ')[1], None, None

@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
def handle_api_register():
    data = request.get_json()
    if not data or not all(k in data for k in ('nome_cliente', 'email', 'senha')):
        return jsonify({"erro": "Corpo da requisição deve conter 'nome_cliente', 'email', e 'senha'."}), 400
    if db_query('SELECT * FROM clientes WHERE nome_cliente = ? OR email = ?', [data['nome_cliente'], data['email']], one=True):
        return jsonify({"erro": "Nome de cliente ou email já existe!"}), 409
    senha_hash = bcrypt.hashpw(data['senha'].encode('utf-8'), bcrypt.gensalt())
    chave_api = "pg_live_" + secrets.token_hex(24)
    conn = sqlite3.connect(config.DB_FILE)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO clientes (nome_cliente, email, senha_hash, chave_api) VALUES (?, ?, ?, ?)', (data['nome_cliente'], data['email'], senha_hash, chave_api))
    conn.commit()
    conn.close()
    logging.info(f"Novo cliente '{data['nome_cliente']}' registado via API.")
    return jsonify({"mensagem": "Conta criada com sucesso.", "api_key": chave_api}), 201

@app.route('/api/encrypt', methods=['POST'])
def handle_encrypt():
    api_key, error_json, status_code = get_api_key_from_request()
    if error_json: return error_json, status_code
    data = request.get_json()
    if not data or not all(k in data for k in ('destinatario_id', 'dados_base64')):
        return jsonify({"erro": "Faltando 'destinatario_id' ou 'dados_base64'"}), 400
    try:
        dados_em_bytes = base64.b64decode(data['dados_base64'])
        pacote_seguro_hibrido = servidor_primeguard.encrypt_hybrid(api_key, data['destinatario_id'], dados_em_bytes)
        return jsonify({"pacote_seguro_hibrido": pacote_seguro_hibrido})
    except (PermissionError, ValueError) as e:
        return jsonify({"erro": str(e)}), 403
    except Exception as e:
        logging.critical(f"Erro interno em /api/encrypt: {e}", exc_info=True)
        return jsonify({"erro": "Erro interno no servidor"}), 500

@app.route('/api/decrypt', methods=['POST'])
def handle_decrypt():
    api_key, error_json, status_code = get_api_key_from_request()
    if error_json: return error_json, status_code
    data = request.get_json()
    if not data or 'pacote_seguro_hibrido' not in data:
        return jsonify({"erro": "Faltando 'pacote_seguro_hibrido'"}), 400
    try:
        # AQUI ESTÁ A CORREÇÃO: Passamos o pacote JSON como string.
        pacote_json_str = data['pacote_seguro_hibrido']
        dados_decifrados_bytes = servidor_primeguard.decrypt_hybrid(api_key, pacote_json_str)
        dados_decifrados_base64 = base64.b64encode(dados_decifrados_bytes).decode('utf-8')
        return jsonify({"dados_recuperados_base64": dados_decifrados_base64})
    except (PermissionError, ValueError) as e:
        return jsonify({"erro": str(e)}), 403
    except Exception as e:
        logging.critical(f"Erro interno em /api/decrypt: {e}", exc_info=True)
        return jsonify({"erro": "Erro interno no servidor"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)), debug=config.DEBUG)