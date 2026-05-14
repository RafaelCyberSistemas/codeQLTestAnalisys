"""
API Vulnerável para Análise CodeQL
Este código contém várias vulnerabilidades intencionais para estudo:
- SQL Injection
- Command Injection
- Path Traversal
- Weak Cryptography
- Sensitive Data Exposure
"""

from flask import Flask, request, jsonify
import sqlite3
import subprocess
import os
from hashlib import md5
import pickle

app = Flask(__name__)

# Configuração de banco de dados vulnerável
DB_PATH = "users.db"

def init_db():
    """Inicializa o banco de dados"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            api_key TEXT
        )
    ''')
    conn.commit()
    conn.close()

# ========== VULNERABILIDADE 1: SQL INJECTION ==========
@app.route('/api/user/<username>', methods=['GET'])
def get_user_sql_injection(username):
    """
    VULNERABILIDADE: SQL Injection
    O parâmetro 'username' é concatenado diretamente na query SQL
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # ❌ INSEGURO: Concatenação direta
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    print(f"Query executada: {query}")
    
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({"id": user[0], "username": user[1], "email": user[3]})
    return jsonify({"error": "User not found"}), 404


# ========== VULNERABILIDADE 2: SQL INJECTION COM LOGIN ==========
@app.route('/api/login', methods=['POST'])
def login_sql_injection():
    """
    VULNERABILIDADE: SQL Injection no login
    Permite bypass de autenticação com: admin' OR '1'='1
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # ❌ INSEGURO: SQL Injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    print(f"Query executada: {query}")
    
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({"success": True, "api_key": user[4], "username": user[1]})
    
    return jsonify({"success": False, "error": "Invalid credentials"}), 401


# ========== VULNERABILIDADE 3: COMMAND INJECTION ==========
@app.route('/api/ping/<host>', methods=['GET'])
def ping_command_injection(host):
    """
    VULNERABILIDADE: Command Injection
    O parâmetro 'host' é passado diretamente para subprocess
    Possível exploração: 127.0.0.1; rm -rf /
    """
    # ❌ INSEGURO: Sem validação
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    
    return jsonify({
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode
    })


# ========== VULNERABILIDADE 4: PATH TRAVERSAL ==========
@app.route('/api/files/<filename>', methods=['GET'])
def get_file_path_traversal(filename):
    """
    VULNERABILIDADE: Path Traversal
    Permite acessar arquivos fora do diretório permitido
    Possível exploração: ../../etc/passwd
    """
    uploads_dir = "/uploads"
    
    # ❌ INSEGURO: Sem validação de path
    file_path = os.path.join(uploads_dir, filename)
    
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return jsonify({"content": content})
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404


# ========== VULNERABILIDADE 5: WEAK HASHING ==========
@app.route('/api/register', methods=['POST'])
def register_weak_hash():
    """
    VULNERABILIDADE: Weak Hashing (MD5)
    MD5 é quebrado e não deve ser usado para passwords
    """
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    email = data.get('email', '')
    
    # ❌ INSEGURO: MD5 para hash de senha
    password_hash = md5(password.encode()).hexdigest()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                      (username, password_hash, email))
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "User already exists"}), 400
    finally:
        conn.close()
    
    return jsonify({"success": True, "username": username}), 201


# ========== VULNERABILIDADE 6: SENSITIVE DATA EXPOSURE ==========
@app.route('/api/admin/users', methods=['GET'])
def get_all_users_no_auth():
    """
    VULNERABILIDADE: Sensitive Data Exposure
    Sem autenticação ou autorização, expõe todos os usuários e hashes
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # ❌ INSEGURO: Sem verificação de autenticação
    cursor.execute("SELECT id, username, password, email FROM users")
    users = cursor.fetchall()
    conn.close()
    
    return jsonify({
        "users": [
            {"id": u[0], "username": u[1], "password": u[2], "email": u[3]}
            for u in users
        ]
    })


# ========== VULNERABILIDADE 7: INSECURE DESERIALIZATION ==========
@app.route('/api/cache/<data>', methods=['GET'])
def unsafe_pickle(data):
    """
    VULNERABILIDADE: Insecure Deserialization
    Pickle é inseguro para dados não confiáveis
    """
    try:
        # ❌ INSEGURO: Deserialization de dados não confiáveis
        obj = pickle.loads(bytes.fromhex(data))
        return jsonify({"cached_data": str(obj)})
    except Exception as e:
        app.logger.exception("Failed to deserialize cache data")
        return jsonify({"error": "Invalid cache data"}), 400


# ========== VULNERABILIDADE 8: HARDCODED SECRETS ==========
API_KEY = "sk-1234567890abcdef"  # ❌ Chave hardcoded!
DATABASE_PASSWORD = "admin123"     # ❌ Senha hardcoded!

@app.route('/api/config', methods=['GET'])
def get_config():
    """
    VULNERABILIDADE: Hardcoded Secrets
    As chaves estão expostas no código fonte
    """
    return jsonify({
        "api_key": API_KEY,
        "db_password": DATABASE_PASSWORD
    })


# ========== VULNERABILIDADE 9: INSECURE RANDOM ==========
@app.route('/api/generate-token', methods=['GET'])
def generate_insecure_token():
    """
    VULNERABILIDADE: Weak Random Number Generation
    """
    import random
    
    # ❌ INSEGURO: random.choice não é criptograficamente seguro
    characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    token = ''.join(random.choice(characters) for _ in range(32))
    
    return jsonify({"token": token})


# ========== VULNERABILIDADE 10: SQL INJECTION EM DELETE ==========
@app.route('/api/user/<user_id>', methods=['DELETE'])
def delete_user_sql_injection(user_id):
    """
    VULNERABILIDADE: SQL Injection no DELETE
    O parâmetro 'user_id' é concatenado na query
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # ❌ INSEGURO: Concatenação direta
    query = f"DELETE FROM users WHERE id = {user_id}"
    print(f"Query executada: {query}")
    
    cursor.execute(query)
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "message": "User deleted"})


# ========== ROTAS SEGURAS (EXEMPLOS) ==========

@app.route('/api/user-safe/<username>', methods=['GET'])
def get_user_safe(username):
    """
    SEGURO: Usa parameterized queries
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # ✅ SEGURO: Parameterized query
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({"id": user[0], "username": user[1], "email": user[3]})
    return jsonify({"error": "User not found"}), 404


@app.route('/api/ping-safe/<host>', methods=['GET'])
def ping_safe(host):
    """
    SEGURO: Valida entrada antes de usar
    """
    import re
    
    # ✅ SEGURO: Validação de entrada
    if not re.match(r'^[a-zA-Z0-9\.\-]+$', host):
        return jsonify({"error": "Invalid host"}), 400
    
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    
    return jsonify({
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode
    })


if __name__ == '__main__':
    init_db()
    # ❌ debug=True em produção é uma vulnerabilidade!
    app.run(debug=True, host='0.0.0.0', port=5000)
