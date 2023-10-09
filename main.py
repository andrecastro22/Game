from flask import Flask, jsonify, request
import psycopg2, jwt
from datetime import datetime, timedelta
from functools import wraps
import os
  
app = Flask(__name__)   

#! Alterar a chavSuperSecreta para algo mais secreto
app.config['SECRET_KEY'] = 'chaveSuperSecreta'

def db_connection():
    DATABASE_URL = os.environ.get('DATABASE_URL')
    db = psycopg2.connect(DATABASE_URL)
    return db

@app.route('/', methods = ["GET"])
def home():
    return "Hello World!"

#* Token interceptor
def auth_user(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'Error': 'Missing token!'}), 401

        try:
            token = token.split(' ')[1]
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'])    
            
            if decoded_token["t_expiration"] < str(datetime.utcnow()):
                return jsonify({"Error": "Token has expired!"}), 404

        except Exception as e:
            return jsonify({'Error': e}), 400
        return func(*args, **kwargs)
    return decorated

#* Login user
#* Generate token
@app.route("/login", methods=['PATCH'])
def login():
    content = request.get_json()

    if "u_username" not in content or "u_password" not in content:
        return jsonify({"Erro": "Missing parameters"}), 400

    query = """
                SELECT *
                FROM users
                WHERE u_username = %s AND u_password = crypt(%s, senha);
                """
    values = [content["u_username"], content["u_password"]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, values)
                rows = cursor.fetchall()
                token = jwt.encode({
                    'id': rows[0][0],
                    'expiration': str(datetime.utcnow() + timedelta(hours=1))
                }, app.config['SECRET_KEY'])
        conn.close()
    except (psycopg2.DatabaseError):
        return jsonify({"Error": "Wrong login credencials!"}), 404
    return {'Message': 'OK', 'Token': token.decode('utf-8')}, 200
  
#* Register new user
@app.route("/resgister", methods=['POST'])
def registar_utilizador():
    content = request.get_json()

    #TODO: Verificar os campos de "user" obrigatorios
    if "u_username" not in content or "u_password" or "u_email" not in content: 
            return jsonify({"Erro": "Missing parameters"}), 400
    
    #TODO: Alterar query e values com os campos de "user"
    query = """
                INSERT INTO utilizadores(u_username, u_password, u_email) 
                VALUES(%s, crypt(%s, gen_salt('bf')), %s);
                """

    values = [content["u_username"], content["u_password"], content["u_email"]]

    try:
        with db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(query, values)
        conn.close()
    except (Exception, psycopg2.DatabaseError) as error:
        return jsonify({"Error": str(error)}), 404
    return jsonify({"Message": 'OK'}),200

#* Regenerate token
@app.route('/renew_token', methods=['PATCH'])
@auth_user
def renew_token():
    user_id = request.decoded_token['id']

    new_token = jwt.encode({
        'id': user_id,
        't_expiration': str(datetime.utcnow() + timedelta(hours=1))
    }, app.config['SECRET_KEY'])

    return jsonify({"Message": 'Token renewed', 'Token': new_token.decode('utf-8')}), 200

if __name__ == "__main__":
    app.run(port=8080, debug=True)