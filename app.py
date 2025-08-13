from flask import Flask, jsonify, request, abort
from pymongo import MongoClient
import os
from flask_cors import CORS 
from dotenv import load_dotenv
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import redis
import json
import re


load_dotenv()
# URI de MongoDB (la tomarás de variable de entorno en Render)
MONGO_URI = os.environ.get("MONGO_URI")

app = Flask(__name__)
limiter = Limiter(get_remote_address,
                  app=app,
                  default_limits=["60 per minute", "5 per second"],
                  storage_uri= MONGO_URI
                  )
CORS(app)

redis_client = redis.Redis.from_url(os.environ.get("REDIS_URL"))

# Conexión a MongoDB
client = MongoClient(MONGO_URI)
db = client["reddit_logs"]
collection = db["mod_actions"]

@app.route("/redis-test")
def redis_test():
    try:
        cache_key = "test:timestamp"

        # Intentar obtener el valor cacheado
        cached = redis_client.get(cache_key)
        if cached:
            return jsonify({
                "cached": True,
                "timestamp": cached.decode("utf-8")
            })

        # Si no existe, lo crea y cachea por 300 segundos
        timestamp = datetime.utcnow().isoformat()
        redis_client.set(cache_key, timestamp, ex=300)

        return jsonify({
            "cached": False,
            "timestamp": timestamp
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

#@cache.cached(timeout=30)
@app.route("/test-cache")
def test_cache():
    print("⚡ NO HAY CACHÉ, ejecutando lógica...")
    return jsonify({"timestamp": datetime.utcnow().isoformat()})


@app.route('/api/tarea-secreta')
def tarea_secreta():
    token = request.args.get('token')
    secret_token = os.getenv('CRON_TOKEN')  # Lee la variable de entorno

    if token != secret_token:
        abort(403)

    # Aquí tu lógica para la tarea cron
    return 'Tarea ejecutada con éxito'


@app.route("/api/actions")
def obtener_acciones():
    try:
        acciones = collection.distinct("action")
        acciones = sorted([a for a in acciones if a])  # Ordena y elimina vacíos
        return jsonify({"actions": acciones})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

#@cache.cached(timeout=30, query_string=True)
@app.route("/api/logs")
def obtener_logs():
    try:
        # Parámetros GET de paginación
        pagina = int(request.args.get("page", 1))
        por_pagina = 25

        # Filtros opcionales
        autor = request.args.get("author","").strip()
        accion = request.args.get("action","").strip()
        moderador = request.args.get("mod","").strip()

        # Validación básica: solo letras, números, guion bajo y medio, máximo 32 caracteres
        def es_texto_simple(valor):
            return bool(re.match(r'^[\w\-]{1,32}$', valor))

        if autor and not es_texto_simple(autor):
            return jsonify({"error": "Formato de usuario inválido"}), 400
        if moderador and not es_texto_simple(moderador):
            return jsonify({"error": "Formato de moderador inválido"}), 400

        # Clave de caché única por combinación de filtros
        cache_key = f"logs:page={pagina}&limit={por_pagina}&mod={moderador or 'all'}&author={autor or 'all'}&action={accion or 'all'}"

        # Intentar leer desde Redis
        cached = redis_client.get(cache_key)
        if cached:
            data= json.loads(cached)
            data["cached"]= True
            return jsonify(data)
        

        filtro = {}
        if autor:
            filtro["target_author"] = {"$regex": re.escape(autor), "$options": "i"}
        if moderador:
            filtro["mod"] = {"$regex": re.escape(moderador), "$options": "i"}
        if accion:
            filtro["action"] = accion

        # Conteo total (para frontend si quieres mostrar total de páginas)
        total = collection.count_documents(filtro)


        campos = {
            "_id": 0,
            "id": 1,
            "action": 1,
            "target_author": 1,
            "mod": 1,
            "created_utc": 1,
            "target_permalink": 1,
            "details":1,
            "description":1,
            "target_body":1,
            "target_title":1
        }

        # Datos paginados
        resultados = (
            collection
            .find(filtro,campos)
            .sort("created_utc", -1)
            .skip((pagina - 1) * por_pagina)
            .limit(por_pagina)
        )

        datos = list(resultados)

        # Eliminar _id para evitar problemas con JSON
        for doc in datos:
            doc["_id"] = "0"


        response = {
            "total": total,
            "page": pagina,
            "limit": por_pagina,
            "results": datos,
            "timestamp": datetime.now().isoformat(),
            "cached": False
        }

        redis_client.set(cache_key, json.dumps(response), ex=300)

        return jsonify(response)
    

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/checking")
@limiter.limit("300 per day")
def home():
    return "API activa"

@app.route("/")
def home():
    return "API activa"

@app.route("/api/clear-cache", methods=["POST"])
def clear_cache():
    token = request.args.get("token")
    secret_token = os.getenv('CRON_RESET_CACHE')
    if token != secret_token:
        abort(403)
    # Borra todas las claves de logs en Redis
    for key in redis_client.scan_iter("logs:*"):
        redis_client.delete(key)
    return jsonify({"ok": True, "msg": "Caché limpiada"})


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(error="Demasiadas peticiones, espera unos segundos."), 429



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)