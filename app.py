from flask import Flask, jsonify, request
from pymongo import MongoClient
import os
from flask_cors import CORS 
from dotenv import load_dotenv
from flask_caching import Cache
from datetime import datetime
from flask_caching.backends.redis import RedisCache # type: ignore

load_dotenv()

app = Flask(__name__)
CORS(app)  # Permitir peticiones desde el frontend (GitHub Pages, etc.)

cache = Cache(config={
    'CACHE_TYPE': RedisCache,
    'CACHE_REDIS_URL': os.environ.get("REDIS_URL"),
    'CACHE_DEFAULT_TIMEOUT': 30
})
cache.init_app(app)

print("Caché tipo:", app.config["CACHE_TYPE"])
print("Redis URL:", app.config["CACHE_REDIS_URL"])


# URI de MongoDB (la tomarás de variable de entorno en Render)
MONGO_URI = os.environ.get("MONGO_URI")
# Conexión a MongoDB
client = MongoClient(MONGO_URI)
db = client["reddit_logs"]
collection = db["mod_actions"]



@cache.cached(timeout=30)
@app.route("/test-cache")
def test_cache():
    print("⚡ NO HAY CACHÉ, ejecutando lógica...")
    return jsonify({"timestamp": datetime.utcnow().isoformat()})

@cache.cached(timeout=30, query_string=True)
@app.route("/api/logs")
def obtener_logs():
    try:
        # Parámetros GET de paginación
        pagina = int(request.args.get("page", 1))
        por_pagina = int(request.args.get("limit", 25))

        # Filtros opcionales
        autor = request.args.get("author")
        accion = request.args.get("action")
        moderador = request.args.get("mod")

        filtro = {}
        if autor:
            filtro["target_author"] = {"$regex": autor, "$options": "i"}
        if moderador:
            filtro["mod"] = {"$regex": moderador, "$options": "i"}
        if accion:
            filtro["action"] = accion

        # Conteo total (para frontend si quieres mostrar total de páginas)
        total = collection.count_documents(filtro)


        campos = {
            "_id": 1,
            "action": 1,
            "target_author": 1,
            "mod": 1,
            "created_utc": 1,
            "target_permalink": 1
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
            doc["_id"] = str(doc["_id"])

        return jsonify({
            "total": total,
            "page": pagina,
            "limit": por_pagina,
            "results": datos,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/")
def home():
    return "API activa"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)