from flask import Flask, jsonify, request
from pymongo import MongoClient
import os
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Permitir peticiones desde el frontend (GitHub Pages, etc.)

# URI de MongoDB (la tomarás de variable de entorno en Render)
MONGO_URI = os.environ.get("MONGO_URI")

# Conexión a MongoDB
client = MongoClient(MONGO_URI)
db = client["reddit_logs"]
collection = db["mod_actions"]

@app.route("/api/logs")
def obtener_logs():
    try:
        # Parámetros GET de paginación
        pagina = int(request.args.get("page", 1))
        por_pagina = int(request.args.get("limit", 25))

        # Filtros opcionales
        autor = request.args.get("author")
        accion = request.args.get("action")

        filtro = {}
        if autor:
            filtro["target_author"] = {"$regex": autor, "$options": "i"}
        if accion:
            filtro["action"] = accion

        # Conteo total (para frontend si quieres mostrar total de páginas)
        total = collection.count_documents(filtro)

        # Datos paginados
        resultados = (
            collection
            .find(filtro)
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
            "results": datos
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/")
def home():
    return "API activa"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)