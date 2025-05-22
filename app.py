from flask import Flask, jsonify
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

@app.route("/api/logs", methods=["GET"])
def get_logs():
    # Puedes agregar filtros si quieres más adelante
    results = list(collection.find({}, {"_id": 0}))  # No incluir _id
    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)