from flask import Flask, jsonify, request, abort
from pymongo import MongoClient, errors
import os
from flask_cors import CORS 
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timezone
import redis
import json
import re
import logging
from time import sleep
import threading
import requests
import traceback

load_dotenv()

# ================== CONFIGURACIÓN SCRAPER ==================
BACKEND_URL = "https://test-logs2.onrender.com"
SECRET_TOKEN = os.environ.get("CRON_RESET_CACHE")
INTERVALO_MINUTOS = int(os.environ.get("SCRAPER_INTERVAL", 10))  # por defecto cada 10 min

# ================== CONFIGURACIÓN FLASK ==================
# MONGO_URI = os.environ.get("MONGO_URI")
MONGO_URI = os.environ.get("MONGO_URI")
DB_NAME = "reddit_logs"
COLLECTION_NAME = "mod_actions"
REDDIT_URL = (
    "https://www.reddit.com/r/mod/about/log/.json?feed=38a1201d33c43f6b758c42b899a33bdd93f4836f&user=rchilemodlog&limit=100&raw_json=1"
)
HEADERS = {"User-Agent": "RedditModLogScraper/1.0 by u/sapomodlogbot"}

app = Flask(__name__)
limiter = Limiter(get_remote_address,
                  app=app,
                  default_limits=["60 per minute", "5 per second"],
                  storage_uri=MONGO_URI
                  )
CORS(app)
redis_client = redis.Redis.from_url(os.environ.get("REDIS_URL"))

# Conexión a MongoDB
client = MongoClient(MONGO_URI)
db = client["reddit_logs"]
collection = db["mod_actions"]


logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    level=logging.INFO
)

def limpiar_cache_backend():
    url = f"{BACKEND_URL}/api/clear-cache?token={SECRET_TOKEN}"
    logging.info("Iniciando limpieza de caché en backend...")

    try:
        resp = requests.post(url, timeout=10)
        if resp.ok:
            logging.info("✅ Caché del backend limpiada correctamente.")
        else:
            logging.error(f"❌ Error al limpiar caché: HTTP {resp.status_code} - {resp.text}")
    except requests.RequestException as e:
        logging.error(f"❌ Error de conexión al limpiar caché: {e}")



def wake_up_backend(max_retries=5, wait_seconds=5):
    url = f"{BACKEND_URL}/"
    logging.info(f"Despertando backend en {url}...")

    for intento in range(1, max_retries + 1):
        try:
            resp = requests.get(url, timeout=10)
            if resp.ok:
                logging.info(f"Backend activo (HTTP {resp.status_code}) en intento {intento}.")
                return True
            else:
                logging.warning(f"Intento {intento}: Respuesta no OK ({resp.status_code}).")
        except requests.RequestException as e:
            logging.warning(f"Intento {intento}: Error al contactar backend: {e}")
        logging.info(f"Esperando {wait_seconds} segundos antes de reintentar...")
        sleep(wait_seconds)

    logging.error("No se pudo activar el backend después de varios intentos.")
    return False

def ejecutar_scraper():
    logging.info(f"=== EJECUCIÓN PROGRAMADA | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} ===")
    run()
    if wake_up_backend():
        limpiar_cache_backend()
    logging.info("=== FIN DE EJECUCIÓN ===")

def scheduler():
    while True:
        ejecutar_scraper()
        sleep(INTERVALO_MINUTOS * 60)

# ================== ARRANQUE DEL SCHEDULER ==================
scheduler_started = False
def iniciar_scheduler():
    global scheduler_started
    if not scheduler_started:
        scheduler_started = True
        hilo = threading.Thread(target=scheduler, daemon=True)
        hilo.start()
iniciar_scheduler()


@app.route("/api/run-scraper", methods=["POST"])
@limiter.limit("3 per minute")  # evita spam incluso con token
def force_run_scraper():
    # Autenticación simple por token secreto
    token = request.args.get("token") or request.headers.get("X-Run-Token")
    secret = os.environ.get("RUN_SCRAPER_TOKEN")
    if not secret or token != secret:
        abort(403)

    # Ejecuta en un hilo para no bloquear el request
    threading.Thread(target=ejecutar_scraper, daemon=True).start()
    return jsonify({"ok": True, "msg": "Scraper encolado para ejecución inmediata"})

def save_to_mongodb(collection, items):
    insert_count = 0
    last_id = None

    for item in items:
        doc = item.get("data")
        if not doc or "id" not in doc:
            continue
        try:
            collection.insert_one(doc)
            insert_count += 1
            last_id = doc["id"]
        except errors.DuplicateKeyError:
            continue
        except Exception as e:
            print(f"Error insertando en MongoDB: {e}")
            continue

    return insert_count, last_id


def fetch_reddit_data(after=None):
    url = REDDIT_URL
    if after:
        url += f"&after={after}"
    print(f"Consultando: {url}")
    try:
        response = requests.get(url, headers=HEADERS, timeout=15)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error al obtener datos de Reddit: {e}")
        return None

def scraper():
    with MongoClient(MONGO_URI) as client:
        db = client[DB_NAME]
        collection = db[COLLECTION_NAME]

        # Asegurar índice único en el campo "id"
        try:
            collection.create_index("id", unique=True)
        except errors.OperationFailure:
            pass

        total_inserted = 0
        after = None

        while True:
            data = fetch_reddit_data(after)
            if not data:
                print("No se pudo obtener datos. Reintentando en 60 segundos...")
                sleep(60)
                continue

            children = data.get("data", {}).get("children", [])
            if not children:
                print("No se encontraron más elementos.")
                break

            inserted, last_id = save_to_mongodb(collection, children)
            total_inserted += inserted
            print(f"Insertados en esta página: {inserted}")

            if inserted < 100:
                print("Menos de 100 elementos insertados, finalizando.")
                break

            if not last_id:
                print("No se pudo determinar el último ID. Finalizando.")
                break

            after = last_id
            sleep(30)

        print(f"Total insertados en esta ejecución: {total_inserted}")
        logging.info(f"Total insertados en esta ejecución: {total_inserted}")

def run():
    logging.info("Iniciando scraper...")
    # Aquí iría tu lógica real de scrap y actualización de MongoDB
    scraper()
    sleep(1)  # Simulación
    logging.info("Scraper finalizado: Base de datos actualizada correctamente.")








""" # Lanzar scheduler en segundo plano al iniciar Flask
@app.before_first_request
def iniciar_scheduler():
    hilo = threading.Thread(target=scheduler)
    hilo.daemon = True
    hilo.start() """

# ----------------- RUTAS EXISTENTES -----------------
@app.route("/redis-test")
def redis_test():
    try:
        cache_key = "test:timestamp"
        cached = redis_client.get(cache_key)
        if cached:
            return jsonify({
                "cached": True,
                "timestamp": cached.decode("utf-8")
            })
        timestamp = datetime.utcnow().isoformat()
        redis_client.set(cache_key, timestamp, ex=300)
        return jsonify({
            "cached": False,
            "timestamp": timestamp
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/test-cache")
def test_cache():
    print("⚡ NO HAY CACHÉ, ejecutando lógica...")
    return jsonify({"timestamp": datetime.utcnow().isoformat()})

@app.route('/api/tarea-secreta')
def tarea_secreta():
    token = request.args.get('token')
    secret_token = os.getenv('CRON_TOKEN')
    if token != secret_token:
        abort(403)
    return 'Tarea ejecutada con éxito'

@app.route("/api/actions")
def obtener_acciones():
    try:
        acciones = collection.distinct("action")
        acciones = sorted([a for a in acciones if a])
        return jsonify({"actions": acciones})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/logs")
def obtener_logs():
    try:
        pagina = int(request.args.get("page", 1))
        por_pagina = 25
        autor = request.args.get("author","").strip()
        accion = request.args.get("action","").strip()
        moderador = request.args.get("mod","").strip()

        def es_texto_simple(valor):
            return bool(re.match(r'^[\w\-]{1,32}$', valor))

        if autor and not es_texto_simple(autor):
            return jsonify({"error": "Formato de usuario inválido"}), 400
        if moderador and not es_texto_simple(moderador):
            return jsonify({"error": "Formato de moderador inválido"}), 400

        cache_key = f"logs:page={pagina}&limit={por_pagina}&mod={moderador or 'all'}&author={autor or 'all'}&action={accion or 'all'}"
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
        resultados = (
            collection
            .find(filtro,campos)
            .sort("created_utc", -1)
            .skip((pagina - 1) * por_pagina)
            .limit(por_pagina)
        )
        datos = list(resultados)
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
def home2():
    return jsonify({"test": "200"}), 200

@app.route("/")
def home():
    return "API activa"

@app.route("/api/clear-cache", methods=["POST"])
def clear_cache():
    token = request.args.get("token")
    secret_token = os.getenv('CRON_RESET_CACHE')
    if token != secret_token:
        abort(403)
    for key in redis_client.scan_iter("logs:*"):
        redis_client.delete(key)
    return jsonify({"ok": True, "msg": "Caché limpiada"})

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(error="Demasiadas peticiones, espera unos segundos."), 429

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
