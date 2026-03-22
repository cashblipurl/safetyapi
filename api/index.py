import os
import json
import hashlib
import uuid
import jwt
import datetime
from pymongo import MongoClient
import firebase_admin
from firebase_admin import credentials, messaging
from fastapi import FastAPI, Request

# ---------- FASTAPI APP ----------
app = FastAPI()

# ---------- FIREBASE INIT ----------
if not firebase_admin._apps:
    firebase_raw = os.environ.get("FIREBASE_JSON")

    if not firebase_raw:
        raise Exception("FIREBASE_JSON env variable not set")

    firebase_dict = json.loads(firebase_raw)

    # 🔥 FIX: handle escaped newlines in private key
    firebase_dict["private_key"] = firebase_dict["private_key"].replace("\\n", "\n")

    cred = credentials.Certificate(firebase_dict)
    firebase_admin.initialize_app(cred)

# ---------- DB ----------
MONGO_URI = os.environ.get("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["womensafety"]

users_tbl = db["users"]
devices_tbl = db["devices"]
alerts_tbl = db["alerts"]

# ---------- AUTH ----------
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_THIS")
JWT_ALGO = "HS256"

# ---------- UTILS ----------
def now_iso():
    return datetime.datetime.utcnow().isoformat()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_jwt(username, role):
    return jwt.encode({
        "username": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }, JWT_SECRET, algorithm=JWT_ALGO)

def verify_jwt(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except:
        return None

def json_resp(code, obj):
    return {
        "statusCode": code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(obj)
    }

def auth(headers, body):
    token = headers.get("authorization", "").replace("Bearer ", "")
    if not token:
        token = body.get("token")
    return verify_jwt(token) if token else None

# ---------- CORE HANDLER ----------
def handler(request):
    try:
        body = request.get_json()
    except:
        return json_resp(400, {"error": "Invalid JSON"})

    action = body.get("action")
    headers = request.headers

    if action == "register":
        return register(body)

    if action == "login":
        return login(body)

    if action == "connectClient":
        return connect_client(body)

    claims = auth(headers, body)
    if not claims:
        return json_resp(401, {"error": "Unauthorized"})

    if action == "registerDevice":
        return register_device(claims, body)

    if action == "triggerSOS":
        return trigger_sos(claims, body)

    return json_resp(400, {"error": "Invalid action"})

# ---------- APIs ----------
def register(data):
    if users_tbl.find_one({"username": data["username"]}):
        return json_resp(400, {"error": "User exists"})

    users_tbl.insert_one({
        "username": data["username"],
        "phone": data["phone"],
        "email": data["email"],
        "password": hash_password(data["password"]),
        "role": data.get("role", "user"),
        "unique_code": str(uuid.uuid4())[:8],
        "created_at": now_iso()
    })

    return json_resp(200, {"message": "Registered"})


def login(data):
    user = users_tbl.find_one({"username": data["username"]})
    if not user or user["password"] != hash_password(data["password"]):
        return json_resp(400, {"error": "Invalid credentials"})

    token = create_jwt(user["username"], user["role"])

    return json_resp(200, {
        "token": token,
        "role": user["role"],
        "unique_code": user.get("unique_code")
    })


def connect_client(data):
    user = users_tbl.find_one({"username": data["username"]})

    if not user:
        return json_resp(400, {"error": "User not found"})

    if user["unique_code"] != data["unique_code"]:
        return json_resp(400, {"error": "Invalid code"})

    users_tbl.update_one(
        {"username": data["username"]},
        {"$set": {"linked_client": data["client_username"]}}
    )

    return json_resp(200, {"message": "Connected"})


def register_device(claims, data):
    devices_tbl.update_one(
        {
            "username": claims["username"],
            "device_id": data.get("device_id")
        },
        upsert=True
    )

    return json_resp(200, {"message": "Device saved"})


# ---------- SOS ----------
def trigger_sos(claims, data):
    username = claims["username"]

    user = users_tbl.find_one({"username": username})
    client_username = user.get("linked_client")

    if not client_username:
        return json_resp(400, {"error": "No client linked"})

    alert_id = str(uuid.uuid4())

    alerts_tbl.insert_one({
        "alert_id": alert_id,
        "user": username,
        "client": client_username,
        "status": "ACTIVE",
        "location": {
            "lat": data.get("lat"),
            "lng": data.get("lng")
        },
        "created_at": now_iso()
    })

    devices = list(devices_tbl.find({"username": client_username}))
    # tokens = [d["fcm_token"] for d in devices if d.get("fcm_token")]

    # if tokens:
    #     send_fcm(tokens, username, alert_id, data)

    return json_resp(200, {
        "message": "SOS sent",
        "alert_id": alert_id
    })


# ---------- FCM ----------
def send_fcm(tokens, user, alert_id, data):
    message = messaging.MulticastMessage(
        tokens=tokens,
        notification=messaging.Notification(
            title="🚨 SOS Alert",
            body=f"{user} needs help"
        ),
        data={
            "type": "sos",
            "alert_id": alert_id,
            "lat": str(data.get("lat", "")),
            "lng": str(data.get("lng", ""))
        }
    )

    messaging.send_multicast(message)

# ---------- FASTAPI ROUTE (ENTRY POINT) ----------
@app.post("/")
async def root(request: Request):
    try:
        body = await request.json()
    except:
        return json_resp(400, {"error": "Invalid JSON"})

    class DummyRequest:
        def get_json(self):
            return body
        headers = dict(request.headers)

    return handler(DummyRequest())

@app.get("/health")
async def health():
    try:
        # Optional DB ping
        client.admin.command('ping')

        return {
            "status": "ok",
            "service": "womensafety-api",
            "time": datetime.datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

@app.get("/")
async def root_get():
    return {
        "message": "API is running 🚀"
    }
