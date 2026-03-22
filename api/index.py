# api/index.py
import os
import json
import hashlib
import uuid
import jwt
import datetime
from pymongo import MongoClient
import firebase_admin
from firebase_admin import credentials, messaging
from fastapi import FastAPI, Request, HTTPException

# ---------- FASTAPI APP ----------
app = FastAPI(title="WomenSafety API", version="1.0")

# ---------- FIREBASE INIT ----------
if not firebase_admin._apps:
    firebase_raw = os.environ.get("FIREBASE_JSON")
    if not firebase_raw:
        raise RuntimeError("FIREBASE_JSON env variable not set")

    try:
        firebase_dict = json.loads(firebase_raw)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid FIREBASE_JSON: {str(e)}")

    # Handle escaped newlines
    firebase_dict["private_key"] = firebase_dict["private_key"].replace("\\n", "\n")

    cred = credentials.Certificate(firebase_dict)
    firebase_admin.initialize_app(cred)

# ---------- DB ----------
MONGO_URI = os.environ.get("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("MONGO_URI env variable not set")

client = MongoClient(MONGO_URI)
db = client["womensafety"]

users_tbl = db["users"]
devices_tbl = db["devices"]
alerts_tbl = db["alerts"]

# ---------- AUTH ----------
JWT_SECRET = os.environ.get("JWT_SECRET", "CHANGE_THIS")
JWT_ALGO = "HS256"

# ---------- UTILS ----------
def now_iso():
    return datetime.datetime.utcnow().isoformat()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_jwt(username: str, role: str) -> str:
    payload = {
        "username": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def verify_jwt(token: str):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except jwt.PyJWTError:
        return None

# ---------- AUTH HELPER ----------
def auth(headers: dict, body: dict):
    token = headers.get("authorization", "").replace("Bearer ", "")
    if not token:
        token = body.get("token")
    return verify_jwt(token) if token else None

# ---------- CORE HANDLERS ----------
def register(data: dict):
    if users_tbl.find_one({"username": data["username"]}):
        raise HTTPException(status_code=400, detail="User exists")

    users_tbl.insert_one({
        "username": data["username"],
        "phone": data["phone"],
        "email": data["email"],
        "password": hash_password(data["password"]),
        "role": data.get("role", "user"),
        "unique_code": str(uuid.uuid4())[:8],
        "created_at": now_iso()
    })
    return {"message": "Registered"}

def login(data: dict):
    user = users_tbl.find_one({"username": data["username"]})
    if not user or user["password"] != hash_password(data["password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    token = create_jwt(user["username"], user["role"])
    return {"token": token, "role": user["role"], "unique_code": user.get("unique_code")}

def connect_client(data: dict):
    user = users_tbl.find_one({"username": data["username"]})
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    if user["unique_code"] != data["unique_code"]:
        raise HTTPException(status_code=400, detail="Invalid code")

    users_tbl.update_one(
        {"username": data["username"]},
        {"$set": {"linked_client": data["client_username"]}}
    )
    return {"message": "Connected"}

def register_device(claims: dict, data: dict):
    devices_tbl.update_one(
        {"username": claims["username"], "device_id": data.get("device_id")},
        {"$set": {"fcm_token": data["fcm_token"], "updated_at": now_iso()}},
        upsert=True
    )
    return {"message": "Device saved"}

def trigger_sos(claims: dict, data: dict):
    username = claims["username"]
    user = users_tbl.find_one({"username": username})
    client_username = user.get("linked_client")
    if not client_username:
        raise HTTPException(status_code=400, detail="No client linked")

    alert_id = str(uuid.uuid4())
    alerts_tbl.insert_one({
        "alert_id": alert_id,
        "user": username,
        "client": client_username,
        "status": "ACTIVE",
        "location": {"lat": data.get("lat"), "lng": data.get("lng")},
        "created_at": now_iso()
    })

    devices = list(devices_tbl.find({"username": client_username}))
    tokens = [d["fcm_token"] for d in devices if d.get("fcm_token")]
    if tokens:
        send_fcm(tokens, username, alert_id, data)

    return {"message": "SOS sent", "alert_id": alert_id}

# ---------- FCM ----------
def send_fcm(tokens: list, user: str, alert_id: str, data: dict):
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

# ---------- FASTAPI ROUTES ----------
@app.post("/")
async def root(request: Request):
    body = await request.json()
    action = body.get("action")
    headers = dict(request.headers)

    if action == "register":
        return register(body)
    if action == "login":
        return login(body)
    if action == "connectClient":
        return connect_client(body)

    claims = auth(headers, body)
    if not claims:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if action == "registerDevice":
        return register_device(claims, body)
    if action == "triggerSOS":
        return trigger_sos(claims, body)

    raise HTTPException(status_code=400, detail="Invalid action")

@app.get("/health")
async def health():
    try:
        client.admin.command("ping")
        return {"status": "ok", "service": "womensafety-api", "time": now_iso()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/")
async def root_get():
    return {"message": "API is running 🚀"}
