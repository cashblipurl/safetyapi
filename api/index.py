import os
import uuid
import datetime
import jwt
import httpx

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks, Depends
from pymongo import MongoClient
from passlib.context import CryptContext

# ---------- CONFIG ----------
MONGO_URI = os.getenv("MONGO_URI")
ONESIGNAL_APP_ID = os.getenv("ONESIGNAL_APP_ID")
ONESIGNAL_API_KEY = os.getenv("ONESIGNAL_API_KEY")
JWT_SECRET = os.getenv("JWT_SECRET", "CHANGE_THIS")
JWT_ALGO = "HS256"

# ---------- APP ----------
app = FastAPI()

# ---------- DB ----------
client = MongoClient(MONGO_URI)
db = client["womensafety"]

users_tbl = db["users"]
devices_tbl = db["devices"]
alerts_tbl = db["alerts"]

# ---------- INDEXES ----------
devices_tbl.create_index("device_id", unique=True)
devices_tbl.create_index("username")
alerts_tbl.create_index("user")
alerts_tbl.create_index([("location", "2dsphere")])

# ---------- PASSWORD HASH ----------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(password, hashed):
    return pwd_context.verify(password, hashed)

# ---------- UTILS ----------
def now():
    return datetime.datetime.utcnow()

def create_jwt(username, role):
    payload = {
        "username": username,
        "role": role,
        "exp": now() + datetime.timedelta(hours=2),
        "iat": now()
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def verify_jwt(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except:
        return None

def get_current_user(request: Request):
    token = request.headers.get("authorization", "").replace("Bearer ", "")
    if not token:
        raise HTTPException(401, "Missing token")

    claims = verify_jwt(token)
    if not claims:
        raise HTTPException(401, "Invalid token")

    user = users_tbl.find_one({"username": claims["username"]})
    if not user:
        raise HTTPException(401, "User not found")

    return user

# ---------- NOTIFICATION ----------
async def send_push_notification(player_ids, message, extra_data=None):
    if not player_ids:
        return

    url = "https://onesignal.com/api/v1/notifications"

    payload = {
        "app_id": ONESIGNAL_APP_ID,
        "include_player_ids": player_ids,
        "contents": {"en": message},
        "data": extra_data or {}
    }

    headers = {
        "Authorization": f"Basic {ONESIGNAL_API_KEY}",
        "Content-Type": "application/json"
    }

    async with httpx.AsyncClient(timeout=5) as client:
        try:
            await client.post(url, json=payload, headers=headers)
        except Exception as e:
            print("Push error:", str(e))

# ---------- AUTH ----------
@app.post("/register")
async def register(data: dict):
    if users_tbl.find_one({"username": data["username"]}):
        raise HTTPException(400, "User exists")

    users_tbl.insert_one({
        "username": data["username"],
        "phone": data.get("phone"),
        "email": data.get("email"),
        "password": hash_password(data["password"]),
        "role": "user",
        "unique_code": str(uuid.uuid4())[:8],
        "linked_client": None,
        "created_at": now()
    })

    return {"message": "Registered successfully"}

@app.post("/login")
async def login(data: dict):
    user = users_tbl.find_one({"username": data["username"]})

    if not user or not verify_password(data["password"], user["password"]):
        raise HTTPException(401, "Invalid credentials")

    token = create_jwt(user["username"], user["role"])

    return {
        "token": token,
        "unique_code": user["unique_code"]
    }

# ---------- LINK CONTACT ----------
@app.post("/connect")
async def connect(data: dict, user=Depends(get_current_user)):
    client = users_tbl.find_one({"username": data["client_username"]})

    if not client:
        raise HTTPException(404, "Client not found")

    if client["unique_code"] != data["unique_code"]:
        raise HTTPException(400, "Invalid code")

    users_tbl.update_one(
        {"_id": user["_id"]},
        {"$set": {"linked_client": client["username"]}}
    )

    return {"message": "Connected successfully"}

# ---------- DEVICE ----------
@app.post("/device")
async def register_device(data: dict, user=Depends(get_current_user)):
    if not data.get("device_id") or not data.get("player_id"):
        raise HTTPException(400, "device_id & player_id required")

    devices_tbl.update_one(
        {"device_id": data["device_id"]},
        {
            "$set": {
                "username": user["username"],
                "player_id": data["player_id"],
                "updated_at": now()
            }
        },
        upsert=True
    )

    return {"message": "Device registered"}

# ---------- SOS ----------
@app.post("/sos")
async def trigger_sos(data: dict, background_tasks: BackgroundTasks, user=Depends(get_current_user)):
    if not user.get("linked_client"):
        raise HTTPException(400, "No trusted contact linked")

    alert_id = str(uuid.uuid4())

    alerts_tbl.insert_one({
        "alert_id": alert_id,
        "user": user["username"],
        "client": user["linked_client"],
        "status": "ACTIVE",
        "location": {
            "type": "Point",
            "coordinates": [data.get("lng"), data.get("lat")]
        },
        "created_at": now()
    })

    # fetch devices
    devices = devices_tbl.find({"username": user["linked_client"]})
    player_ids = [d["player_id"] for d in devices if d.get("player_id")]

    # background notification
    background_tasks.add_task(
        send_push_notification,
        player_ids,
        f"🚨 SOS Alert from {user['username']}",
        {
            "alert_id": alert_id,
            "lat": data.get("lat"),
            "lng": data.get("lng"),
            "type": "SOS"
        }
    )

    return {
        "message": "SOS triggered",
        "alert_id": alert_id,
        "devices_notified": len(player_ids)
    }

# ---------- HEALTH ----------
@app.get("/health")
async def health():
    try:
        client.admin.command("ping")
        return {"status": "ok", "time": now()}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/")
async def root():
    return {"message": "Women Safety API running 🚀"}
