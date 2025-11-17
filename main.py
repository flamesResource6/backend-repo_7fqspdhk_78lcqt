import os
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, WebSocket, WebSocketDisconnect, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from pydantic import BaseModel, EmailStr
from passlib.hash import bcrypt
import jwt
from database import db
from bson import ObjectId

APP_NAME = "Naija Traffic Backend"
JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret")
MAPBOX_TOKEN = os.getenv("MAPBOX_TOKEN", "YOUR_MAPBOX_KEY")
OPENWEATHER_KEY = os.getenv("OPENWEATHER_KEY", "YOUR_OPENWEATHER_KEY")

app = FastAPI(title=APP_NAME)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

# ------------------ Helpers ------------------

def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def decode_token(token: str) -> Dict[str, Any]:
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])  # type: ignore


def current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[Dict[str, Any]]:
    if not credentials:
        return None
    try:
        payload = decode_token(credentials.credentials)
        uid = payload.get("id")
        if uid and uid != "anonymous" and db is not None:
            u = db.user.find_one({"_id": oid(uid)})
            if u:
                u["id"] = str(u.pop("_id"))
                u.pop("password_hash", None)
                return u
        return {"id": uid, "email": payload.get("email"), "isAdmin": payload.get("isAdmin", False)}
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# Ensure indices
if db is not None:
    try:
        db.report.create_index("expires_at", expireAfterSeconds=0)
        db.report.create_index([("created_at", -1)])
        db.report.create_index([("city", 1)])
        db.user.create_index("email", unique=True)
    except Exception:
        pass

# --------------- Models ----------------
class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    city: Optional[str] = None


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class VoteRequest(BaseModel):
    userId: Optional[str]
    value: int


class ReportJSON(BaseModel):
    location: Dict[str, float]
    type: str
    description: Optional[str] = None
    photo: Optional[str] = None
    anonymous: Optional[bool] = False
    city: Optional[str] = None


# --------------- WebSocket Hub ----------------
class ConnectionManager:
    def __init__(self):
        self.active: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active.discard(websocket)

    async def broadcast(self, event: str, data: dict):
        message = json.dumps({"event": event, "data": data}, default=str)
        for ws in list(self.active):
            try:
                await ws.send_text(message)
            except Exception:
                self.disconnect(ws)


manager = ConnectionManager()

# --------------- Routes ----------------
@app.get("/")
def root():
    return {"service": APP_NAME, "ok": True}


@app.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keepalive; ignore client messages
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# Auth
@app.post("/api/auth/signup")
def signup(req: SignupRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    if db.user.find_one({"email": req.email}):
        raise HTTPException(status_code=400, detail="Email already in use")
    password_hash = bcrypt.hash(req.password)
    doc = {
        "name": req.name,
        "email": req.email,
        "password_hash": password_hash,
        "city": req.city,
        "points": 0,
        "badges": [],
        "provider": "local",
        "is_admin": False,
        "created_at": datetime.now(timezone.utc),
    }
    user_id = db.user.insert_one(doc).inserted_id
    token = jwt.encode({"id": str(user_id), "email": req.email, "isAdmin": False}, JWT_SECRET, algorithm="HS256")
    return {"token": token, "user": {"id": str(user_id), "name": req.name, "email": req.email, "city": req.city, "points": 0, "badges": []}}


@app.post("/api/auth/login")
def login(req: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    user = db.user.find_one({"email": req.email})
    if not user or not bcrypt.verify(req.password, user.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    token = jwt.encode({"id": str(user["_id"]), "email": user["email"], "isAdmin": user.get("is_admin", False)}, JWT_SECRET, algorithm="HS256")
    return {"token": token, "user": {"id": str(user["_id"]), "name": user.get("name"), "email": user.get("email"), "city": user.get("city"), "points": user.get("points", 0), "badges": user.get("badges", [])}}


@app.get("/api/auth/me")
def me(user: Optional[Dict[str, Any]] = Depends(current_user)):
    return {"user": user}


@app.post("/api/auth/anonymous")
def anonymous():
    token = jwt.encode({"id": "anonymous", "email": "anonymous@local", "isAdmin": False}, JWT_SECRET, algorithm="HS256")
    return {"token": token, "user": {"id": "anonymous", "name": "Guest", "email": "anonymous"}}


# Reports
@app.get("/api/reports")
def list_reports(city: Optional[str] = None):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    q: Dict[str, Any] = {}
    if city:
        q["city"] = city
    items = list(db.report.find(q).sort("created_at", -1).limit(200))
    for r in items:
        r["id"] = str(r.pop("_id"))
    return items


@app.post("/api/reports")
async def create_report(
    # Form-data support (with optional photo upload)
    lat: Optional[float] = Form(None),
    lng: Optional[float] = Form(None),
    type: Optional[str] = Form(None),
    desc: Optional[str] = Form(None),
    userId: Optional[str] = Form(None),
    city: Optional[str] = Form(None),
    photo: Optional[UploadFile] = File(None),
    # JSON support
    payload: Optional[ReportJSON] = Body(None),
):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    photo_url = None
    if photo is not None:
        upload_dir = os.path.join(os.getcwd(), "uploads")
        os.makedirs(upload_dir, exist_ok=True)
        filename = f"{int(datetime.now().timestamp())}-{photo.filename}"
        filepath = os.path.join(upload_dir, filename)
        with open(filepath, "wb") as f:
            f.write(await photo.read())
        photo_url = f"/uploads/{filename}"

    if payload is not None:
        lat = payload.location.get("lat")
        lng = payload.location.get("lng")
        type = payload.type
        desc = payload.description
        city = payload.city
        # If base64 photo strings are sent, you could store them directly or upload to storage
        if payload.photo and not photo_url:
            photo_url = payload.photo  # storing data URL as-is for demo
        userId = None if payload.anonymous else userId

    if lat is None or lng is None or not type:
        raise HTTPException(status_code=400, detail="Missing required fields")

    now = datetime.now(timezone.utc)
    doc = {
        "location": {"lat": lat, "lng": lng},
        "type": type,
        "desc": desc,
        "timestamp": now,
        "userId": None if (userId in (None, "anonymous")) else userId,
        "city": city,
        "photoUrl": photo_url,
        "votes": {},
        "score": 0,
        "created_at": now,
        "updated_at": now,
        "expires_at": now + timedelta(hours=1),
    }
    inserted = db.report.insert_one(doc)
    doc["id"] = str(inserted.inserted_id)
    await manager.broadcast("report:new", doc)
    return doc


@app.post("/api/reports/{id}/vote")
def vote_report(id: str, req: VoteRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    r = db.report.find_one({"_id": oid(id)})
    if not r:
        raise HTTPException(status_code=404, detail="Not found")
    votes: Dict[str, int] = r.get("votes", {})
    if req.userId and req.userId != "anonymous":
        votes[req.userId] = 1 if req.value >= 0 else -1
    score = sum(votes.values())
    db.report.update_one({"_id": oid(id)}, {"$set": {"votes": votes, "score": score, "updated_at": datetime.now(timezone.utc)}})
    r = db.report.find_one({"_id": oid(id)})
    r["id"] = str(r.pop("_id"))
    return r


# Leaderboard
@app.get("/api/leaderboard")
def leaderboard(city: Optional[str] = None):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    pipeline = []
    if city:
        pipeline.append({"$match": {"city": city}})
    pipeline += [
        {"$match": {"userId": {"$ne": None}}},
        {"$group": {"_id": "$userId", "reports": {"$sum": 1}}},
        {"$sort": {"reports": -1}},
        {"$limit": 20},
    ]
    agg = list(db.report.aggregate(pipeline))
    user_ids = [oid(x["_id"]) for x in agg if ObjectId.is_valid(x["_id"]) ]
    users = list(db.user.find({"_id": {"$in": user_ids}})) if user_ids else []
    by_id = {str(u["_id"]): u for u in users}
    result = [{"user": {"name": by_id.get(x["_id"], {}).get("name", "Anonymous"), "id": x["_id"]}, "reports": x["reports"]} for x in agg]
    return result


# Admin minimal
@app.get("/api/admin/reports")
def admin_reports(user: Optional[Dict[str, Any]] = Depends(current_user)):
    if not user or not user.get("isAdmin"):
        raise HTTPException(status_code=403, detail="Forbidden")
    items = list(db.report.find({}).sort("created_at", -1).limit(500))
    for r in items:
        r["id"] = str(r.pop("_id"))
    return items


@app.delete("/api/admin/reports/{id}")
def admin_delete(id: str, user: Optional[Dict[str, Any]] = Depends(current_user)):
    if not user or not user.get("isAdmin"):
        raise HTTPException(status_code=403, detail="Forbidden")
    db.report.delete_one({"_id": oid(id)})
    return {"ok": True}


# Proxy external APIs
import httpx


@app.get("/api/directions")
async def directions(start: str, end: str):
    # start/end as "lng,lat" strings
    url = f"https://api.mapbox.com/directions/v5/mapbox/driving/{start};{end}"
    params = {"access_token": MAPBOX_TOKEN, "geometries": "geojson", "overview": "full"}
    async with httpx.AsyncClient() as client:
        r = await client.get(url, params=params)
        return r.json()


@app.get("/api/weather")
async def weather(lat: float, lon: float):
    url = "https://api.openweathermap.org/data/2.5/weather"
    params = {"lat": lat, "lon": lon, "appid": OPENWEATHER_KEY, "units": "metric"}
    async with httpx.AsyncClient() as client:
        r = await client.get(url, params=params)
        return r.json()


# Seed
@app.post("/api/seed")
def seed():
    sample = [
        {"location": {"lat": 6.5244, "lng": 3.3792}, "type": "traffic_jam", "desc": "Heavy traffic on Third Mainland Bridge", "city": "Lagos"},
        {"location": {"lat": 9.0765, "lng": 7.3986}, "type": "roadwork", "desc": "Road maintenance causing delays", "city": "Abuja"},
        {"location": {"lat": 6.465422, "lng": 3.406448}, "type": "flood", "desc": "Flooded area around Lekki", "city": "Lagos"},
    ]
    now = datetime.now(timezone.utc)
    for s in sample:
        s.update({"timestamp": now, "created_at": now, "updated_at": now, "votes": {}, "score": 0, "expires_at": now + timedelta(hours=1)})
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    db.report.insert_many(sample)
    return {"inserted": len(sample)}


# Static files for uploads
@app.get("/uploads/{filename}")
def get_upload(filename: str):
    file_path = os.path.join(os.getcwd(), "uploads", filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="Not found")
    return FileResponse(file_path)


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
            response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
