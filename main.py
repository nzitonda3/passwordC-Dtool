# main.py
import uvicorn
from fastapi import FastAPI, Request, Form, HTTPException
from pydantic import BaseModel
from database import AsyncSessionLocal, init_db, User, LoginLog
from utils import hash_password, verify_password, fingerprint_password
from sqlalchemy import select

app = FastAPI(title="Password Security System")


# Start DB
@app.on_event("startup")
async def startup_event():
    await init_db()


# Extract client IP (X-Forwarded-For supported for attack simulation)
def get_client_ip(request: Request):
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host


# --------------------------
# SIGNUP ENDPOINT
# --------------------------
class SignupModel(BaseModel):
    username: str
    password: str

@app.post("/signup")
async def signup(data: SignupModel):
    async with AsyncSessionLocal() as session:
        # check if user exists
        q = select(User).where(User.username == data.username)
        res = await session.execute(q)
        existing = res.scalar_one_or_none()

        if existing:
            raise HTTPException(status_code=400, detail="User already exists")

        user = User(
            username=data.username,
            password_hash=hash_password(data.password)
        )

        session.add(user)
        await session.commit()

    return {"status": "ok", "message": "User created"}


# --------------------------
# LOGIN ENDPOINT
# --------------------------
@app.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    ip = get_client_ip(request)

    async with AsyncSessionLocal() as session:
        q = select(User).where(User.username == username)
        res = await session.execute(q)
        user = res.scalar_one_or_none()

        success = False
        if user and verify_password(password, user.password_hash):
            success = True

        # Log the attempt
        log = LoginLog(
            username=username,
            ip=ip,
            status="success" if success else "fail",
            pwd_fingerprint=fingerprint_password(password)
        )
        session.add(log)
        await session.commit()

    if success:
        return {"status": "ok", "message": "Login successful"}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")


# --------------------------
# ADMIN LOG VIEW
# --------------------------
@app.get("/admin/logs")
async def admin_logs():
    async with AsyncSessionLocal() as session:
        q = select(LoginLog).order_by(LoginLog.timestamp.desc())
        res = await session.execute(q)
        logs = res.scalars().all()

    output = []
    for l in logs:
        output.append({
            "timestamp": l.timestamp.isoformat(),
            "username": l.username,
            "ip": l.ip,
            "status": l.status,
            "pwd_fingerprint": l.pwd_fingerprint[:12]   # shorter for readability
        })

    return output


# Run server
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
