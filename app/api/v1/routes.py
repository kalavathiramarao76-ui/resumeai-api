from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from ...core.auth import hash_password, verify_password, create_token, get_current_user
from ...core.database import get_db, init_db
from ...services.ai_service import analyze_resume, rewrite_bullet, job_match, optimize_resume, career_feed
import json

router = APIRouter(prefix="/api/v1")

class AuthRequest(BaseModel):
    email: str
    password: str
    name: str = ""

class AnalyzeRequest(BaseModel):
    text: str

class RewriteRequest(BaseModel):
    bullet: str
    context: str = ""

class JobMatchRequest(BaseModel):
    resume_text: str
    job_description: str

@router.post("/auth/register")
def register(req: AuthRequest, db=Depends(get_db)):
    init_db()
    cur = db.cursor()
    try:
        cur.execute(
            "INSERT INTO users (email, password_hash, name) VALUES (%s, %s, %s) RETURNING id, email, name, plan, scans_used, scans_limit, created_at",
            (req.email, hash_password(req.password), req.name or req.email.split("@")[0])
        )
        user = dict(cur.fetchone())
        db.commit()
        token = create_token(user["id"], user["email"])
        return {"user": user, "token": token}
    except Exception as e:
        db.rollback()
        if "duplicate" in str(e).lower():
            raise HTTPException(status_code=409, detail="Email already exists")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/auth/login")
def login(req: AuthRequest, db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE email = %s", (req.email,))
    user = cur.fetchone()
    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user = dict(user)
    del user["password_hash"]
    token = create_token(user["id"], user["email"])
    return {"user": user, "token": token}

@router.post("/resumes/analyze")
async def analyze(req: AnalyzeRequest, user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT scans_used, scans_limit, plan FROM users WHERE id = %s", (user["id"],))
    u = cur.fetchone()
    if u["plan"] == "free" and u["scans_used"] >= u["scans_limit"]:
        raise HTTPException(status_code=403, detail="Free scan limit reached. Upgrade to Pro.")
    score = await analyze_resume(req.text)
    cur.execute("UPDATE users SET scans_used = scans_used + 1 WHERE id = %s", (user["id"],))
    cur.execute(
        "INSERT INTO resumes (user_id, raw_text, score) VALUES (%s, %s, %s) RETURNING id",
        (user["id"], req.text[:5000], json.dumps(score))
    )
    db.commit()
    return {"score": score}

@router.post("/resumes/rewrite-bullet")
async def rewrite(req: RewriteRequest, user=Depends(get_current_user)):
    suggestions = await rewrite_bullet(req.bullet, req.context)
    return {"suggestions": suggestions}

@router.post("/resumes/job-match")
async def match(req: JobMatchRequest, user=Depends(get_current_user)):
    result = await job_match(req.resume_text, req.job_description)
    return result

@router.post("/resumes/optimize")
async def optimize(req: AnalyzeRequest, user=Depends(get_current_user)):
    result = await optimize_resume(req.text)
    return result

@router.get("/career/feed")
async def feed(user=Depends(get_current_user)):
    tips = await career_feed()
    return {"tips": tips}

@router.get("/resumes")
def list_resumes(user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT id, name, file_url, score, created_at, updated_at FROM resumes WHERE user_id = %s ORDER BY updated_at DESC", (user["id"],))
    return {"resumes": [dict(r) for r in cur.fetchall()]}
