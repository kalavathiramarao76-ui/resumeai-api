import httpx
import json
from ..core.config import GROQ_API_KEY

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

async def analyze_resume(text: str) -> dict:
    prompt = f"""Analyze this resume and provide an ATS score. Return JSON only:
{{
  "overall": <0-100>,
  "formatting": <0-100>,
  "content": <0-100>,
  "keywords": <0-100>,
  "impact": <0-100>,
  "brevity": <0-100>,
  "suggestions": ["suggestion1", "suggestion2", ...]
}}

Resume:
{text[:4000]}"""

    async with httpx.AsyncClient() as client:
        res = await client.post(GROQ_URL, json={
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 2000,
            "response_format": {"type": "json_object"},
        }, headers={"Authorization": f"Bearer {GROQ_API_KEY}"}, timeout=30)
        data = res.json()
        return json.loads(data["choices"][0]["message"]["content"])

async def rewrite_bullet(bullet: str, context: str = "") -> list:
    prompt = f"""Rewrite this resume bullet point to be more impactful. Return JSON array of 3 alternatives:
["rewrite1", "rewrite2", "rewrite3"]

Context: {context}
Original: {bullet}

Rules: Use strong action verbs, add metrics where possible, keep under 2 lines. Return ONLY JSON array."""

    async with httpx.AsyncClient() as client:
        res = await client.post(GROQ_URL, json={
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7,
            "max_tokens": 1000,
            "response_format": {"type": "json_object"},
        }, headers={"Authorization": f"Bearer {GROQ_API_KEY}"}, timeout=30)
        data = res.json()
        content = json.loads(data["choices"][0]["message"]["content"])
        if isinstance(content, dict) and "rewrites" in content:
            return content["rewrites"]
        if isinstance(content, list):
            return content
        return list(content.values())[0] if isinstance(content, dict) else [bullet]

async def job_match(resume_text: str, job_description: str) -> dict:
    prompt = f"""Compare this resume to the job description. Return JSON:
{{
  "match_percentage": <0-100>,
  "matched_skills": ["skill1", ...],
  "missing_skills": ["skill1", ...],
  "suggestions": ["suggestion1", ...],
  "section_scores": {{"experience": <0-100>, "skills": <0-100>, "education": <0-100>}}
}}

Resume:
{resume_text[:3000]}

Job Description:
{job_description[:2000]}"""

    async with httpx.AsyncClient() as client:
        res = await client.post(GROQ_URL, json={
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
            "max_tokens": 2000,
            "response_format": {"type": "json_object"},
        }, headers={"Authorization": f"Bearer {GROQ_API_KEY}"}, timeout=30)
        data = res.json()
        return json.loads(data["choices"][0]["message"]["content"])

async def optimize_resume(text: str) -> dict:
    prompt = f"""Optimize this entire resume for ATS. Return JSON:
{{
  "optimized_sections": [
    {{"type": "summary", "title": "Professional Summary", "bullets": [{{"text": "...", "impact_score": 85}}]}},
    {{"type": "experience", "title": "Experience", "bullets": [{{"text": "...", "impact_score": 90}}]}}
  ],
  "changes_made": ["change1", "change2"],
  "new_score": <0-100>
}}

Resume:
{text[:4000]}"""

    async with httpx.AsyncClient() as client:
        res = await client.post(GROQ_URL, json={
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.5,
            "max_tokens": 4000,
            "response_format": {"type": "json_object"},
        }, headers={"Authorization": f"Bearer {GROQ_API_KEY}"}, timeout=60)
        data = res.json()
        return json.loads(data["choices"][0]["message"]["content"])

async def career_feed() -> list:
    prompt = """Generate 5 career tips for job seekers in tech (March 2026). Return JSON:
[{"title": "...", "description": "...", "category": "tip|insight|challenge|skill"}]"""

    async with httpx.AsyncClient() as client:
        res = await client.post(GROQ_URL, json={
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.8,
            "max_tokens": 2000,
            "response_format": {"type": "json_object"},
        }, headers={"Authorization": f"Bearer {GROQ_API_KEY}"}, timeout=30)
        data = res.json()
        content = json.loads(data["choices"][0]["message"]["content"])
        return content if isinstance(content, list) else content.get("tips", [])
