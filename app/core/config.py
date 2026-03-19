import os

DATABASE_URL = os.getenv("DATABASE_URL", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
JWT_SECRET = os.getenv("JWT_SECRET", "resumeai-secret-2026")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 168  # 7 days
