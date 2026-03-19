import psycopg2
from psycopg2.extras import RealDictCursor
from .config import DATABASE_URL

def get_db():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            name VARCHAR(255),
            plan VARCHAR(50) DEFAULT 'free',
            scans_used INT DEFAULT 0,
            scans_limit INT DEFAULT 3,
            stripe_customer_id VARCHAR(255),
            created_at TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS resumes (
            id SERIAL PRIMARY KEY,
            user_id INT REFERENCES users(id),
            name VARCHAR(255) DEFAULT 'Untitled Resume',
            file_url TEXT,
            raw_text TEXT,
            parsed_data JSONB,
            score JSONB,
            created_at TIMESTAMP DEFAULT NOW(),
            updated_at TIMESTAMP DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS generations (
            id SERIAL PRIMARY KEY,
            user_id INT REFERENCES users(id),
            resume_id INT REFERENCES resumes(id),
            action VARCHAR(50),
            input_data JSONB,
            output_data JSONB,
            created_at TIMESTAMP DEFAULT NOW()
        );
    """)
    conn.commit()
    cur.close()
    conn.close()
