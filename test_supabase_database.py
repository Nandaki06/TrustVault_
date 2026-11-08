
import os
import psycopg
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL is missing in .env file!")

try:
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:

            # Test database connection
            cur.execute("SELECT version();")
            version = cur.fetchone()
            print("Database connection successful!")

            # Check TrustVault tables
            cur.execute("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_name IN (
                    'users',
                    'documents',
                    'document_permissions',
                    'audit_logs'
                )
                ORDER BY table_name;
            """)

            tables = cur.fetchall()

            print("\nTrustVault tables found:")
            for table in tables:
                print("-", table[0])

            if len(tables) == 4:
                print("\nAll four TrustVault tables verified!")
            else:
                print("\nWarning: Some TrustVault tables are missing.")

except Exception as error:
    print("Database test failed:", error)
