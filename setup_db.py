from sqlalchemy import create_engine, text

DATABASE_URL = "postgresql+psycopg://user:pass@127.0.0.1:5432/phishdb"
engine = create_engine(DATABASE_URL)

try:
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    print("Database connection successful!")
except Exception as e:
    print(f"Connection failed: {e}")
    exit(1)

try:
    from shared.models import Base
    Base.metadata.create_all(engine)
    print("Database tables created!")
except ImportError:
    print("No models found - database connection works but skipping table creation")
except Exception as e:
    print(f"Table creation failed: {e}")