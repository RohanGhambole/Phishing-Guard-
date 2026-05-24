from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str = "postgresql://user:pass@127.0.0.1:5432/phishdb"
    redis_url: str = "redis://127.0.0.1:6379"

settings = Settings()