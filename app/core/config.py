from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    # App
    APP_NAME: str = "WAF"
    DEBUG: bool = False

    # Database
    DATABASE_URL: str = "sqlite:///./waf.db"

    # WAF
    ML_MODEL_PATH: str = "ml_models/sqli_model.pkl"
    ML_THRESHOLD: float = 0.5
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW: int = 60
    MAX_REQUEST_SIZE: int = 1024 * 1024  # 1MB

    # Dashboard Auth
    DASHBOARD_USERNAME: str = "admin"
    DASHBOARD_PASSWORD: str = "mohamed"

    # Auth
    SECRET_KEY: str = "your-super-secret-key-change-this-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    class Config:
        env_file = ".env"


settings = Settings()