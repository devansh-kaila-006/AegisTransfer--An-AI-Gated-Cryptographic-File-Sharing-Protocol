from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "AI-Driven Secure File Sharing"
    max_upload_size: int = 104857600  # 100MB
    key_passphrase: str = "secure_college_project_passphrase" # Default, change in prod
    jwt_secret_key: str = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7" # Run 'openssl rand -hex 32' in prod
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    database_url: str = "sqlite:///./audit_log.db"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()
