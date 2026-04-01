from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "ReconX API"
    database_url: str
    redis_url: str
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 120
    refresh_token_expire_minutes: int = 10080
    scan_allowed_schemes: str = "http,https"
    nuclei_templates: str = ""
    scan_throttle_seconds: int = 20
=======
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
    app_name: str = "ReconX API"
    secret_key: str = "change-this-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60

    database_url: str = "postgresql+psycopg2://reconx:reconx@db:5432/reconx"
    redis_url: str = "redis://redis:6379/0"

    scan_allowed_suffix_enforcement: bool = True

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
<<<<<<< ours
<<<<<<< ours
<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs
=======
>>>>>>> theirs


settings = Settings()
