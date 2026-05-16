from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings (BaseSettings):
    DB_HOST: str
    DB_PORT: str
    DB_DATABASE: str
    DB_USER: str
    DB_PASSWORD: str
    SECRET_KEY: str
    ALGORITHM: str
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: str
    MAIL_PORT: str
    MAIL_SERVER: str
    CORS_ORIGINS: str = "*"
    LOBSTERTRAP_BASE_URL: str
    ENVIRONMENT: str = "development"  # "development" or "production"

    model_config = SettingsConfigDict (env_file= ".env")
    
    @property
    def async_db_url (self) -> str:
        return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_DATABASE}"

    @property
    def cors_origin_list (self) -> list[str]:
        return [origin.strip () for origin in self.CORS_ORIGINS.split (",")]

settings = Settings ()