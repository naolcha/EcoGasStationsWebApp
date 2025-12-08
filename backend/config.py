from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "EcoGasStationsWebApp"
    database_url: str
    api_key: str  
    access_token_expire_minutes: int = 60

    secret_key: str = "supersecretkey"         
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60   

    class Config:
        env_file = ".env"
        extra = "ignore"  
settings = Settings()

