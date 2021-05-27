from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


from util import config
from . import db_user, db_mal_ips, db_firewall_mal_ips, db_fingerprintjs


class DatabaseConnection:
    def __init__(self):
        database_config = config.PostgresDatabaseConfig()

        engine = create_engine(
            database_config.db_url, pool_size=3, max_overflow=0,
        )
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

        self.users = db_user
        self.fingerprintjs = db_fingerprintjs
        self.firewall_mal_ips = db_firewall_mal_ips
        self.mal_ips = db_mal_ips
        
    def create_session(self):
        return self.SessionLocal()
