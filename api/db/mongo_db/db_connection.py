import motor.motor_asyncio

from util import config
from . import db_user, db_fingerprintjs, db_firewall_mal_ips, db_mal_ips


class MongoDBConnection:
    def __init__(self):
        database_config = config.MongoDBConfig()
        self.client = motor.motor_asyncio.AsyncIOMotorClient(database_config.db_url)
        self.db = self.client[database_config.db_database_name]

        self.users = db_user
        self.fingerprintjs = db_fingerprintjs
        self.firewall_mal_ips = db_firewall_mal_ips
        self.mal_ips = db_mal_ips
    
    def create_session(self):
        return self.db
