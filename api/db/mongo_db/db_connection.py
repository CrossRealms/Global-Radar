import motor.motor_asyncio

from util import config
from . import db_user, db_fingerprintjs


class MongoDBConnection:
    def __init__(self):
        database_config = config.MongoDBConfig()
        self.client = motor.motor_asyncio.AsyncIOMotorClient(database_config.db_url)
        self.db = self.client[database_config.db_database_name]

        self.users = db_user
        self.fingerprintjs = db_fingerprintjs
    
    def create_session(self):
        return self.db
