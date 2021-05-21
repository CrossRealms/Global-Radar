
from util import config

if config.app_config.database_type == 'mongodb':
    from db.mongo_db.db_connection import MongoDBConnection as DBConnection
elif config.app_config.database_type == 'postgres':
    from db.postgres_db.db_connection import PostgresConnection as DBConnection
else:
    raise Exception("Database type is not configured. Please check bot.config [postgres_database] database_type.")



class DatabaseConnection:
    def __init__(self):
        self.db_connection = None
    
    def get_db_connection(self):
        if self.db_connection:
            return self.db_connection
        
        self.db_connection = DBConnection()
        return self.db_connection
