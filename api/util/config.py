import urllib
import configparser

CONFIG_FILE = 'api.conf'
MONGODB_CONFIGURATION = 'monogodb_database'
POSTGRES_DATABASE_CONFIGURATION = 'postgres_database'
APP_ADMIN_CONFIGURATION = 'app-admin'
TOKEN_CONFIGURATION = 'token'
HONEYPOTS_CONFIGURATION = 'honeypots'


class AppConfig:
    def __init__(self):
        conf = configparser.RawConfigParser()   
        conf.read(CONFIG_FILE)
        self.admin_user = conf.get(APP_ADMIN_CONFIGURATION, 'user')
        self.admin_email = conf.get(APP_ADMIN_CONFIGURATION, 'email')
        self.admin_password = conf.get(APP_ADMIN_CONFIGURATION, 'password')
        self.database_type = conf.get(APP_ADMIN_CONFIGURATION, 'database_type')

app_config = AppConfig()


class MongoDBConfig:
    def __init__(self):
        conf = configparser.RawConfigParser()   
        conf.read(CONFIG_FILE)
        self.db_username = conf.get(MONGODB_CONFIGURATION, 'username')
        self.db_password = conf.get(MONGODB_CONFIGURATION, 'password')
        self.db_database_name = conf.get(MONGODB_CONFIGURATION, 'name')
        self.db_url = conf.get(MONGODB_CONFIGURATION, 'uri').format(urllib.parse.quote(self.db_username), urllib.parse.quote(self.db_password), urllib.parse.quote(self.db_database_name))


class PostgresDatabaseConfig:
    def __init__(self):
        conf = configparser.RawConfigParser()   
        conf.read(CONFIG_FILE)

        self.db_username = conf.get(POSTGRES_DATABASE_CONFIGURATION, 'username')
        self.db_password = conf.get(POSTGRES_DATABASE_CONFIGURATION, 'password')
        self.db_host = conf.get(POSTGRES_DATABASE_CONFIGURATION, 'host')
        self.db_port = conf.get(POSTGRES_DATABASE_CONFIGURATION, 'port')
        self.db_database_name = conf.get(POSTGRES_DATABASE_CONFIGURATION, 'name')
        self.db_url = conf.get(POSTGRES_DATABASE_CONFIGURATION, 'uri').format(urllib.parse.quote(self.db_username), urllib.parse.quote(self.db_password), urllib.parse.quote(self.db_host), urllib.parse.quote(self.db_port), urllib.parse.quote(self.db_database_name))


class TokenConfig:
    def __init__(self):
        conf = configparser.RawConfigParser()   
        conf.read(CONFIG_FILE)
        self.secret_key = conf.get(TOKEN_CONFIGURATION, 'secret_key')
        self.algorithm = conf.get(TOKEN_CONFIGURATION, 'algorithm')

token_config = TokenConfig()


class HoneyPotsConfig:
    def __init__(self):
        conf = configparser.RawConfigParser()   
        conf.read(CONFIG_FILE)
        ha = conf.get(HONEYPOTS_CONFIGURATION, 'accounts')
        self.honeypot_accounts = [i.strip() for i in ha.split(",")]
