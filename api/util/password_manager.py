
from passlib.context import CryptContext

class PasswordManager:

    def __init__(self, logger):
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        self.logger = logger

    def get_password_hash(self, password):
        self.logger.debug("Get password hash.")
        return self.pwd_context.hash(password)

    def verify_password(self, plain_password, hashed_password):
        self.logger.debug("Verify password.")
        return self.pwd_context.verify(plain_password, hashed_password)
