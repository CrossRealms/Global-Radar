
from jose import jwt
from util.config import token_config

from schemas.general import Token


class TokenManager:
    def __init__(self, logger):
        self.logger = logger
    
    def create_token(self, username):
        self.logger.info("Creating an access token.")
        data={"sub": username}
        to_encode = data.copy()
        access_token = jwt.encode(to_encode, token_config.secret_key, algorithm=token_config.algorithm)
        return Token(
            access_token=access_token,
            token_type="bearer"
        )
    
    def decode_access_token(self, token):
        payload = jwt.decode(token, token_config.secret_key, algorithms=token_config.algorithm)
        username: str = payload.get("sub")
        return username
