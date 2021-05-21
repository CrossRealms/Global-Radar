
# Fast API
from fastapi import FastAPI, Depends, status, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm


# Logger
from util import logger_manager
logger = logger_manager.setup_logging('cyences_api')



# Token and Password Manager
from jose import JWTError
from util.password_manager import PasswordManager
from util.token_manager import TokenManager
password_manager = PasswordManager(logger)
token_manager = TokenManager(logger)


from util import config

# Schemas
from schemas.general import Token, ApiSuccessResponse, ApiErrorResponse, ApiUnprocessableEntityResponse
from schemas.user import UserRoles, User, UserList, UserCreate
from schemas.fingerprintjs import FingerprintJSData, FingerprintJSGeoLocation

# Database
from db import DatabaseConnection


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")

app = FastAPI(
    title="Cyences API",
    version="1.0.0",
    debug=False
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db = DatabaseConnection().get_db_connection()


async def authenticate_user(username: str, password: str):
    logger.info("Authenticate user: {}".format(username))
    user = await db.users.get_with_name(db.create_session(), username)
    if not user:
        return False
    if not password_manager.verify_password(password, user.hashed_password):
        return False
    return user



@app.on_event("startup")
async def startup_function():
    logger.info("Starting Application.")
    try:
        user = await db.users.get_with_name(db.create_session(), config.app_config.admin_user)
        if user == None:
            logger.info("DB admin user is not present, creating admin user.")
            new_u = User(username=config.app_config.admin_user,
                email=config.app_config.admin_email,
                role=UserRoles.ADMIN,
                hashed_password=password_manager.get_password_hash(config.app_config.admin_password))
            await db.users.add(db.create_session(), new_u)
            logger.info('New user {} created.'.format(new_u.username))
        else:
            logger.info('DB admin user already exist. {}'.format(user.username))
    except Exception as e:
        logger.exception("Exception in startup function: {}".format(e))
        raise


async def authenticate(token: str = Depends(oauth2_scheme)):
    logger.debug("Get current user function.")
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        username = token_manager.decode_access_token(token)
        if username is None:
            raise credentials_exception
    except JWTError:
        logger.exception("JWT Error while getting user token.")
        raise credentials_exception
    user = await db.users.get_with_name(db.create_session(), username)
    if user is None:
        logger.exception("Unable to find user from DB.")
        raise credentials_exception
    return user



def authorize(current_user, roles=[]):
    if current_user.role in roles:
        return True
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Privilege escalation. You do not have access to this function.",
        headers={"WWW-Authenticate": "Bearer"},
    )



# Custom Exception Handler - Logs the exception
class UnicornException(Exception):
    def __init__(self, name: str):
        self.name = name

@app.exception_handler(UnicornException)
async def unicorn_exception_handler(request: Request, exc: UnicornException):
    logger.exception("{}".format(exc))
    raise exc



def get_client_ip(request):
    return request.client.host



@app.post("/api/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    logger.info("login for user: {}".format(form_data.username))
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return token_manager.create_token(user.username)



@app.get(
    "/api/admin/users/list",
    response_model=UserList,
    operation_id="listUsers",
    description="List all the Users"
)
async def get_all_user_list(current_user: User = Depends(authenticate)):
    authorize(current_user, roles=[UserRoles.ADMIN])
    logger.info("Getting user list")
    users = await db.users.get_user_list(db.create_session())
    return users


@app.post(
    "/api/admin/users/register",
    response_model=ApiSuccessResponse,
    status_code=status.HTTP_200_OK,
    responses={422: {"model": ApiUnprocessableEntityResponse}},
    operation_id="addUser",
    description="Register New User to the System",
)
async def register_user(user: UserCreate, role: str=UserRoles.USER, current_user: User = Depends(authenticate)):
    authorize(current_user, roles=[UserRoles.ADMIN])
    logger.info("Creating a new user: {} - {}".format(user.username, user.email))
    try:
        await db.users.add(
            db.create_session(),
            User(
                username=user.username,
                email=user.email,
                hashed_password=password_manager.get_password_hash(user.password),
                role=role,
            )
        )
        return ApiSuccessResponse()
    except Exception as e:
        logger.exception("Exception while creating user. {}".format(e))
        return JSONResponse(
            status_code=422,
            content=ApiErrorResponse(message="Failed - %r" % e).__dict__
        )


@app.post(
    "/api/fingerprintjs/add",
    response_model=ApiSuccessResponse,
    status_code=status.HTTP_200_OK,
    responses={422: {"model": ApiUnprocessableEntityResponse}},
    operation_id="addFingerprintJSData",
    description="Add fingerprinting data collected from the browser.",
)
async def add_fingerprintjs_data(fingerprint_data: FingerprintJSData, request: Request):
    client_ip = get_client_ip(request)
    await db.fingerprintjs.add(db.create_session(), fingerprint_data, client_ip)
    return ApiSuccessResponse()


@app.post(
    "/api/fingerprintjs/add/geo",
    response_model=ApiSuccessResponse,
    status_code=status.HTTP_200_OK,
    responses={422: {"model": ApiUnprocessableEntityResponse}},
    operation_id="addFingerprintJSGeoLocation",
    description="Add geo location collected from the browser.",
)
async def add_fingerprintjs_geo(location_data: FingerprintJSGeoLocation, request: Request):
    client_ip = get_client_ip(request)
    if location_data.geoLocation:
        await db.fingerprintjs.add_geo_location(db.create_session(), location_data, client_ip)
        return ApiSuccessResponse()
    else:
        # we do not store geo errors
        pass




# TODO - Security checks
# 1. input check for XSS and other values
# 2. other security check for APIs
# 3. deleting ip (and cascaded information)
# 4. deleting ip info based on time
# 5. deleting source (and cascaded information)
# 6. deleting source info based on time
# 7. Test true concurrency of API and database operations with Postgres
# 8. Optimise database for better performance
