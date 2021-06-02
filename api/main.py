
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
from schemas.malicious_ips import MaliciousIPListAdmin, MaliciousIPListOnlyIPs, MaliciousIPsRemove
from schemas.shadow_collector import SCDeviceList
from schemas.firewall_malicious_ips import FirewallMaliciousIPCreateList, FirewallMaliciousIPCreateListOld, FirewallMaliciousIPGetAll, FirewallMaliciousIPGetAllOld, FirewallMaliciousIPsRemove

# Database
from db import DatabaseConnection


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/token")

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

@app.exception_handler(Exception)
async def unicorn_exception_handler(request: Request, exc: Exception):
    logger.exception("{}".format(exc))
    raise exc



def get_client_ip(request):
    return request.client.host



@app.post("/api/v1/token", response_model=Token)
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


##################
## User Actions ##
##################

@app.get(
    "/api/v1/users/list",
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
    "/api/v1/users/register",
    response_model=ApiSuccessResponse,
    status_code=status.HTTP_200_OK,
    responses={422: {"model": ApiUnprocessableEntityResponse}},
    operation_id="addUser",
    description="Register New User to the System",
)
# TODO - Need to validate role being created must be one of the Enum role
async def register_user(user: UserCreate, role: UserRoles = UserRoles.USER, current_user: User = Depends(authenticate)):
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
    "/api/v1/users/remove",
    response_model=ApiSuccessResponse,
    status_code=status.HTTP_200_OK,
    responses={422: {"model": ApiUnprocessableEntityResponse}},
    operation_id="removeUser",
    description="Remove a user from the System",
)
async def remove_user(username: str, current_user: User = Depends(authenticate)):
    authorize(current_user, roles=[UserRoles.ADMIN])
    logger.info("Removing a user: {}".format(username))
    await db.users.remove(
        db.create_session(),
        username
    )
    return ApiSuccessResponse()



####################
## Fingerprint JS ##
####################

@app.post(
    "/api/v1/fingerprintjs/add",
    response_model=ApiSuccessResponse,
    status_code=status.HTTP_200_OK,
    responses={422: {"model": ApiUnprocessableEntityResponse}},
    operation_id="addFingerprintJSData",
    description="Add fingerprinting data collected from the browser.",
)
async def add_fingerprintjs_data(fingerprint_data: FingerprintJSData, request: Request, current_user: User = Depends(authenticate)):
    client_ip = get_client_ip(request)
    await db.fingerprintjs.add(db.create_session(), fingerprint_data, client_ip, current_user.username)
    return ApiSuccessResponse()


@app.post(
    "/api/v1/fingerprintjs/add/geo",
    response_model=ApiSuccessResponse,
    status_code=status.HTTP_200_OK,
    responses={422: {"model": ApiUnprocessableEntityResponse}},
    operation_id="addFingerprintJSGeoLocation",
    description="Add geo location collected from the browser.",
)
async def add_fingerprintjs_geo_location(location_data: FingerprintJSGeoLocation, request: Request, current_user: User = Depends(authenticate)):
    client_ip = get_client_ip(request)
    if location_data.geoLocation:
        await db.fingerprintjs.add_geo_location(db.create_session(), location_data, client_ip, current_user.username)
        return ApiSuccessResponse()
    else:
        # we do not store geo errors
        pass


##############################################
## Network Malicious IPs / Shadow Collector ##
##############################################

@app.get(
    "/api/v1/mal_ips/list",
    response_model=MaliciousIPListOnlyIPs,
    status_code=status.HTTP_200_OK,
    operation_id="listMaliciousIPListIPsOnly",
    description="List malicious Ip list (only IP Addresses) (Collected by Shadow Collectors)",
)
async def get_malicious_ip_list_ips_only(current_user: User = Depends(authenticate)):
    authorize(current_user, roles=[UserRoles.USER, UserRoles.ADMIN])
    logger.info("Listing IP Addresses only.")
    return await db.mal_ips.get_malicious_ip_list_only_ips(db.create_session())


@app.get(
    "/api/v1/mal_ips/details",
    response_model=MaliciousIPListAdmin,
    status_code=status.HTTP_200_OK,
    operation_id="listMaliciousIPsDetails",
    description="List network malicious Ips (collected by Shadow Collectors) (with all details) directly from database (only for admin)",
)
async def get_malicious_ip_details(page: int=0, page_size: int=10, current_user: User = Depends(authenticate)):
    authorize(current_user, roles=[UserRoles.ADMIN])
    logger.info("Listing IP information (only for admin user).")
    return await db.mal_ips.get_malicious_ip_list_for_admin(db.create_session(), page, page_size)


@app.post(
    "/api/v1/mal_ips/remove",
    response_model=ApiSuccessResponse,
    status_code=status.HTTP_200_OK,
    operation_id="removeMaliciousIPs",
    description="Remove network malicious Ips (collected by Shadow Collectors)",
)
async def remove_malicious_ips(ip_address_to_remove: MaliciousIPsRemove, current_user: User = Depends(authenticate)):
    authorize(current_user, roles=[UserRoles.ADMIN])
    logger.info("Removing Network Malicious IPs")
    await db.mal_ips.remove_malicious_ips(db.create_session(), ip_address_to_remove)
    return ApiSuccessResponse()


@app.post(
    "/api/v1/sc/add",
    response_model=ApiSuccessResponse,
    status_code=status.HTTP_200_OK,
    responses={422: {"model": ApiUnprocessableEntityResponse}},
    operation_id="addShadowCollectorFingerprinting",
    description="Add fingerprinting from Shadow Collectors (Network Malicious IPs).",
)
async def add_sc_fingerprints(device_list: SCDeviceList, current_user: User = Depends(authenticate)):
    authorize(current_user, roles=[UserRoles.USER, UserRoles.ADMIN])
    logger.info("Adding Malicious IP information from Shadow Collector.")
    await db.mal_ips.add_shadow_collector_ips(db.create_session(), current_user.username, device_list)
    return ApiSuccessResponse()



############################
## Firewall Malicious IPs ##
############################

async def add_firewall_malicious_ip_to_db(username: str, firewall_mal_ips, current_user: User = Depends(authenticate)):
    authorize(current_user, roles=[UserRoles.USER, UserRoles.ADMIN])
    logger.info("Adding a new malicious IP list.")
    await db.firewall_mal_ips.add_firewall_malicious_ips(db.create_session(), username, firewall_mal_ips)
    return ApiSuccessResponse()


# For backward compatibility for Firewall Malicious IP list from Splunk
@app.post(
    "/api/v1/ip",
    response_model=ApiSuccessResponse,
    status_code=status.HTTP_200_OK,
    responses={422: {"model": ApiUnprocessableEntityResponse}},
    operation_id="addFirewallMaliciousIpsFromSplunk_Backward_Compatibility",
    description="Add Malicious IP addresses from Firewall (through Splunk) (Backward Compatibility)",
)
async def add_firewall_malicious_ip_old(firewall_mal_ips: FirewallMaliciousIPCreateListOld, current_user: User = Depends(authenticate)):
    authorize(current_user, roles=[UserRoles.USER, UserRoles.ADMIN])
    return await add_firewall_malicious_ip_to_db(current_user.username, firewall_mal_ips)


@app.post(
    "/api/v1/firewall_mal_ips/add",
    response_model=ApiSuccessResponse,
    status_code=status.HTTP_200_OK,
    responses={422: {"model": ApiUnprocessableEntityResponse}},
    operation_id="addFirewallMaliciousIps",
    description="Add Malicious IP addresses from Firewall (through Splunk)",
)
async def add_firewall_malicious_ip(firewall_mal_ips: FirewallMaliciousIPCreateList, current_user: User = Depends(authenticate)):
    authorize(current_user, roles=[UserRoles.USER, UserRoles.ADMIN])
    return await add_firewall_malicious_ip_to_db(current_user.username, firewall_mal_ips)


# For backward compatibility for Malicious IP list from Splunk
@app.get(
    "/api/v1/ip",
    response_model=FirewallMaliciousIPGetAllOld,
    status_code=status.HTTP_200_OK,
    responses={422: {"model": ApiUnprocessableEntityResponse}},
    operation_id="listFirewallMaliciousIps_Backward_Compatibility",
    description="List firewall malicious IPs for Splunk (Backward Compatibility)",
)
async def list_firewall_malicious_ips_old(current_user: User = Depends(authenticate)):
    authorize(current_user, roles=[UserRoles.USER, UserRoles.ADMIN])
    logger.info("Return Malicious IP List. (Old)")
    return await db.firewall_mal_ips.get_firewall_malicious_ips_old(db.create_session())


@app.get(
    "/api/v1/firewall_mal_ips/list",
    response_model=FirewallMaliciousIPGetAll,
    status_code=status.HTTP_200_OK,
    responses={422: {"model": ApiUnprocessableEntityResponse}},
    operation_id="listFirewallMaliciousIps",
    description="List firewall malicious IPs for Splunk",
)
async def list_firewall_malicious_ips(current_user: User = Depends(authenticate)):
    authorize(current_user, roles=[UserRoles.USER, UserRoles.ADMIN])
    logger.info("Return Malicious IP List.")
    return await db.firewall_mal_ips.get_firewall_malicious_ips(db.create_session())


@app.post(
    "/api/v1/firewall_mal_ips/remove",
    response_model=ApiSuccessResponse,
    status_code=status.HTTP_200_OK,
    responses={422: {"model": ApiUnprocessableEntityResponse}},
    operation_id="removeFirewallMaliciousIps",
    description="Remove Malicious IP addresses from Firewall (through Splunk)",
)
async def remove_firewall_malicious_ips(ip_address_to_remove: FirewallMaliciousIPsRemove, current_user: User = Depends(authenticate)):
    authorize(current_user, roles=[UserRoles.ADMIN])
    await db.firewall_mal_ips.remove_firewall_malicious_ips(db.create_session(), ip_address_to_remove)
    return ApiSuccessResponse()




# TODO - Security checks
# 1. input check for XSS and other values
# 2. other security check for APIs
# 3. deleting ip (and cascaded information)
# 4. deleting ip info based on time
# 5. deleting source (and cascaded information)
# 6. deleting source info based on time
# 7. Test true concurrency of API and database operations with Postgres
# 8. Optimise database for better performance
# 9. DDoS attack
# 10. Bruteforce: 5 wrong password a client
# 11. put fingerprintjs separate key so can we can identity client that sends the request differently
