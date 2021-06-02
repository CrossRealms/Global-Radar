
import datetime
from schemas.fingerprintjs import FingerprintJSData, FingerprintJSGeoLocation



async def get_fingerprintjs(db, visitor_id):
    # TODO - Need to implement for postgres
    pass



async def add(db, fingerprint: FingerprintJSData, client_ip: str, username: str):
    # TODO - Need to implement for postgres
    pass



async def add_geo_location(db, geo_location: FingerprintJSGeoLocation, client_ip: str, username: str):
    # TODO - Need to implement for postgres
    pass
