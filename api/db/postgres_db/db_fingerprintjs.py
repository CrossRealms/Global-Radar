
import datetime
from schemas.fingerprintjs import FingerprintJSData, FingerprintJSGeoLocation



async def get_fingerprintjs(db, visitor_id):
    # TODO - Need to implement for postgres
    fingerprint =  await db[DBFingerprintJS.COLLECTION].find_one({DBFingerprintJS.FIELD_VISITOR_ID: visitor_id})



async def add(db, fingerprint: FingerprintJSData, client_ip: str, username: str):
    # TODO - Need to implement for postgres
    document_from_database = await db[DBFingerprintJS.COLLECTION].find_one({DBFingerprintJS.FIELD_VISITOR_ID : fingerprint.visitorId})
    if document_from_database:
        # If document already exist in the database
        await db[DBFingerprintJS.COLLECTION].update_one(
            { DBFingerprintJS.FIELD_VISITOR_ID : fingerprint.visitorId },
            { "$addToSet": { DBFingerprintJS.FIELD_IP_ADDRESS : client_ip } }
        )
    else:
        await db[DBFingerprintJS.COLLECTION].insert_one({
            DBFingerprintJS.FIELD_VISITOR_ID: fingerprint.visitorId,
            DBFingerprintJS.FIELD_COMPONENTS: fingerprint.components,
            DBFingerprintJS.FIELD_IP_ADDRESSES: [client_ip]
        })
    return fingerprint.visitorId



async def add_geo_location(db, geo_location: FingerprintJSGeoLocation, client_ip: str, username: str):
    # TODO - Need to implement for postgres
    geo_document_from_database = await db[DBFingerprintJS.COLLECTION].find_one(
        {
            DBFingerprintJS.FIELD_VISITOR_ID : geo_location.visitorId,
            DBFingerprintJS.FIELD_GEO_LOCATION: {
                "$elemMatch": {
                    DBFingerprintJS.FIELD_GEO_LAT: geo_location.geoLocation.lat,
                    DBFingerprintJS.FIELD_GEO_LON: geo_location.geoLocation.lon,
                }
            }
        }
    )

    if geo_document_from_database:
        await db[DBFingerprintJS.COLLECTION].update_one(
            {
                DBFingerprintJS.FIELD_VISITOR_ID : geo_location.visitorId,
                DBFingerprintJS.FIELD_GEO_LOCATION: {
                    "$elemMatch": {
                        DBFingerprintJS.FIELD_GEO_LAT: geo_location.geoLocation.lat,
                        DBFingerprintJS.FIELD_GEO_LON: geo_location.geoLocation.lon,
                    }
                }
            },
            {
                "$set" : {
                    "{}.$.{}".format(DBFingerprintJS.FIELD_GEO_LOCATION, DBFingerprintJS.FIELD_GEO_ACCURACY): geo_location.geoLocation.accuracy,
                    "{}.$.{}".format(DBFingerprintJS.FIELD_GEO_LOCATION, DBFingerprintJS.FIELD_GEO_TIMESTAMP): datetime.datetime.now(),
                },
                "$addToSet" : {
                    "{}.$.{}".format(DBFingerprintJS.FIELD_GEO_LOCATION, DBFingerprintJS.FIELD_GEO_IPS): client_ip
                }
            }
        )
    else:
        await db[DBFingerprintJS.COLLECTION].update_one(
            {DBFingerprintJS.FIELD_VISITOR_ID : geo_location.visitorId},
            {
                "$push": {
                    DBFingerprintJS.FIELD_GEO_LOCATION: {
                        DBFingerprintJS.FIELD_GEO_LAT: geo_location.geoLocation.lat,
                        DBFingerprintJS.FIELD_GEO_LON: geo_location.geoLocation.lon,
                        DBFingerprintJS.FIELD_GEO_ACCURACY: geo_location.geoLocation.accuracy,
                        DBFingerprintJS.FIELD_GEO_TIMESTAMP: datetime.datetime.now(),
                        DBFingerprintJS.FIELD_GEO_IPS: [client_ip]
                    }
                }
            }
        )
