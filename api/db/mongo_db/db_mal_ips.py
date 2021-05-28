
import datetime

from schemas.malicious_ips import MaliciousIPAdmin, MaliciousIPInformationAdmin, MaliciousIPListAdmin, MaliciousIPListOnlyIPs, MaliciousIPSourceCategory, MaliciousIPsRemove
from schemas.shadow_collector import SCUniqueDeviceList

from util.config import HoneyPotsConfig



class DBMaliciousIPLocation:
    COLLECTION = 'mal_ips_location'

    FIELD_ID = '_id'
    FIELD_IP = 'ip'
    FIELD_RECEIVED_FROM = 'received_from'   # list of usernames

    FIELD_LAST_SEEN = 'last_seen'
    FIELD_LAT = 'lat'
    FIELD_LON = 'lon'
    FIELD_COUNTRY = 'country'
    FIELD_CITY = 'city'
    FIELD_REGION = 'region'


class DBMaliciousIPSources:
    COLLECTION = 'mal_ips_sources'

    FIELD_ID = '_id'
    FIELD_RECEIVED_FROM = 'received_from'
    FIELD_NAME = 'source_name'


class DBMaliciousIPInformation:
    COLLECTION = 'mal_ips_information'

    FIELD_ID = '_id'
    FIELD_BAD_ACTOR = 'ip'
    FIELD_SOURCE_ID = 'source_id'

    FIELD_FIELD = 'field'
    FIELD_VALUE = 'value'
    FIELD_LAST_DETECTED = 'last_detected'
    FIELD_COUNT = 'count'


class DBMaliciousIPs:
    COLLECTION = 'malicious_ips'

    FIELD_IP = '_id'
    FIELD_COUNT = 'count'

    @classmethod
    def get_information(cls, db, ip, source_id):
        return db[DBMaliciousIPInformation.COLLECTION].find({DBMaliciousIPInformation.FIELD_BAD_ACTOR: ip, DBMaliciousIPInformation.FIELD_SOURCE_ID: source_id})

    @classmethod
    def get_all_information(cls, db, ip):
        return db[DBMaliciousIPInformation.COLLECTION].find({DBMaliciousIPInformation.FIELD_BAD_ACTOR: ip})
    
    @classmethod
    def get_locations(cls, db, ip):
        return db[DBMaliciousIPLocation.COLLECTION].find({DBMaliciousIPLocation.FIELD_IP: ip})



async def add_shadow_collector_ips(db, account_username, sc_list):
    target_source = '{}'.format(MaliciousIPSourceCategory.DMZ)
    if account_username in HoneyPotsConfig().honeypot_accounts:
        target_source = '{}'.format(MaliciousIPSourceCategory.HONEYPOT)
    
    device_list = SCUniqueDeviceList(sc_list)

    for _, device in device_list.devices.items():
        # Making sure device is present in the database
        db_device = await db[DBMaliciousIPs.COLLECTION].find_one({DBMaliciousIPs.FIELD_IP : device.ip})

        if not db_device:
            await db[DBMaliciousIPs.COLLECTION].insert_one({
                DBMaliciousIPs.FIELD_IP : device.ip,
                DBMaliciousIPs.FIELD_COUNT: 1,
            })
            db_device = await db[DBMaliciousIPs.COLLECTION].find_one({DBMaliciousIPs.FIELD_IP : device.ip})
        else:
            await db[DBMaliciousIPs.COLLECTION].update_one(
                { DBMaliciousIPs.FIELD_IP : device.ip },
                {
                    "$set": {
                        DBMaliciousIPs.FIELD_COUNT: db_device[DBMaliciousIPs.FIELD_COUNT] + 1,
                    }
                }
            )
        
        # Making sure source is present in the database
        db_source = await db[DBMaliciousIPSources.COLLECTION].find_one({DBMaliciousIPSources.FIELD_RECEIVED_FROM: account_username, DBMaliciousIPSources.FIELD_NAME: target_source})
        if not db_source:
            await db[DBMaliciousIPSources.COLLECTION].insert_one({
                DBMaliciousIPSources.FIELD_RECEIVED_FROM: account_username,
                DBMaliciousIPSources.FIELD_NAME: target_source,
            })
            db_source = await db[DBMaliciousIPSources.COLLECTION].find_one({DBMaliciousIPSources.FIELD_RECEIVED_FROM: account_username, DBMaliciousIPSources.FIELD_NAME: target_source})
        
        # Adding field-values(information about the device)
        information = await DBMaliciousIPs.get_information(db, device.ip, db_source[DBMaliciousIPSources.FIELD_ID]).to_list(None)
        for field in device.fields:
            for value in device.fields[field]:
                # create information if not present, otherwise update last_detected
                for i in information:
                    if i[DBMaliciousIPInformation.FIELD_FIELD] == field and i[DBMaliciousIPInformation.FIELD_VALUE] == value:
                        await db[DBMaliciousIPInformation.COLLECTION].update_one(
                            { DBMaliciousIPInformation.FIELD_ID : i[DBMaliciousIPInformation.FIELD_ID] },
                            {
                                "$set": {
                                    DBMaliciousIPInformation.FIELD_LAST_DETECTED: datetime.datetime.now(),
                                    DBMaliciousIPInformation.FIELD_COUNT: i[DBMaliciousIPInformation.FIELD_COUNT] + 1,
                                }
                            }
                        )
                        break
                else:
                    info = await db[DBMaliciousIPInformation.COLLECTION].insert_one({
                        DBMaliciousIPInformation.FIELD_BAD_ACTOR : db_device[DBMaliciousIPs.FIELD_IP],
                        DBMaliciousIPInformation.FIELD_SOURCE_ID : db_source[DBMaliciousIPSources.FIELD_ID],
                        DBMaliciousIPInformation.FIELD_FIELD : field,
                        DBMaliciousIPInformation.FIELD_VALUE : value,
                        DBMaliciousIPInformation.FIELD_LAST_DETECTED : datetime.datetime.now(),
                        DBMaliciousIPInformation.FIELD_COUNT : 1,
                    })


async def get_malicious_ip_list_for_admin(db, page=0, page_size=10):
    db_malicious_ips = db[DBMaliciousIPs.COLLECTION].find().skip(page*page_size).limit(page_size)
    all_ips = MaliciousIPListAdmin(ips=list(), count=0)
    count = 0

    async for db_ip in db_malicious_ips:
        ip = MaliciousIPAdmin(
            ip = db_ip[DBMaliciousIPs.FIELD_IP],
            count = db_ip[DBMaliciousIPs.FIELD_COUNT],
            locations = await DBMaliciousIPs.get_locations(db, db_ip[DBMaliciousIPs.FIELD_IP]).to_list(None),
            information = []
        )

        async for db_info in DBMaliciousIPs.get_all_information(db, db_ip[DBMaliciousIPs.FIELD_IP]):
            info = MaliciousIPInformationAdmin(
                source_id = str(db_info[DBMaliciousIPInformation.FIELD_SOURCE_ID]),
                field = db_info[DBMaliciousIPInformation.FIELD_FIELD],
                value = db_info[DBMaliciousIPInformation.FIELD_VALUE],
                last_detected = db_info[DBMaliciousIPInformation.FIELD_LAST_DETECTED],
                count = db_info[DBMaliciousIPInformation.FIELD_COUNT],
            )
            ip.information.append(info)

        all_ips.ips.append(ip)
        count += 1
    
    all_ips.count = count

    return all_ips


async def get_malicious_ip_list_only_ips(db):
    db_malicious_ips = db[DBMaliciousIPs.COLLECTION].find()
    all_ips = MaliciousIPListOnlyIPs(ips=list(), total=0)
    total = 0

    async for db_ip in db_malicious_ips:
        all_ips.ips.append(db_ip[DBMaliciousIPs.FIELD_IP])
        total += 1

    all_ips.total = total
    return all_ips


async def remove_malicious_ips(db, ip_addresses: MaliciousIPsRemove):
    await db[DBMaliciousIPInformation.COLLECTION].delete_many({ 
        DBMaliciousIPInformation.FIELD_BAD_ACTOR : { "$in": ip_addresses.ips_to_remove } 
    })
    await db[DBMaliciousIPs.COLLECTION].delete_many({ 
        DBMaliciousIPs.FIELD_IP : { "$in": ip_addresses.ips_to_remove } 
    })


async def get_malicious_ip_sources(db):
    '''
    TODO
    for db_source in db_ip.sources:
            source = MaliciousIPSourcesAdmin(
                id = db_source.id,
                received_from = db_source.received_from,
                source = db_source.source,
                count = db_source.count,
                information = []
            )
    '''
    pass


async def get_malicious_ip_list(db):
    pass

async def get_account_specific_malicious_ip_list(db):
    pass    

async def get_specific(db, ip):
    # full_details =  await self.collection.find_one({DBMaliciousIPs.FIELD_IP: ip})
    # TODO - modify the response
    pass
