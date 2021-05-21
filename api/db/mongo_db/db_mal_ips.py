
from config import honeypots_config


class DBMaliciousIPs:
    '''
    Format
    ------
    {
        ip: 63.63.63.63,
        iplocation: {
            lat: -91,
            lon: -91,
            country: China,
            other_info ...
        }
        last_detected_on_shadow_collector: _time,
        last_detected_on_firewall: _time,
        firewall_detection: {
            ddos_attack: [
                "CR": {
                    devices_list: [
                        "device1": {
                            last_detected: _time,
                            count: 2
                        },
                        "device2": {
                            last_detected: _time,
                            count: 5
                        },
                    ]
                }
            ],
            inbound_mal_traffic: [
                "CR": {
                    devices_list: [
                        "device1": {
                            last_detected: _time,
                            count: 2
                        },
                        "device2": {
                            last_detected: _time,
                            count: 5
                        },
                    ]
                }
            ],
            outbound_mal_traffic: [
                "CR": {
                    devices_list: [
                        "device1": {
                            last_detected: _time,
                            count: 2
                        },
                        "device2": {
                            last_detected: _time,
                            count: 5
                        },
                    ]
                }
            ],
        },
        honeypot_detection: [
            "CR": {
                fields: {
                    "raw_sig": [
                        {
                            value: "4:236+19:0:0:1024,0:::0",
                            last_detected: _time
                        },
                        {
                            value: "4+19:0:0:1024,0:::0",
                            last_detected: _time
                        },
                    ],
                    "field2": []...
                }
            }
        ],
        dmz_detection: {
            "CR": {
                fields: {
                    "raw_sig": [
                        {
                            value: "4:236+19:0:0:1024,0:::0",
                            last_detected: _time
                        },
                        {
                            value: "4+19:0:0:1024,0:::0",
                            last_detected: _time
                        },
                    ],
                    "field2": []...
                }
            }
        } 
    }
    '''
    COLLECTION = 'malicious_ips'

    FIELD_IP = '_id'
    FIELD_HONEYPOT_DETECTION = 'honeypot_detection'
    FIELD_DMZ_DETECTION = 'dmz_detection'



async def add_shadow_collector_ips(db, account_name, sc_list):
    field = None
    if account_name in honeypots_config.honeypot_accounts:
        field = DBMaliciousIPs.FIELD_HONEYPOT_DETECTION
    else:
        field = DBMaliciousIPs.FIELD_DMZ_DETECTION

    for device in sc_list.device_list:
        # db[DBMaliciousIPs.COLLECTION].findone
        db[DBMaliciousIPs.COLLECTION].update(
            query = { DBMaliciousIPs.FIELD_IP: device.ip },
            update = {
                "$set": {
                }
            },
        )


async def get_specific(db, ip):
    full_details =  await db[DBMaliciousIPs.COLLECTION].find_one({DBMaliciousIPs.FIELD_IP: ip})
    # TODO - modify the response
    # user_obj = None
    # if user:
    #     user_obj = User(user[DBUsers.FIELD_USERNAME], user[DBUsers.FIELD_EMAIL], user[DBUsers.FIELD_PASSWORD], user[DBUsers.FIELD_ROLE])
    # return user_obj
    
'''
async def get_user_list(db):        
    users_from_db = db[DBMaliciousIPs.COLLECTION].find({})
    users = UserList(user_list=list())
    async for u in users_from_db:
        users.user_list.append(GetUser(username=u.get(DBUsers.FIELD_USERNAME), email=u[DBUsers.FIELD_EMAIL], role=u[DBUsers.FIELD_ROLE]))
    return users

async def add(db, user):
    return await db[DBMaliciousIPs.COLLECTION].insert_one({
        DBUsers.FIELD_USERNAME: user.username,
        DBUsers.FIELD_EMAIL: user.email,
        DBUsers.FIELD_PASSWORD: user.hashed_password,
        DBUsers.FIELD_ROLE: user.role
    })
'''



# TODO - Write function to store the data to mongodb
# TODO - write list of honeypots in the config file list of account usernames

