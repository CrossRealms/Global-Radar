
import datetime
from schemas.firewall_malicious_ips import FirewallIpCategory, FirewallMaliciousIPGet, FirewallMaliciousIPGetAll

class DBFirewallMaliciousIPs:
    COLLECTION = 'firewall_malicious_ips'

    FIELD_IP = '_id'
    FIELD_IP_LOCATION = 'location'
    FIELD_CATEGORIES = 'categories'
    FIELD_LAST_SEEN = 'last_seen'
    FIELD_HITS = 'no_of_hits'
    FIELD_AFFECTED_DEVICES = 'affected_devices'

    FIELD_DEVICE_USERNAME = 'customer_id'
    FIELD_DEVICE_ID = 'device_id'

    '''
    {
        _id: 10.10.10.10,
        location: ,
        categories: [],
        last_seen: ,
        no_of_hits: ,
        affected_devices: [
            {
                customer_id: ,
                device_id: ,
                device_name: 
            }
        ]
    }
    '''


async def add_firewall_malicious_ips(db, username: str, mal_ip_list):   # FirewallMaliciousIPCreateList
    for ip_object in mal_ip_list.data:

        document_from_database = await db[DBFirewallMaliciousIPs.COLLECTION].find_one({DBFirewallMaliciousIPs.FIELD_IP : ip_object.ip})
        if document_from_database:
            # If document already exist in the database
            await db[DBFirewallMaliciousIPs.COLLECTION].update_one(
                { DBFirewallMaliciousIPs.FIELD_IP : ip_object.ip },
                {
                    "$set": {
                        DBFirewallMaliciousIPs.FIELD_IP_LOCATION: ip_object.ip_location,
                        DBFirewallMaliciousIPs.FIELD_LAST_SEEN: datetime.datetime.now(),
                        DBFirewallMaliciousIPs.FIELD_HITS: document_from_database[DBFirewallMaliciousIPs.FIELD_HITS] + 1
                    },
                    "$addToSet": {
                        DBFirewallMaliciousIPs.FIELD_CATEGORIES: ip_object.category
                    }
                }
            )
        else:
            await db[DBFirewallMaliciousIPs.COLLECTION].insert_one({
                DBFirewallMaliciousIPs.FIELD_IP : ip_object.ip,
                DBFirewallMaliciousIPs.FIELD_IP_LOCATION: ip_object.ip_location,
                DBFirewallMaliciousIPs.FIELD_CATEGORIES: [ip_object.category],
                DBFirewallMaliciousIPs.FIELD_LAST_SEEN: datetime.datetime.now(),
                DBFirewallMaliciousIPs.FIELD_HITS: 1,
            })

        # Append affected device list
        for device_id in ip_object.device.split(','):
            await db[DBFirewallMaliciousIPs.COLLECTION].update_one(
                { DBFirewallMaliciousIPs.FIELD_IP : ip_object.ip },
                {
                    "$addToSet": {
                        DBFirewallMaliciousIPs.FIELD_AFFECTED_DEVICES : {
                            DBFirewallMaliciousIPs.FIELD_DEVICE_USERNAME: username,
                            DBFirewallMaliciousIPs.FIELD_DEVICE_ID: device_id,
                        }
                    }
                }
            )
        # TODO - Need to use current_user object instead what user passes


async def get_firewall_malicious_ips(db):
    firewall_mal_ips = db[DBFirewallMaliciousIPs.COLLECTION].aggregate(
        [
            {
                "$project": {
                    DBFirewallMaliciousIPs.FIELD_IP: 1,
                    DBFirewallMaliciousIPs.FIELD_IP_LOCATION: 1,
                    DBFirewallMaliciousIPs.FIELD_CATEGORIES: 1,
                    DBFirewallMaliciousIPs.FIELD_LAST_SEEN: 1,
                    DBFirewallMaliciousIPs.FIELD_HITS: 1,
                    "number_of_affected_devices": {
                        "$size": "${}".format(DBFirewallMaliciousIPs.FIELD_AFFECTED_DEVICES)
                    },
                }
            }
        ]
    )

    category_to_description = {
        FirewallIpCategory.OUTBOUND: "Outgoing traffic from multiple firewalls to this blocked IP",
        FirewallIpCategory.INBOUND: "Incoming traffic into multiple firewalls from this blocked IP",
        FirewallIpCategory.DDOS: "Involved in DDoS Attack",
    }

    malicious_ips = []
    last_7_days = datetime.datetime.now() - datetime.timedelta(days=7)

    async for mal_ip in firewall_mal_ips:
        if mal_ip[DBFirewallMaliciousIPs.FIELD_LAST_SEEN] >= last_7_days:
            for category in mal_ip[DBFirewallMaliciousIPs.FIELD_CATEGORIES]:
                if category == FirewallIpCategory.DDOS:
                    malicious_ips.append(
                        FirewallMaliciousIPGet(
                            ip=mal_ip[DBFirewallMaliciousIPs.FIELD_IP],
                            description=category_to_description[category],
                            ip_location=mal_ip[DBFirewallMaliciousIPs.FIELD_IP_LOCATION],
                            last_seen=mal_ip[DBFirewallMaliciousIPs.FIELD_LAST_SEEN].timestamp(),
                            no_of_affected_devices=mal_ip["number_of_affected_devices"],
                            no_of_hits=mal_ip[DBFirewallMaliciousIPs.FIELD_HITS]
                        )
                    )
                else:
                    if mal_ip["number_of_affected_devices"] >= 3:
                        malicious_ips.append(
                            FirewallMaliciousIPGet(
                                ip=mal_ip[DBFirewallMaliciousIPs.FIELD_IP],
                                description=category_to_description[category],
                                ip_location=mal_ip[DBFirewallMaliciousIPs.FIELD_IP_LOCATION],
                                last_seen=mal_ip[DBFirewallMaliciousIPs.FIELD_LAST_SEEN].timestamp(),
                                no_of_affected_devices=mal_ip["number_of_affected_devices"],
                                no_of_hits=mal_ip[DBFirewallMaliciousIPs.FIELD_HITS]
                            )
                        )
    return FirewallMaliciousIPGetAll(
        data=malicious_ips
    )
