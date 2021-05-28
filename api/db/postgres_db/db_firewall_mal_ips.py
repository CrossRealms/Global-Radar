
import datetime
from sqlalchemy import Column, String, DateTime, Enum, Integer, func
from sqlalchemy.orm import relationship
from .db_base import Base

from schemas.firewall_malicious_ips import FirewallIpCategory, FirewallMaliciousIPCreateList, FirewallMaliciousIPGet, FirewallMaliciousIPGetAll, FirewallMaliciousIPGetAllOld, FirewallMaliciousIPGetOld, FirewallMaliciousIPsRemove

class FirewallMaliciousIpModel(Base):
    __tablename__ = 'firewall_maliciousip'

    ip = Column(String(255), unique=True, primary_key=True)
    ip_location = Column(String(255))
    category = Column(Enum(FirewallIpCategory))
    last_seen = Column(DateTime, default=datetime.datetime.now())
    no_of_hits = Column(Integer)

    # Relationships
    affected_devices = relationship("FirewallAffectedDeviceModel", backref="firewall_malicious_ip")


class FirewallAffectedDeviceModel(Base):
    __tablename__ = 'firewall_affected_device'

    ip = Column(String(255), primary_key=True)
    device = Column(String(255), primary_key=True)
    customer_id = Column(String(255), primary_key=True)


async def add_firewall_malicious_ips(db, username: str, mal_ip_list: FirewallMaliciousIPCreateList):

    for ip_object in mal_ip_list.data:

        ip_info = db.query(FirewallMaliciousIpModel).get(ip_object.ip)

        last_seen = datetime.datetime.now()
        if ip_object.last_seen:
            ls_from_input = datetime.datetime.utcfromtimestamp(ip_object.last_seen)
            if ls_from_input < last_seen:
                last_seen = ls_from_input
        
        categories = set(ip_info.category.split(','))
        categories.add(ip_object.category)
        categories = ','.join(categories)

        if ip_info:
            # If document already exist in the database
            ip_info.no_of_hits = ip_info.no_of_hits + 1
            ip_info.ip_location = ip_object.ip_location
            ip_info.category = categories
            ip_info.last_seen = last_seen
            db.commit()
            db.refresh(ip_info)
        else:
            ip_db = FirewallMaliciousIpModel(
                ip=ip_object.ip,
                no_of_hits=1,
                last_seen=last_seen,
                ip_location=ip_object.ip_location,
                category = ip_object.category,
            )
            db.add(ip_db)
            db.commit()
            db.refresh(ip_db)
            
        for device_id in ip_object.device.split(','):
            device_info = db.query(FirewallAffectedDeviceModel).get(
                {
                    "ip": ip_object.ip,
                    "device": device_id,
                    "customer_id": username,
                }
            )
            if not device_info:
                device_db = FirewallAffectedDeviceModel(
                    ip=ip_object.ip,
                    device=device_id,
                    customer_id=ip_object.customer_id
                )
                db.add(device_db)
                db.commit()


async def get_firewall_malicious_ips_old(db):
    affected_devices_list = db.query(FirewallAffectedDeviceModel.ip,func.count(FirewallAffectedDeviceModel.device)).group_by(FirewallAffectedDeviceModel.ip).all()

    # convert affected devices to dict for better performance
    affected_devices = {}
    for d in affected_devices_list:
        #                 ip = no_of_devices
        affected_devices[d[0]] = d[1]

    category_to_description = {
        FirewallIpCategory.OUTBOUND: "Outgoing traffic from multiple firewalls to this blocked IP",
        FirewallIpCategory.INBOUND: "Incoming traffic into multiple firewalls from this blocked IP",
        FirewallIpCategory.DDOS: "Involved in DDoS Attack",
    }

    malicious_ips = []
    last_7_days = datetime.datetime.now() - datetime.timedelta(days=7)

    firewall_mal_ips = db.query(FirewallMaliciousIpModel).all()

    for mal_ip in firewall_mal_ips:
        if mal_ip.last_seen >= last_7_days:
            for category in mal_ip.category.split(','):
                if category == FirewallIpCategory.DDOS:
                    malicious_ips.append(
                        FirewallMaliciousIPGetOld(
                            ip=mal_ip.ip,
                            description=category_to_description[category],
                            ip_location=mal_ip.ip_location,
                            last_seen=mal_ip.last_seen.timestamp(),
                        )
                    )
                else:
                    if affected_devices.get(mal_ip.ip, 0) >= 3:
                        malicious_ips.append(
                            FirewallMaliciousIPGetOld(
                                ip=mal_ip.ip,
                                description=category_to_description[mal_ip.category],
                                ip_location=mal_ip.ip_location,
                                last_seen=mal_ip.last_seen.timestamp(),
                            )
                        )
    return FirewallMaliciousIPGetAllOld(
        data=malicious_ips
    )


async def get_firewall_malicious_ips(db):
    affected_devices_list = db.query(FirewallAffectedDeviceModel.ip,func.count(FirewallAffectedDeviceModel.device)).group_by(FirewallAffectedDeviceModel.ip).all()

    # convert affected devices to dict for better performance
    affected_devices = {}
    for d in affected_devices_list:
        #                 ip = no_of_devices
        affected_devices[d[0]] = d[1]

    malicious_ips = []
    last_7_days = datetime.datetime.now() - datetime.timedelta(days=7)

    firewall_mal_ips = db.query(FirewallMaliciousIpModel).all()

    for mal_ip in firewall_mal_ips:
        if mal_ip.last_seen >= last_7_days:
            for category in mal_ip.category.split(','):
                if category == FirewallIpCategory.DDOS:
                    malicious_ips.append(
                        FirewallMaliciousIPGet(
                            ip=mal_ip.ip,
                            category=category,
                            ip_location=mal_ip.ip_location,
                            last_seen=mal_ip.last_seen.timestamp(),
                            no_of_affected_devices=affected_devices.get(mal_ip.ip, 0),
                            no_of_hits=mal_ip.no_of_hits,
                        )
                    )
                else:
                    if affected_devices.get(mal_ip.ip, 0) >= 3:
                        malicious_ips.append(
                            FirewallMaliciousIPGetOld(
                                ip=mal_ip.ip,
                                category=category,
                                ip_location=mal_ip.ip_location,
                                last_seen=mal_ip.last_seen.timestamp(),
                                no_of_affected_devices=affected_devices.get(mal_ip.ip, 0),
                                no_of_hits=mal_ip.no_of_hits,
                            )
                        )
    return FirewallMaliciousIPGetAll(
        data=malicious_ips
    )


async def remove_firewall_malicious_ips(db, ip_addresses: FirewallMaliciousIPsRemove):
    # TODO - need to test
    return db.query(FirewallMaliciousIpModel)\
            .filter(FirewallMaliciousIpModel.ip.in_(ip_addresses))\
            .delete()
