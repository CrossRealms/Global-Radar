
import datetime
from sqlalchemy import Column, String, DateTime, Enum, Integer, func
from .db_base import Base

from schemas.firewall_malicious_ips import FirewallIpCategory, FirewallMaliciousIPCreateList, FirewallMaliciousIPGet, FirewallMaliciousIPGetAll

class MaliciousIp(Base):
    __tablename__ = 'firewall_maliciousip'

    id = Column(Integer, autoincrement=True)
    ip = Column(String(255), unique=True, primary_key=True)
    ip_location = Column(String(255))
    category = Column(Enum(FirewallIpCategory))
    last_seen = Column(DateTime, default=datetime.datetime.now())
    no_of_ports_used = Column(Integer)
    no_of_victims = Column(Integer)
    hits = Column(Integer)


class AffectedDevice(Base):
    __tablename__ = 'firewall_affected_device'

    ip = Column(String(255), primary_key=True)
    device = Column(String(255), primary_key=True)
    device_name = Column(String(255))
    customer_id = Column(String(255), primary_key=True)


async def add_firewall_malicious_ips(db, data_source: FirewallMaliciousIPCreateList):
    ip_address_list = []
    success = True
    error_list = []
    for ip_object in data_source.data:
        ip_info = db.query(MaliciousIp).get(ip_object.ip)
        if ip_info:
            ip_info.hits = ip_info.hits + 1
            ip_info.ip_location = ip_object.ip_location
            ip_info.category = ip_object.category
            ip_info.last_seen = datetime.datetime.now()
            ip_info.no_of_ports_used = ip_object.no_of_ports_used + ip_info.no_of_ports_used
            ip_info.no_of_victims = ip_info.no_of_victims + ip_object.no_of_victims
            db.commit()
            db.refresh(ip_info)
            ip_address_list.append(ip_info.ip)
        else:
            ip_db = MaliciousIp(
                ip=ip_object.ip,
                hits=1,
                last_seen=datetime.datetime.now(),
                ip_location=ip_object.ip_location,
                category = ip_object.category,
                no_of_ports_used = ip_object.no_of_ports_used,
                no_of_victims = ip_object.no_of_victims,
            )
            db.add(ip_db)
            db.commit()
            db.refresh(ip_db)
            ip_address_list.append(ip_db.ip)
            
        for device_id in ip_object.device.split(','):
            device_info = db.query(AffectedDevice).get(
                {
                    "ip": ip_object.ip,
                    "device": device_id,
                    "customer_id": ip_object.customer_id,
                }
            )
            if not device_info:
                device_db = AffectedDevice(
                    ip=ip_object.ip,
                    device=device_id,
                    device_name=ip_object.device_name,
                    customer_id=ip_object.customer_id
                )
                db.add(device_db)
                db.commit()


async def get_firewall_malicious_ips(db):
    ip_filtered = db.query(AffectedDevice.ip,func.count(AffectedDevice.device)).group_by(AffectedDevice.ip).all()
    category_to_description = {
        FirewallIpCategory.OUTBOUND: "Outgoing traffic from multiple firewalls to this blocked IP",
        FirewallIpCategory.INBOUND: "Incoming traffic into multiple firewalls from this blocked IP",
        FirewallIpCategory.DDOS: "Involved in DDoS Attack",
    }
    malicious_ips = []
    last_7_days = datetime.datetime.now() - datetime.timedelta(days=7)
    found_ip = {}
    for ip_obj in ip_filtered:
        if ip_obj[1] >= 3:
            mal_ip = db.query(MaliciousIp).get(ip_obj[0])
            if mal_ip.last_seen >= last_7_days:
                malicious_ips.append(
                    FirewallMaliciousIPGet(
                        ip=mal_ip.ip,
                        description=category_to_description[mal_ip.category],
                        ip_location=mal_ip.ip_location,
                        last_seen=mal_ip.last_seen.timestamp(),
                    )
                )
                found_ip[mal_ip.ip] = True
    ddos_ips = db.query(MaliciousIp).filter(MaliciousIp.category==FirewallIpCategory.DDOS).all()
    for ip_obj in ddos_ips:
        if ip_obj.ip not in found_ip:
            malicious_ips.append(
                FirewallMaliciousIPGet(
                    ip=ip_obj.ip,
                    description=category_to_description[ip_obj.category],
                    ip_location=ip_obj.ip_location,
                    last_seen=ip_obj.last_seen.timestamp(),
                    no_of_ports_used=ip_obj.no_of_ports_used,
                    no_of_victims=ip_obj.no_of_victims,
                )
            )
    return FirewallMaliciousIPGetAll(
        data=malicious_ips
    )
