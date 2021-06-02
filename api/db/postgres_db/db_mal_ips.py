
from sqlalchemy import ForeignKey, UniqueConstraint, PrimaryKeyConstraint, Column, String, Float, DateTime, Enum, Integer
from sqlalchemy.orm import relationship
import datetime

from schemas.malicious_ips import MaliciousIPAdmin, MaliciousIPInformationAdmin, MaliciousIPListAdmin, MaliciousIPListOnlyIPs, MaliciousIPSourceCategory, MaliciousIPsRemove
from schemas.shadow_collector import SCUniqueDeviceList

from util.config import HoneyPotsConfig
from .db_base import Base


class IPLocationModel(Base):
    __tablename__="ip_location"

    ip = Column(String(length=50), ForeignKey('malicious_ips.ip', ondelete="cascade"))
    received_from = Column(String(length=255), ForeignKey('users.username'))

    last_seen = Column(DateTime, default=datetime.datetime.now())
    lat = Column(Float)
    lon = Column(Float)
    country = Column(String(length=50))
    city = Column(String(length=50))
    region = Column(String(length=50))

    # Constraints
    __table_args__ = (
        PrimaryKeyConstraint('ip', 'received_from', name='pk_ip_account'),
        )


class MaliciousIPInformationModel(Base):
    __tablename__="malicious_ip_information"

    bad_actor = Column(String(length=50), ForeignKey('malicious_ips.ip', ondelete="cascade"))
    source_id = Column(Integer(), ForeignKey('malicious_ip_sources.id', ondelete="cascade"))

    # Add more fields
    field = Column(String(length=50))
    # for firewall field = "device"
    # for honeypots and dmz field -> field name
    
    value = Column(String(length=5000))
    # for firewall value = device name
    # for honeypots and dmz field -> field name

    last_detected = Column(DateTime, default=datetime.datetime.now())
    # when the value is detected last time

    count = Column(Integer, default=1)
    # count not being used as of now, maybe we can use in the future

    # Constraints
    __table_args__ = (
        PrimaryKeyConstraint('bad_actor', 'source_id', 'field', 'value', name='pk_mal_ip_information'),
        )
    
    def __repr__(self) -> str:
        return 'bad_actor: {}, source_id: {}, field: {}, value: {}, last_detected: {}, count: {}'.format(self.bad_actor, self.source_id, self.field, self.value, self.last_detected, self.count)
    
    def __str__(self) -> str:
        return self.__repr__()



class MaliciousIPModel(Base):
    __tablename__="malicious_ips"

    ip = Column(String(length=50))
    count = Column(Integer, default=1)
    
    # Relationships
    locations = relationship("IPLocationModel", backref="malicious_ip", cascade="all, delete", passive_deletes=True)

    def get_information(self, db, source_id):
        return db.query(MaliciousIPInformationModel).filter(MaliciousIPInformationModel.bad_actor==self.ip and MaliciousIPInformationModel.source_id == source_id)

    def get_all_information(self, db):
        return db.query(MaliciousIPInformationModel).filter(MaliciousIPInformationModel.bad_actor==self.ip)

    # Constraints
    __table_args__ = (
        PrimaryKeyConstraint('ip'),
        )
    
    def __repr__(self) -> str:
        return 'ip: {}'.format(self.ip)
    
    def __str__(self) -> str:
        return self.__repr__()


class MaliciousIPSourcesModel(Base):
    __tablename__="malicious_ip_sources"

    id = Column(Integer, primary_key=True, autoincrement=True)

    received_from = Column(String(length=255), ForeignKey('users.username'))
    source = Column(String(length=50))

    # Constraints
    __table_args__ = (
        PrimaryKeyConstraint('id'),
        UniqueConstraint('received_from', 'source', name='unique_sources'),
        )

    def __repr__(self) -> str:
        return 'id: {}, received_from: {}, source: {}'.format(self.id, self.received_from, self.source)
    
    def __str__(self) -> str:
        return self.__repr__()



async def add_shadow_collector_ips(db, account_username, sc_list):
    target_source = '{}'.format(MaliciousIPSourceCategory.DMZ)
    if account_username in HoneyPotsConfig().honeypot_accounts:
        target_source = '{}'.format(MaliciousIPSourceCategory.HONEYPOT)
    
    device_list = SCUniqueDeviceList(sc_list)

    for _, device in device_list.devices.items():
        # Making sure device is present in the database
        db_device = db.query(MaliciousIPModel).get(device.ip)
        if not db_device:
            db_device = MaliciousIPModel(
                ip = device.ip
            )
            db.add(db_device)
            db.commit()
        else:
            db_device.count += 1
        
        # Making sure source is present in the database
        db_source = db.query(MaliciousIPSourcesModel).filter(MaliciousIPSourcesModel.received_from==account_username and MaliciousIPSourcesModel.source == target_source).first()
        if not db_source:
            db_source = MaliciousIPSourcesModel(
                received_from = account_username,
                source = target_source,
            )
            db.add(db_source)
            db.commit()
        
        # Adding field-values(information about the device)
        information = db_device.get_information(db, db_source.id)
        for field in device.fields:
            for value in device.fields[field]:
                # create information if not present, otherwise update last_detected
                for i in information:
                    if i.field == field and i.value == value:
                        i.last_detected = datetime.datetime.now()
                        i.count += 1
                        break
                else:
                    info = MaliciousIPInformationModel(
                        bad_actor = db_device.ip,
                        source_id = db_source.id,
                        field = field,
                        value = value,
                    )
                    db.add(info)
                    db.commit()
        db.commit()


async def get_malicious_ip_list_for_admin(db, page=0, page_size=10):
    db_malicious_ips = db.query(MaliciousIPModel).offset(page*page_size).limit(page_size)
    all_ips = MaliciousIPListAdmin(ips=list(), count=0)
    count = 0

    for db_ip in db_malicious_ips:
        ip = MaliciousIPAdmin(
            ip = db_ip.ip,
            count = db_ip.count,
            locations = db_ip.locations,
            information = []
        )

        for db_info in db_ip.get_all_information(db):
            info = MaliciousIPInformationAdmin(
                source_id = db_info.source_id,
                field = db_info.field,
                value = db_info.value,
                last_detected = db_info.last_detected,
                count = db_info.count,
            )
            ip.information.append(info)

        all_ips.ips.append(ip)
        count += 1
    
    all_ips.count = count

    return all_ips


async def get_malicious_ip_list_only_ips(db):
    db_malicious_ips = db.query(MaliciousIPModel).all()
    all_ips = MaliciousIPListOnlyIPs(ips=list(), total=0)
    total = 0

    for db_ip in db_malicious_ips:
        all_ips.ips.append(db_ip.ip)
        total += 1

    all_ips.total = total
    return all_ips


async def remove_malicious_ips(db, ip_addresses: MaliciousIPsRemove):
    # TODO - testing with postgres pending
    return db.query(MaliciousIPModel)\
            .filter(MaliciousIPModel.ip.in_(ip_addresses))\
            .delete()


async def get_malicious_ip_sources(db):
    # TODO - Need to implement
    pass


async def get_malicious_ip_list(db):
    pass

async def get_account_specific_malicious_ip_list(db):
    pass    

async def get_specific(db, ip):
    # TODO - modify the response
    pass

