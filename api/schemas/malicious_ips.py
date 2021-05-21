
import enum
import datetime
from typing import List
from pydantic import BaseModel


class MaliciousIPSourceCategory(str, enum.Enum):
    FIREWALL_INBOUND_TRAFFIC = 'firewall_inbound_traffic'
    FIREWALL_OUTBOUND_TRAFFIC = 'firewall_outbound_traffic'
    FIREWALL_DDOS_ATTACK = 'firewall_ddos_attack'
    HONEYPOT = 'honeypot'
    DMZ = 'dmz'



class IPLocationAdmin(BaseModel):
    ip: str
    received_from: str
    last_seen: datetime.datetime
    lat: float
    lon: float
    country: str
    city: str
    region: str


class MaliciousIPInformationAdmin(BaseModel):
    source_id: int
    field: str
    value: str
    last_detected: datetime.datetime
    count: int


class MaliciousIPSourcesAdmin(BaseModel):
    id: str
    received_from: str
    source: str


class MaliciousIPAdmin(BaseModel):
    ip: str
    count: int
    locations: List[IPLocationAdmin]
    information: List[MaliciousIPInformationAdmin]


class MaliciousIPListAdmin(BaseModel):
    ips: List[MaliciousIPAdmin]
    count: int


class MaliciousIPListOnlyIPs(BaseModel):
    ips: List[str]
    total: int
