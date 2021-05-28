
import enum
from typing import Optional, List
from pydantic import BaseModel


class FirewallIpCategory(str, enum.Enum):
    DDOS = "ddos"
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class FirewallMaliciousIPCreateOld(BaseModel):
    ip: str
    ip_location: str
    category: FirewallIpCategory
    device_name: str
    device: str
    customer_id: Optional[str]
    no_of_ports_used: Optional[int]
    no_of_victims: Optional[int]
    last_seen: Optional[float]

class FirewallMaliciousIPCreate(BaseModel):
    ip: str
    ip_location: str
    category: FirewallIpCategory
    device: str
    last_seen: Optional[float]


class FirewallMaliciousIPCreateListOld(BaseModel):
    data: List[FirewallMaliciousIPCreateOld] = []

class FirewallMaliciousIPCreateList(BaseModel):
    data: List[FirewallMaliciousIPCreate] = []



class FirewallMaliciousIPGetOld(BaseModel):
    ip: str
    description: str
    ip_location: str
    last_seen: float

class FirewallMaliciousIPGetAllOld(BaseModel):
    data: List[FirewallMaliciousIPGetOld] = []


class FirewallMaliciousIPGet(BaseModel):
    ip: str
    category: str
    ip_location: str
    last_seen: float
    no_of_affected_devices: int
    no_of_hits: int


class FirewallMaliciousIPGetAll(BaseModel):
    data: List[FirewallMaliciousIPGet] = []


class FirewallMaliciousIPsRemove(BaseModel):
    ips_to_remove: List[str]
