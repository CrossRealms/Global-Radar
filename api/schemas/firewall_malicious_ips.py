
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

class FirewallMaliciousIPCreate(BaseModel):
    ip: str
    ip_location: str
    category: FirewallIpCategory
    device: str
    last_seen: float   # TODO - currently not being used, we can use after applying validator this cannot be more than current time


class FirewallMaliciousIPCreateListOld(BaseModel):
    data: List[FirewallMaliciousIPCreateOld] = []
    class Config:
        schema_extra = {
            'example': {
                'data': [
                    {
                        'ip': "1.2.3.4",
                        'ip_location': 'Sydney',
                        'category': 'ddos',
                        'device_name': 'dev-1',
                        'device': 'chapman',
                        'customer_id': 'wer',
                        'no_of_ports_used': 10,
                        'no_of_victims': 12
                    }
                ]
            }
        }

class FirewallMaliciousIPCreateList(BaseModel):
    data: List[FirewallMaliciousIPCreate] = []
    class Config:
        schema_extra = {
            'example': {
                'data': [
                    {
                        'ip': "1.2.3.4",
                        'ip_location': 'Sydney',
                        'category': 'ddos',
                        'device_name': 'dev-1',
                        'device': 'chapman',
                        'customer_id': 'wer',
                        'no_of_ports_used': 10,
                        'no_of_victims': 12
                    }
                ]
            }
        }



class FirewallMaliciousIPGetOld(BaseModel):
    ip: str
    description: str
    ip_location: str
    last_seen: float
    no_of_affected_devices: int
    no_of_hits: int

class FirewallMaliciousIPGet(BaseModel):
    ip: str
    description: str
    ip_location: str
    last_seen: float
    no_of_affected_devices: int
    no_of_hits: int


class FirewallMaliciousIPGetAllOld(BaseModel):
    data: List[FirewallMaliciousIPGetOld] = []


class FirewallMaliciousIPGetAll(BaseModel):
    data: List[FirewallMaliciousIPGet] = []
