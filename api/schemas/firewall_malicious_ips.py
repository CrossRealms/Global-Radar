
import enum
from typing import Optional, List
from pydantic import BaseModel


class FirewallIpCategory(str, enum.Enum):
    DDOS = "ddos"
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class FirewallMaliciousIPCreate(BaseModel):
    ip: str
    ip_location: str
    category: FirewallIpCategory
    device_name: str
    device: str
    customer_id: Optional[str]
    no_of_ports_used: Optional[int]
    no_of_victims: Optional[int]


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


class FirewallMaliciousIPListResponse(BaseModel):
    ip_list: List[str]


class FirewallMaliciousIPGet(BaseModel):
    ip: str
    description: str
    ip_location: str
    last_seen: int
    no_of_affected_devices: int
    no_of_hits: int

class FirewallMaliciousIPGetAll(BaseModel):
    data: List[FirewallMaliciousIPGet] = []
