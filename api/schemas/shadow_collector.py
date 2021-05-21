
from typing import List, Dict, Set
from pydantic import BaseModel, validator
from util import logger_manager



FingerprintGenericFields = Dict[str, Set]
ALLOWED_FINGERPRINT_FIELDS = ['os', 'port', 'dist', 'params', 'protocol', 'app', 'link', 'uptime', 'reason', 'raw_mtu', 'raw_sig', 'raw_freq', 'raw_hits']


class SCDeviceInfo(BaseModel):
    ip: str
    fields_alias: FingerprintGenericFields
    # Developer Note - fields is not allowed, so need to use Config to make alias

    class Config:
        fields = {'fields_alias': 'fields'}


class SCDeviceList(BaseModel):
    device_list: List[SCDeviceInfo]



class SCUniqueDevice:

    def __init__(self, logger, ip):
        self.logger = logger
        self.ip = ip
        # self.os = os
        self.fields = dict()
    
    def add_data(self, data):
        # data is Dict[AnyStr, Set]
        for i in data:
            if i in ALLOWED_FINGERPRINT_FIELDS:
                if i not in self.fields:
                    self.fields[i] = set()
                self.fields[i].update(data[i])
            else:
                self.logger.info('Received not allowed field: {}, with values: {}'.format(i, data[i]))

    def __eq__(self, other):
        return self.ip == other.ip
    
    def __hash__(self):
        return hash((self.ip))
    
    
    def __repr__(self) -> str:
        return 'ip: {}, fields: {}\n'.format(self.ip, self.fields)
    
    def __str__(self) -> str:
        return self.__repr__()


class SCUniqueDeviceList:
    
    # EMPTY_OS_VALUES = ['???']
    # EMPTY_OS = '-'

    def __init__(self, sc_list):
        self.logger = logger_manager.setup_logging('shadow_collector')
        self.devices = dict()
        self.generate_unique_devices(sc_list)
        self.set_fields(sc_list)
    
    def get_device_signature(self, ip):
        return "{}".format(ip)
    
    def generate_unique_devices(self, sc_list):
        for device in sc_list.device_list:
            # os = self.EMPTY_OS if device.os in self.EMPTY_OS_VALUES else device.os
            if self.get_device_signature(device.ip) not in self.devices:
                new_device = SCUniqueDevice(self.logger, device.ip)
                self.devices[self.get_device_signature(device.ip)] = new_device

    
    def set_fields(self, sc_list):
        for device in sc_list.device_list:
            # os = self.EMPTY_OS if device.os in self.EMPTY_OS_VALUES else device.os
            device_obj = self.devices[self.get_device_signature(device.ip)]
            device_obj.add_data(device.fields_alias)
    
    
    def __repr__(self) -> str:
        return 'devices: {}'.format(self.devices)
    
    def __str__(self) -> str:
        return self.__repr__()
