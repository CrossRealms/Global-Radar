
import threading
import time
from api import CyencesAPI

FILTER_FIELDS = ["client", "server"]
# EMPTY_OS = '-'


class DeviceInfo:

    def __init__(self, ip, data=None):
        self.ip = ip
        # self.os = os
        self.fields = dict()
        if data:
            self.add_data(data)
    
    def add_data(self, data):
        # data is List[Tuple[(<fieldname>,<fieldvalue>)]]
        for i in data:
            if i[0] not in FILTER_FIELDS:
                if i[0] in self.fields:
                    self.fields[i[0]].add(i[1])
                else:
                    self.fields[i[0]] = set()
                    self.fields[i[0]].add(i[1])

    def get_representation(self):
        fields_list = dict()
        for key in self.fields:
            fields_list[key] = list(self.fields[key])
        return {
            "ip": self.ip,
            "fields": fields_list
        }

    def __repr__(self) -> str:
        return '{}'.format(self.get_representation())
    
    def __str__(self) -> str:
        return self.__repr__()

    def __eq__(self, other):
        return self.ip == other.ip
    
    def __hash__(self):
        return hash((self.ip))


class FingerprintingInfo:
    API_PUSH_SCHEDULE_TIME = 900   # API Scheduling - 15 minute = 900 seconds

    def __init__(self, logger):
        self.logger = logger
        self.device_list = dict()
        self.run_scheduler()
    
    def __repr__(self):
        return '{}'.format(self.device_list)
    
    def __str__(self) -> str:
        return self.__repr__()

    def run_scheduler(self):
        t = threading.Thread(target=self.schedule)
        t.start()
        self.is_scheduler_running = True
        self.logger.info("Started API scheduler()")
    
    def stop_scheduler(self):
        self.logger.info("Stopping API Scheduled()")
        self.is_scheduler_running = False
    
    def schedule(self):
        time.sleep(self.API_PUSH_SCHEDULE_TIME)
        # TODO - on cancelling the process sleep is continue and exist after sleep completes
        self.send_data_to_api()
        if self.is_scheduler_running:
            self.schedule()

    def get_device_signature(self, ip):
        return "{}".format(ip)

    def add_device_info(self, ip, data):
        # os = EMPTY_OS
        # for i in data:
        #     if i[0] == 'os':
        #         os = i[1]
        #         break
        dev_rep = self.get_device_signature(ip)
        if dev_rep in self.device_list:
            self.device_list[dev_rep].add_data(data)
        else:
            self.device_list[dev_rep] = DeviceInfo(ip, data)


    def send_data_to_api(self):
        try:
            data_to_be_sent = self.device_list
            self.device_list = dict()
            self.logger.info("Sending data to API.")
            # TODO - we can use multiprocessing here, as the data is already separated
            api = CyencesAPI(self.logger)
            api.send_info_to_api(data_to_be_sent)
        except Exception as e:
            self.logger.exception("Error while sending data to API. {}".format(e))
