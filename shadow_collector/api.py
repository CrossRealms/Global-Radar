
import requests
import configparser

CONFIG_FILE = 'sc.conf'
API_CONFIGURATION = 'api'
API_PATH_ADD_FINGERPRINT = 'api/v1/sc/add'
DEFAULT_API_TIMEOUT = 20


class CyencesAPI:
    def __init__(self, logger):
        conf = configparser.RawConfigParser()   
        conf.read(CONFIG_FILE)
        self.api_url = conf.get(API_CONFIGURATION, 'url').strip().rstrip("/")
        # self.api_username = conf.get(API_CONFIGURATION, 'username')
        # self.api_password = conf.get(API_CONFIGURATION, 'password')
        self.api_access_key = conf.get(API_CONFIGURATION, 'access_key')
        self.logger = logger
        self.headers = {
            "accept": "application/json",
            "Authorization": "Bearer {}".format(self.api_access_key),
            "Content-Type": "application/json"
        }

    
    def send_info_to_api(self, data):
        # TODO - Need to handle a situation where temporary API is not reachable (need to store data in queue for failure scenario)
        # TODO - Need to also handle scenario where for continuously 3 times, shutdown the process with the error
        json_data = {
            "device_list": []
        }

        for i in data:
            json_data["device_list"].append(data[i].get_representation())
        '''
        Example:
            {
                "device_list": [
                    {
                        "ip": "10.33.1.33",
                        "fields": {
                            "uptime": ["29 days 18 hrs 38 min (modulo 49 days)"],
                            "raw_freq": ["1000.00 Hz"]
                        }
                    }
                ]
            }
        '''
        
        # TODO - Need to remove below line
        self.logger.debug("Data to be sent to API: {}".format(json_data))
        try:
            response = requests.post(
                url = "{}/{}".format(self.api_url, API_PATH_ADD_FINGERPRINT),
                json = json_data,
                headers = self.headers,
                timeout = DEFAULT_API_TIMEOUT
            )
            if(response.status_code >= 200 and response.status_code < 300):
                self.logger.info("Fingerprinting data successfully sent to Cyences API.")
            else:
                self.logger.error("API request is not valid. Response-Code:{}, Response-Body:{}".format(response.status_code, response.json()))
        except Exception as e:
            self.logger.exception("Error while sending fingerprinting information to API. {}".format(e))
