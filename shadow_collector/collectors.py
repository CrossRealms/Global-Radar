
import re
import queue
import subprocess
import threading
import time
import configparser

CONFIG_FILE = 'sc.conf'
SC_CONFIGURATION = 'shadow_collector'
conf = configparser.RawConfigParser()
conf.read(CONFIG_FILE)



class ShadowCollector:

    EMPTY_QUEUE_SLEEP_TIME = 0.5   # seconds

    PRIVATE_IP_CHECK = '(^127\.)|(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)'

    def __init__(self, logger, fingerprint, command):
        self.command = command
        self.fingerprint = fingerprint
        self.logger = logger
    

    def excute(self):

        processable_data = ''
        try:
            streaming_queue = queue.Queue()
            popen = subprocess.Popen(self.command, stdout=subprocess.PIPE, universal_newlines=True)
            thr = threading.Thread(target=self.enqueue_output, args=(popen.stdout, streaming_queue))
            thr.daemon = True   # thread dies with the program
            thr.start()
            self.logger.info("Enqueue output thread started.")
            while True:
                if streaming_queue.empty():
                    time.sleep(self.EMPTY_QUEUE_SLEEP_TIME)
                    continue
                output = streaming_queue.get_nowait()
                processable_data += output
                blocks, rest = self.wait_until_block_ends(processable_data)
                if not blocks:
                    continue
                else:
                    self.process_data(blocks)
                    processable_data = rest
            # below code will never be called
            # TODO - Need to find a way by which we can identify if the command fails initially or fails later on, we can identify
            return_code = popen.wait()
            if return_code:
                self.logger.exception("Process error: return_code: {}".format(return_code))
                raise subprocess.CalledProcessError(return_code, self.command)
        except Exception as e:
            # Process has finished
            self.logger.exception("Exception while executing command. {}".format(e))
            self.fingerprint.stop_scheduler()
        
    
    def enqueue_output(self, popen_stdout, streaming_queue):
        for stdout_line in iter(popen_stdout.readline, ""):
            streaming_queue.put(stdout_line)
        popen_stdout.close()



class P0FCollector(ShadowCollector):

    BLOCK_SEPARATOR = '\.?\-(\[\s*[^`]*)'
    BLOCK_MAIN_INFORMATION = '\[\s*([^\/]*)\/(\d*)\s*\-\>\s*([^\/]*)\/(\d*)\s*\(([^\)]*)\)\s*\]\-\s*'
    #                                  1-ip       2-port       3-internal_ip 4-internal_port  5-protocol
    BLOCK_FIELDS = '\s*\|\s*([\w_\d]+)\s*\=\s+(.*)\s'
    #                        1-field_name       2-field_value
    BLOCK_END = "`----"


    def __init__(self, logger, fingerprint, promiscuous=True):
        current_machine_ips = conf.get(SC_CONFIGURATION, 'current_machine_ips').strip().split(",")
        self.current_machine_ips = [x.strip() for x in current_machine_ips]

        filter_internal_ips = conf.get(SC_CONFIGURATION, 'filter_internal_ips').strip()
        self.filter_internal_ips = True    # default is to filter internal IPs
        if filter_internal_ips.lower() in ['0', 'f', 'false']:
            self.filter_internal_ips = False


        interface = conf.get(SC_CONFIGURATION, 'interface').strip()
        cmd = ['p0f', '-i', interface]
        if promiscuous:
            cmd.append('-p')
        super().__init__(logger, fingerprint, cmd)
        

    def process_data(self, content):
        all_blocks = re.findall(self.BLOCK_SEPARATOR, content)
        for i in all_blocks:
            self.extract_information_from_block(i)


    def extract_information_from_block(self, block):
        main_info = re.search(self.BLOCK_MAIN_INFORMATION, block)
        if main_info:
            other_ip = None
            other_port = None
            ip1 = main_info.group(1)
            port1 = main_info.group(2)
            ip2 = main_info.group(3)
            port2 = main_info.group(4)

            ip1_is_current = ip1 in self.current_machine_ips
            ip2_is_current = ip2 in self.current_machine_ips
            
            if ip1_is_current and ip2_is_current:
                # This is not possible scenario as traffic cannot go from one machine to the same machine, handling crazily defined conf file scenario
                return

            if not ip1_is_current:
                other_ip = ip1
                other_port = port1
            elif not ip2_is_current:
                other_ip = ip2
                other_port = port2

            if self.filter_internal_ips:
                if re.match(self.PRIVATE_IP_CHECK, other_ip):
                    # If set to filter internal IPs, ignore filter internal IPs with regex
                    return

            protocol = main_info.group(5)
            other_info = re.findall(self.BLOCK_FIELDS, block)
            other_info.append(('port', other_port))
            other_info.append(('protocol', protocol))
            self.fingerprint.add_device_info(other_ip, other_info)


    def wait_until_block_ends(self, output):
        block_ending = re.search("(?s:.*){}".format(self.BLOCK_END), output)
        if block_ending:
            return output[:block_ending.end()], output[block_ending.end():]
        else:
            return None, output
