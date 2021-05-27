
from fingerprint import FingerprintingInfo
from collectors import P0FCollector

import logger_manager
logger = logger_manager.setup_logging('shadow_collector_logs')


logger.info("Process started.")
fp = FingerprintingInfo(logger)
p = P0FCollector(logger, fp, 'ens4')
# TODO - Need to test mongodb add_sc and list_mal_ip related endpoints, directly from API swagger doc
# TODO - configure interface in config file
# TODO - Internal IPs are filtered by default.
logger.info("Executing p0f")
p.excute()
