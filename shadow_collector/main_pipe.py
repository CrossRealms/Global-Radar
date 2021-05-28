
from fingerprint import FingerprintingInfo
from collectors import P0FCollector

import logger_manager
logger = logger_manager.setup_logging('shadow_collector_logs')


logger.info("Process started.")
fp = FingerprintingInfo(logger)
p = P0FCollector(logger, fp)
# TODO - Need to test with the environment where p0f command gives error or p0f command not exist, etc.
logger.info("Executing p0f")
p.excute()
