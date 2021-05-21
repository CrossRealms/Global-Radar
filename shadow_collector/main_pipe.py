
from fingerprint import FingerprintingInfo
from collectors import P0FCollector

import logger_manager
logger = logger_manager.setup_logging('shadow_collector_logs')


logger.info("Process started.")
fp = FingerprintingInfo(logger)
p = P0FCollector(logger, fp, 'ens4')
logger.info("Executing p0f")
p.excute()
