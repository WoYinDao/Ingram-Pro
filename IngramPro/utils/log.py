"""Logging configuration via loguru."""
import sys
from loguru import logger


def _not_debug_filter(record):
    """Non-debug console: hide DEBUG, keep WARNING and ERROR visible."""
    return record['level'].name != 'DEBUG'



def config_logger(log_file: str, debug: bool = False):
    """Configure loguru sinks: file sink always active; stderr only in debug mode."""
    logger.remove()   # remove default stderr sink

    # File sink - always capture everything
    logger.add(log_file, level='DEBUG', rotation='10 MB', retention=3)

    # Console sink - only show WARNING+ unless debug is enabled
    if debug:
        logger.add(sys.stderr, level='DEBUG')
    else:
        logger.add(sys.stderr, level='WARNING', filter=_not_debug_filter)
