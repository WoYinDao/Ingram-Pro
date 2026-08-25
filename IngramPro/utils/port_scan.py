"""TCP port scanner using raw sockets."""
import socket

from loguru import logger


def port_scan(ip: str, port: str, timeout: int=1) -> bool:
    """Check if tcp/ip port is open using a socket connection."""
    with socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            return s.connect_ex((ip, int(port))) == 0
        except Exception as e:
            logger.error(e)
            return False
