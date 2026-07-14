import os
import ctypes
import platform
import socket
from typing import List, Dict

def is_admin() -> bool:
    """
    Check if the script is running with Administrator (Windows)
    or root (Linux/macOS) privileges.
    """
    try:
        if platform.system() == "Windows":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.getuid() == 0
    except Exception:
        return False

def get_interfaces() -> List[Dict[str, str]]:
    """
    Get a list of available network interfaces.
    Returns a list of dicts with 'name' and 'ip' keys.
    """
    interfaces = []
    # Scapy's get_if_list or conf.ifaces can be used, 
    # but for simplicity and avoid immediate scapy load delay here, we use socket
    try:
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        interfaces.append({"name": "Default", "ip": host_ip})
    except Exception:
        pass
        
    # We will also use Scapy to get more detailed interfaces when actually initializing
    # the sniffer, this is just a fallback.
    return interfaces
