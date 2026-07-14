import string
from scapy.all import Packet, Ether, IP, IPv6, TCP, UDP, ICMP, Raw

class PacketAnalyzer:
    """
    A class to extract and format data from different network layers using Scapy.
    """
    
    @staticmethod
    def _is_printable(s: bytes) -> str:
        """
        Safely extract printable ASCII characters from a bytes payload.
        """
        try:
            decoded = s.decode('utf-8', errors='ignore')
            return ''.join(c for c in decoded if c in string.printable)
        except Exception:
            return ""

    @staticmethod
    def analyze(packet: Packet) -> dict:
        """
        Analyze a scapy packet and extract relevant L2, L3, L4, and L7 data.
        Returns a dictionary with the extracted info.
        """
        result = {
            "summary": packet.summary(),
            "length": len(packet),
            "l2": {},
            "l3": {},
            "l4": {},
            "l7": {}
        }

        # Layer 2: Data Link
        if packet.haslayer(Ether):
            result["l2"]["src_mac"] = packet[Ether].src
            result["l2"]["dst_mac"] = packet[Ether].dst
            result["l2"]["type"] = hex(packet[Ether].type)

        # Layer 3: Network
        if packet.haslayer(IP):
            result["l3"]["protocol"] = "IPv4"
            result["l3"]["src_ip"] = packet[IP].src
            result["l3"]["dst_ip"] = packet[IP].dst
            result["l3"]["ttl"] = packet[IP].ttl
            # IP Flags can be extracted as a string representation
            result["l3"]["flags"] = str(packet[IP].flags)
        elif packet.haslayer(IPv6):
            result["l3"]["protocol"] = "IPv6"
            result["l3"]["src_ip"] = packet[IPv6].src
            result["l3"]["dst_ip"] = packet[IPv6].dst
            result["l3"]["hlim"] = packet[IPv6].hlim # Hop Limit (similar to TTL)
            
        # Layer 4: Transport
        if packet.haslayer(TCP):
            result["l4"]["protocol"] = "TCP"
            result["l4"]["src_port"] = packet[TCP].sport
            result["l4"]["dst_port"] = packet[TCP].dport
            result["l4"]["seq"] = packet[TCP].seq
            result["l4"]["ack"] = packet[TCP].ack
            result["l4"]["flags"] = str(packet[TCP].flags)
        elif packet.haslayer(UDP):
            result["l4"]["protocol"] = "UDP"
            result["l4"]["src_port"] = packet[UDP].sport
            result["l4"]["dst_port"] = packet[UDP].dport
            result["l4"]["len"] = packet[UDP].len
        elif packet.haslayer(ICMP):
            result["l4"]["protocol"] = "ICMP"
            result["l4"]["type"] = packet[ICMP].type
            result["l4"]["code"] = packet[ICMP].code

        # Layer 7: Application / Payload
        if packet.haslayer(Raw):
            raw_payload = packet[Raw].load
            printable_payload = PacketAnalyzer._is_printable(raw_payload)
            if printable_payload.strip():
                # Truncate if too long to keep UI clean, but provide a decent chunk
                result["l7"]["payload"] = printable_payload[:500] 

        return result
