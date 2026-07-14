import threading
import queue
from scapy.all import sniff
from scapy.utils import PcapWriter
from scapy.error import Scapy_Exception
from typing import Optional, Callable
from .analyzer import PacketAnalyzer

class NetworkSniffer:
    """
    A multi-threaded network sniffer using scapy that captures packets 
    without storing them in memory indefinitely to prevent memory leaks.
    """
    def __init__(self, interface: Optional[str] = None, bpf_filter: str = "", pcap_filename: Optional[str] = None):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.pcap_filename = pcap_filename
        self.packet_queue = queue.Queue()
        self._stop_event = threading.Event()
        self._sniff_thread = None
        self._pcap_writer = None

    def _packet_handler(self, packet):
        """
        Callback for scapy sniff. Analyzes the packet and puts it into the queue.
        """
        # We don't want to block the sniffer, so we put it in the queue non-blocking
        if not self._stop_event.is_set():
            if self._pcap_writer:
                self._pcap_writer.write(packet)
            
            analyzed_data = PacketAnalyzer.analyze(packet)
            try:
                self.packet_queue.put_nowait(analyzed_data)
            except queue.Full:
                pass # Drop packet if queue is unexpectedly full (shouldn't happen with infinite queue, but good for safety)

    def _sniff_loop(self):
        """
        The main loop running in a separate thread.
        """
        try:
            if self.pcap_filename:
                self._pcap_writer = PcapWriter(self.pcap_filename, append=True, sync=True)

            sniff(
                iface=self.interface,
                filter=self.bpf_filter,
                prn=self._packet_handler,
                store=False, # EXTREMELY IMPORTANT: prevents memory leak
                stop_filter=lambda p: self._stop_event.is_set()
            )
        except OSError as e:
            self.packet_queue.put({"error": f"Interface Error: Could not bind to interface '{self.interface}'. (Run as Admin or check interface name). Details: {e}"})
        except Scapy_Exception as e:
            self.packet_queue.put({"error": f"Scapy Error: {e}"})
        except Exception as e:
            self.packet_queue.put({"error": f"Unexpected Sniffer Error: {str(e)}"})
        finally:
            if self._pcap_writer:
                self._pcap_writer.close()
                self._pcap_writer = None

    def start(self):
        """
        Start the sniffing thread.
        """
        self._stop_event.clear()
        self._sniff_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._sniff_thread.start()

    def stop(self):
        """
        Signal the sniffing thread to stop.
        """
        self._stop_event.set()
        if self._sniff_thread and self._sniff_thread.is_alive():
            # Scapy's stop_filter only checks when a new packet arrives.
            # So the thread might not terminate immediately if no packets arrive.
            # But the daemon=True ensures it won't block the program exit.
            pass

    def get_packet(self, timeout=0.1) -> Optional[dict]:
        """
        Retrieve a packet from the queue for the UI.
        """
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
