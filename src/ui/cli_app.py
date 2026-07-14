import time
import sys
from collections import Counter
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from src.core.sniffer import NetworkSniffer
from src.utils.system_checks import is_admin

class CLIApp:
    def __init__(self, interface=None, bpf_filter="", pcap_file=""):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.pcap_file = pcap_file if pcap_file else None
        self.console = Console()
        
        # Statistics
        self.total_packets = 0
        self.protocol_counts = Counter()
        self.ip_counts = Counter()
        self.start_time = 0

    def generate_table(self, recent_packets) -> Table:
        """Create a rich table for live packet display."""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("No.", style="dim", width=6)
        table.add_column("Protocol", width=8)
        table.add_column("Source", justify="left", width=25)
        table.add_column("Destination", justify="left", width=25)
        table.add_column("Info", justify="left")

        for idx, pkt in enumerate(recent_packets):
            proto = "Unknown"
            src = "Unknown"
            dst = "Unknown"
            info = pkt.get("summary", "")

            # Set colors based on protocol
            style = "white"

            if "protocol" in pkt.get("l4", {}):
                proto = pkt["l4"]["protocol"]
                if proto == "TCP":
                    style = "cyan" # Keeping cyan inside the box as it is more readable than dark blue
                elif proto == "UDP":
                    style = "green"
                elif proto == "ICMP":
                    style = "red"
            elif "protocol" in pkt.get("l3", {}):
                proto = pkt["l3"]["protocol"]
                style = "yellow"

            if "src_ip" in pkt.get("l3", {}):
                src = pkt["l3"]["src_ip"]
                if "src_port" in pkt.get("l4", {}):
                    src += f":{pkt['l4']['src_port']}"
            elif "src_mac" in pkt.get("l2", {}):
                src = pkt["l2"]["src_mac"]

            if "dst_ip" in pkt.get("l3", {}):
                dst = pkt["l3"]["dst_ip"]
                if "dst_port" in pkt.get("l4", {}):
                    dst += f":{pkt['l4']['dst_port']}"
            elif "dst_mac" in pkt.get("l2", {}):
                dst = pkt["l2"]["dst_mac"]
                
            if "payload" in pkt.get("l7", {}):
                payload_str = pkt["l7"]["payload"].replace('\n', ' ')
                if len(payload_str) > 40:
                    payload_str = payload_str[:37] + "..."
                info += f" | Payload: {payload_str}"

            # Calculate actual packet number based on total captured
            actual_num = self.total_packets - len(recent_packets) + idx + 1
            table.add_row(str(actual_num), proto, src, dst, info, style=style)

        return table

    def show_summary(self):
        """Display summary statistics upon exit."""
        duration = time.time() - self.start_time
        self.console.print("\n[bold green]Capture Stopped. Generating Summary...[/bold green]")
        
        summary_text = (
            f"[bold]Total Packets Captured:[/bold] {self.total_packets}\n"
            f"[bold]Capture Duration:[/bold] {duration:.2f} seconds\n\n"
        )
        
        summary_text += "[bold]Protocol Breakdown:[/bold]\n"
        for proto, count in self.protocol_counts.most_common():
            summary_text += f"  - {proto}: {count}\n"
            
        summary_text += "\n[bold]Top 5 Talking IPs:[/bold]\n"
        for ip, count in self.ip_counts.most_common(5):
            summary_text += f"  - {ip}: {count} packets\n"
            
        if self.pcap_file:
            summary_text += f"\n[bold green]Packets saved to:[/bold green] {self.pcap_file}\n"
            
        self.console.print(Panel(summary_text, title="Traffic Summary", expand=False))

    def prompt_user(self):
        """Prompt user for missing details instead of auto-starting"""
        self.console.print(Panel("[bold cyan]Welcome to the Network Sniffer CLI[/bold cyan]"))
        
        if self.interface is None:
            self.interface = Prompt.ask("Enter network [bold]interface[/bold] to sniff on (leave blank for Default)", default="")
            if self.interface == "":
                self.interface = None
                
        if self.bpf_filter == "":
            self.bpf_filter = Prompt.ask("Enter [bold]BPF Filter[/bold] (leave blank for None)", default="")

        if not self.pcap_file:
            pcap = Prompt.ask("Enter filename to save .pcap (leave blank for none)", default="")
            if pcap:
                if not pcap.endswith(".pcap"):
                    pcap += ".pcap"
                self.pcap_file = pcap

    def run(self):
        if not is_admin():
            self.console.print("[bold red]Warning: You are not running as Administrator/root. Packet capture may fail.[/bold red]")
            
        # Interactive prompts before starting
        self.prompt_user()
            
        self.console.print(f"\n[bold cyan]Starting capture on interface: {self.interface or 'Default'} | Filter: {self.bpf_filter or 'None'}[/bold cyan]")
        self.console.print("[yellow]Press Ctrl+C to stop...[/yellow]\n")
        
        self.sniffer = NetworkSniffer(interface=self.interface, bpf_filter=self.bpf_filter, pcap_filename=self.pcap_file)
        self.start_time = time.time()
        self.sniffer.start()
        
        recent_packets = []
        
        try:
            # We keep the last 30 packets in view to allow seeing "above or below" more clearly
            # while maintaining the beautiful Table box
            with Live(self.generate_table(recent_packets), refresh_per_second=4, console=self.console) as live:
                while True:
                    pkt = self.sniffer.get_packet(timeout=0.2)
                    if pkt:
                        if "error" in pkt:
                            self.console.print(f"[bold red]Sniffer Error: {pkt['error']}[/bold red]")
                            break
                            
                        self.total_packets += 1
                        
                        # Update stats
                        proto = pkt.get("l4", {}).get("protocol", pkt.get("l3", {}).get("protocol", "Other"))
                        self.protocol_counts[proto] += 1
                        
                        src_ip = pkt.get("l3", {}).get("src_ip")
                        if src_ip:
                            self.ip_counts[src_ip] += 1
                            
                        recent_packets.append(pkt)
                        if len(recent_packets) > 30: # Increased from 15 to 30 to show more history
                            recent_packets.pop(0)
                            
                        live.update(self.generate_table(recent_packets))
                        
        except KeyboardInterrupt:
            pass
        finally:
            self.sniffer.stop()
            self.show_summary()
