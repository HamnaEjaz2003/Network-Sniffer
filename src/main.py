import argparse
import sys
import os

# Ensure the root of the project is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def main():
    parser = argparse.ArgumentParser(description="Professional Network Sniffer")
    parser.add_argument("--cli", action="store_true", help="Run in Command Line Interface mode")
    parser.add_argument("--interface", "-i", type=str, default=None, help="Network interface to sniff on (default: active interface)")
    parser.add_argument("--filter", "-f", type=str, default="", help="BPF filter (e.g., 'tcp port 80')")
    parser.add_argument("--pcap", "-p", type=str, default="", help="Path to save captured packets as a .pcap file (CLI only)")
    
    args = parser.parse_args()

    if args.cli:
        from src.ui.cli_app import CLIApp
        app = CLIApp(interface=args.interface, bpf_filter=args.filter, pcap_file=args.pcap)
        app.run()
    else:
        from src.ui.gui_app import run_gui
        # BPF and Interface args are mostly ignored here since GUI allows selection,
        # but could be passed to pre-fill the GUI inputs if desired.
        run_gui()

if __name__ == "__main__":
    main()
