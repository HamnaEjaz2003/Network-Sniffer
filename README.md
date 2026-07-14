# Network Sniffer

A robust, cross-platform Network Sniffer built with Python and Scapy. This application is designed to capture, analyze, and log network traffic efficiently without suffering from memory leaks.

## Project Overview

This project provides a professional-grade network sniffing tool that can operate both in a Command Line Interface (CLI) and a Graphical User Interface (GUI). It leverages `scapy` for deep packet inspection across various network layers (Data Link, Network, Transport, and Application layers).

## Detailed Features

- Core Network Inspection: 
  - Layer 2 (Data Link): Extracts Source/Destination MAC addresses and Ethernet types.
  - Layer 3 (Network): Extracts IPv4/IPv6 addresses, TTL/Hop Limits, and IP flags.
  - Layer 4 (Transport): Identifies protocols (TCP, UDP, ICMP), extracts source/destination ports, sequence numbers, and flags.
  - Layer 7 (Application): Safely extracts and decodes printable ASCII payloads, truncating them gracefully to prevent UI clutter.
- Architectural Efficiency: 
  - Implements a multi-threaded architecture. The sniffer loop runs on a dedicated daemon thread, preventing UI freezing.
  - Uses `scapy.sniff(store=False)` coupled with a thread-safe `queue.Queue` to ensure zero memory leaks during continuous, long-term captures.
- Dual Interfaces:
  - Command Line Interface (CLI): A terminal interface built with the `rich` library. It features live-updating data tables, color-coded protocol rows, and a comprehensive summary of statistics (total packets, top talking IPs, protocol breakdown) upon exit.
  - Graphical User Interface (GUI): A clean, native desktop application utilizing `tkinter` and `ttk`. It limits memory usage by retaining only the last 1000 packets in the view buffer. Features include easy packet filtering, live scrolling, and detailed JSON-style payload inspection with syntax highlighting for keys, strings, and integers.
- PCAP Logging: Offers the ability to stream and save all captured network traffic directly to a standard `.pcap` file using `scapy.utils.PcapWriter`. These files are fully compatible with external analysis tools such as Wireshark.
- Robust Exception Handling: Features granular error handling to gracefully inform the user about interface binding issues (e.g., non-existent interfaces, lack of administrative privileges) or internal Scapy errors, rather than causing an application crash.
- Cross Platform: Operates smoothly on Windows, Linux, and macOS. Includes built-in checks to warn users if they are not running with the requisite Administrator/Root privileges.

## Project Structure

- `src/main.py`: The main entry point of the application. It parses arguments and launches either the CLI or GUI.
- `src/core/analyzer.py`: Contains the packet analysis logic, strictly separating data extraction methodologies from the user interfaces.
- `src/core/sniffer.py`: Handles the multi-threaded sniffing loop, PCAP file writing, packet queuing, and exception propagation.
- `src/ui/cli_app.py`: The Command Line Interface implementation logic.
- `src/ui/gui_app.py`: The Graphical User Interface implementation logic.
- `src/utils/system_checks.py`: Utilities for privilege verification across different operating systems.

## Installation Instructions

1. Ensure Python 3.8 or higher is installed on your system.
2. Clone or download this repository.
3. Open your terminal and navigate to the root directory of the project.
4. Install the required dependencies using pip:
   ```bash
   pip install -r requirements.txt
   ```
   (Note: Network packet capture requires a low-level driver. You might need to install `npcap` on Windows or `libpcap` on Linux/macOS for scapy to work properly if it is not already installed on your system.)

## Usage Guide

Important Requirement: Network sniffing requires administrative privileges. You must run your terminal or command prompt as Administrator (Windows) or root (Linux/macOS) for packet capture to initialize successfully.

### Running in GUI Mode (Default)

To launch the graphical interface, run the main script without any arguments:

```bash
python src/main.py
```

In the GUI, you can perform the following actions:
- Select Interface: Choose your network interface from the dropdown list. If left blank, it will attempt to bind to the system's default active interface.
- Apply BPF Filter: Enter a Berkeley Packet Filter (e.g., `tcp port 80` or `icmp`) to capture only specific traffic.
- Save to PCAP: Check the "Save to .pcap" box to automatically record the session into a timestamped file (e.g., `capture_20260714_135047.pcap`).
- Start/Stop: Click "Start Capture" to begin sniffing and "Stop Capture" to halt. 
- Inspect Packets: Click on any row in the packet table to view its fully decoded contents in the details pane, which will be formatted as highlighted JSON data.

### Running in CLI Mode

To run the application entirely within the terminal, pass the `--cli` flag:

```bash
python src/main.py --cli
```

When you launch the CLI without further arguments, you will be prompted interactively to enter:
1. Your desired interface.
2. A BPF filter.
3. An optional PCAP filename to save the capture.

Alternatively, you can provide these settings directly via command-line arguments to bypass the interactive prompts entirely.

Specify an interface and a BPF filter:
```bash
python src/main.py --cli --interface "Ethernet" --filter "tcp port 80"
```

Save the captured traffic to a PCAP file:
```bash
python src/main.py --cli --pcap "my_capture.pcap"
```

Combine all arguments:
```bash
python src/main.py --cli -i "Ethernet" -f "icmp" -p "ping_test.pcap"
```

To terminate the CLI capture, press `Ctrl+C` at any time. The application will intercept the keyboard interrupt, gracefully stop the background sniffing thread, save and close your PCAP file (if specified), and print a detailed summary report of the captured traffic.
