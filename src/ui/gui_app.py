import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import json
import re
import datetime
from scapy.arch import get_if_list
from src.core.sniffer import NetworkSniffer
from src.utils.system_checks import is_admin

class GUIApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Professional Network Sniffer")
        self.root.geometry("1000x700")
        
        self.sniffer = None
        self.is_sniffing = False
        self.packet_count = 0
        self.packets_data = [] # Store limited history for detail view
        
        # Statistics
        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.start_time = 0
        self.pcap_filename = None

        self._setup_style()
        self._setup_ui()
        self._check_privileges()

    def _setup_style(self):
        self.style = ttk.Style()
        # Use a cleaner theme if available ('clam' is usually available and looks better than default on Windows)
        if 'clam' in self.style.theme_names():
            self.style.theme_use('clam')
            
        default_font = ('Segoe UI', 10)
        bold_font = ('Segoe UI', 10, 'bold')
        
        self.style.configure(".", font=default_font)
        self.style.configure("Treeview.Heading", font=bold_font, background="#e1e1e1", foreground="black")
        self.style.configure("Treeview", rowheight=25, font=('Segoe UI', 9))
        self.style.configure("TButton", padding=6, font=bold_font)
        self.style.configure("TLabel", padding=2)
        
        # Status Bar Style
        self.style.configure("StatusBar.TFrame", background="#f0f0f0")
        self.style.configure("StatusBar.TLabel", background="#f0f0f0", font=('Segoe UI', 9))

    def _setup_ui(self):
        # Control Frame
        control_frame = ttk.Frame(self.root, padding="10")
        control_frame.pack(fill=tk.X)

        ttk.Label(control_frame, text="Interface:").pack(side=tk.LEFT, padx=(0, 5))
        
        # Use Combobox instead of Entry
        ifaces = [""] + get_if_list()
        self.iface_entry = ttk.Combobox(control_frame, values=ifaces, width=20, state="normal")
        self.iface_entry.pack(side=tk.LEFT, padx=(0, 15))
        self.iface_entry.insert(0, "") # Empty implies default

        ttk.Label(control_frame, text="BPF Filter:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_entry = ttk.Entry(control_frame, width=25)
        self.filter_entry.pack(side=tk.LEFT, padx=(0, 15))

        self.start_btn = ttk.Button(control_frame, text="Start Capture", command=self.toggle_capture)
        self.start_btn.pack(side=tk.LEFT)

        self.restart_btn = ttk.Button(control_frame, text="Restart", command=self.restart_capture)
        self.restart_btn.pack(side=tk.LEFT, padx=(5, 0))

        self.save_pcap_var = tk.BooleanVar(value=False)
        self.save_pcap_chk = ttk.Checkbutton(control_frame, text="Save to .pcap", variable=self.save_pcap_var)
        self.save_pcap_chk.pack(side=tk.LEFT, padx=(15, 0))

        self.status_var = tk.StringVar()
        self.status_var.set("● STOPPED")
        self.status_label = ttk.Label(control_frame, textvariable=self.status_var, foreground="#d9534f", font=('Segoe UI', 10, 'bold'))
        self.status_label.pack(side=tk.RIGHT, padx=10)

        # Main Splitter
        paned_window = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # Packet Table Frame
        table_frame = ttk.Frame(paned_window)
        paned_window.add(table_frame, weight=3)

        columns = ("No.", "Protocol", "Source", "Destination", "Length", "Info")
        self.tree = ttk.Treeview(table_frame, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, minwidth=50, width=120)
        self.tree.column("Info", width=400)
        self.tree.column("No.", width=60, anchor=tk.CENTER)
        self.tree.column("Protocol", width=80, anchor=tk.CENTER)
        self.tree.column("Length", width=80, anchor=tk.E)
        
        # Tags for row coloring
        self.tree.tag_configure("TCP", background="#e6f2ff") # Light Blue
        self.tree.tag_configure("UDP", background="#e6ffe6") # Light Green
        self.tree.tag_configure("ICMP", background="#ffe6e6") # Light Red
        self.tree.tag_configure("Other", background="#f9f9f9")
        
        # Scrollbar for tree
        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.tree.bind("<<TreeviewSelect>>", self.on_packet_select)

        # Details Frame
        details_frame = ttk.Frame(paned_window)
        paned_window.add(details_frame, weight=1)

        self.details_text = scrolledtext.ScrolledText(details_frame, height=12, state='disabled', font=('Consolas', 10))
        self.details_text.pack(fill=tk.BOTH, expand=True)
        
        # Syntax highlighting tags
        self.details_text.tag_config("key", foreground="#005cc5", font=('Consolas', 10, 'bold'))
        self.details_text.tag_config("string", foreground="#032f62")
        self.details_text.tag_config("number", foreground="#005cc5")

        # Live Statistics Status Bar
        self.status_bar = ttk.Frame(self.root, style="StatusBar.TFrame", padding=(10, 2))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.stats_var = tk.StringVar()
        self.update_stats_label()
        ttk.Label(self.status_bar, textvariable=self.stats_var, style="StatusBar.TLabel").pack(side=tk.LEFT)
        
        self.duration_var = tk.StringVar()
        self.duration_var.set("Time: 00:00:00")
        ttk.Label(self.status_bar, textvariable=self.duration_var, style="StatusBar.TLabel").pack(side=tk.RIGHT)

    def _check_privileges(self):
        if not is_admin():
            messagebox.showwarning("Privilege Warning", "You are not running as Administrator/root.\nPacket capture will likely fail.")

    def update_stats_label(self):
        s = self.stats
        self.stats_var.set(f"Total: {self.packet_count} | TCP: {s['TCP']} | UDP: {s['UDP']} | ICMP: {s['ICMP']} | Other: {s['Other']}")

    def toggle_capture(self):
        if not self.is_sniffing:
            self.start_capture()
        else:
            self.stop_capture()

    def restart_capture(self):
        if self.is_sniffing:
            self.stop_capture()
        self.start_capture()

    def start_capture(self):
        interface = self.iface_entry.get() or None
        bpf_filter = self.filter_entry.get()
        
        if self.save_pcap_var.get():
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.pcap_filename = f"capture_{timestamp}.pcap"
        else:
            self.pcap_filename = None
        
        self.sniffer = NetworkSniffer(interface=interface, bpf_filter=bpf_filter, pcap_filename=self.pcap_filename)
        self.sniffer.start()
        
        self.is_sniffing = True
        self.start_btn.config(text="Stop Capture")
        self.status_var.set("● RUNNING")
        self.status_label.config(foreground="#5cb85c")
        
        # Disable inputs
        self.iface_entry.config(state='disabled')
        self.filter_entry.config(state='disabled')
        self.save_pcap_chk.config(state='disabled')
        
        # Clear previous data
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.packets_data.clear()
        self.packet_count = 0
        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.start_time = time.time()
        self.update_stats_label()
        
        self.details_text.config(state='normal')
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state='disabled')

        self.root.after(100, self.poll_queue)
        self.root.after(1000, self.update_duration)

    def stop_capture(self):
        if self.sniffer:
            self.sniffer.stop()
        
        self.is_sniffing = False
        self.start_btn.config(text="Start Capture")
        self.status_var.set("● STOPPED")
        self.status_label.config(foreground="#d9534f")
        
        if self.pcap_filename:
            messagebox.showinfo("Capture Saved", f"Packets successfully saved to:\n{self.pcap_filename}")
        
        # Enable inputs
        self.iface_entry.config(state='normal')
        self.filter_entry.config(state='normal')
        self.save_pcap_chk.config(state='normal')

    def update_duration(self):
        if self.is_sniffing:
            elapsed = int(time.time() - self.start_time)
            hours, remainder = divmod(elapsed, 3600)
            minutes, seconds = divmod(remainder, 60)
            self.duration_var.set(f"Time: {hours:02d}:{minutes:02d}:{seconds:02d}")
            self.root.after(1000, self.update_duration)

    def poll_queue(self):
        if not self.is_sniffing:
            return

        # Process up to 50 packets per UI tick to prevent freezing
        for _ in range(50):
            pkt = self.sniffer.get_packet(timeout=0)
            if not pkt:
                break
                
            if "error" in pkt:
                messagebox.showerror("Sniffer Error", pkt["error"])
                self.stop_capture()
                return

            self.packet_count += 1
            
            # Format row data
            proto = pkt.get("l4", {}).get("protocol", pkt.get("l3", {}).get("protocol", "Other"))
            src = pkt.get("l3", {}).get("src_ip", pkt.get("l2", {}).get("src_mac", ""))
            dst = pkt.get("l3", {}).get("dst_ip", pkt.get("l2", {}).get("dst_mac", ""))
            length = pkt.get("length", 0)
            info = pkt.get("summary", "")

            if proto in self.stats:
                self.stats[proto] += 1
            else:
                self.stats["Other"] += 1

            # Keep last 1000 packets in memory to avoid huge memory usage
            if len(self.packets_data) >= 1000:
                self.packets_data.pop(0)
                # Remove the oldest item from the treeview to stay in sync
                oldest_item = self.tree.get_children()[0]
                self.tree.delete(oldest_item)
                
            self.packets_data.append(pkt)

            # Insert into tree with tag for color
            tag = proto if proto in ["TCP", "UDP", "ICMP"] else "Other"
            item_id = self.tree.insert("", tk.END, values=(self.packet_count, proto, src, dst, length, info), tags=(tag,))
            self.tree.yview_moveto(1) # Auto-scroll

        if self.packet_count % 10 == 0:
            self.update_stats_label()

        self.root.after(100, self.poll_queue)

    def on_packet_select(self, event):
        selected_items = self.tree.selection()
        if not selected_items:
            return
            
        item = selected_items[0]
        
        try:
            pkt_num = int(self.tree.item(item, "values")[0])
            offset = self.packet_count - len(self.packets_data)
            idx = pkt_num - 1 - offset
            
            if 0 <= idx < len(self.packets_data):
                pkt = self.packets_data[idx]
                self._display_details(pkt)
            else:
                self._display_details({"info": "Packet data purged from memory buffer."})
        except Exception:
            pass

    def _display_details(self, pkt):
        self.details_text.config(state='normal')
        self.details_text.delete(1.0, tk.END)
        
        formatted = json.dumps(pkt, indent=4)
        self.details_text.insert(tk.END, formatted)
        
        # Simple Syntax Highlighting for JSON
        lines = formatted.split('\n')
        for i, line in enumerate(lines):
            # Highlight keys: "key":
            key_match = re.search(r'^\s*("[^"]+")\s*:', line)
            if key_match:
                start, end = key_match.span(1)
                self.details_text.tag_add("key", f"{i+1}.{start}", f"{i+1}.{end}")
                
            # Highlight string values: : "value"
            val_match = re.search(r':\s*("[^"]+")', line)
            if val_match:
                start, end = val_match.span(1)
                self.details_text.tag_add("string", f"{i+1}.{start}", f"{i+1}.{end}")
                
            # Highlight number values: : 123
            num_match = re.search(r':\s*(\d+)', line)
            if num_match:
                start, end = num_match.span(1)
                self.details_text.tag_add("number", f"{i+1}.{start}", f"{i+1}.{end}")

        self.details_text.config(state='disabled')

def run_gui():
    root = tk.Tk()
    app = GUIApp(root)
    
    def on_closing():
        if app.is_sniffing:
            app.stop_capture()
        root.destroy()
        
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()
