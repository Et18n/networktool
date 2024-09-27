import scapy.all as scp
import os
import scapy.arch.windows as scpwinarch
import threading
import hashlib
import socket
import customtkinter as ctk  # Use CTk components for theming consistency


class PacketAnalyzer(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.grid(padx=20, pady=20)  # Padding to ensure a clean layout

        self.suspiciouspackets = []
        self.sus_readablepayloads = []
        self.source_ip_counts = {}
        self.updatepktlist = False
        self.running = False

        # Load and process the rules from rules.txt
        self.rules_list = self.read_rules()
        self.process_rules(self.rules_list)

        # Create GUI components using CTk for a consistent UI
        self.label1 = ctk.CTkLabel(self, text="All Packets:", anchor="w")
        self.label1.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        
        self.listbox1 = ctk.CTkTextbox(self, height=200, width=500)  # Using Textbox instead of Listbox for CTk
        self.listbox1.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        self.label2 = ctk.CTkLabel(self, text="Suspicious Packets:", anchor="w")
        self.label2.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        
        self.listbox2 = ctk.CTkTextbox(self, height=200, width=500)
        self.listbox2.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        # Buttons with a consistent color and style
        self.start_button = ctk.CTkButton(self, text="Start Capture", command=self.start_capture, fg_color="green")
        self.start_button.grid(row=2, column=0, padx=10, pady=10, sticky="w")

        self.stop_button = ctk.CTkButton(self, text="Stop Capture", command=self.stop_capture, fg_color="red")
        self.stop_button.grid(row=2, column=1, padx=10, pady=10, sticky="w")

        self.show_counts_button = ctk.CTkButton(self, text="Show Source IP Counts", command=self.show_source_ip_counts)
        self.show_counts_button.grid(row=3, column=0, padx=10, pady=10, sticky="w")

        # Sniffing thread
        self.sniffthread = threading.Thread(target=self.sniff_thread)

    def read_rules(self):
        """Read rules from the rules.txt file."""
        script_dir = os.path.dirname(__file__)
        rulefile = os.path.join(script_dir, 'rules.txt')
        rules_list = []
        with open(rulefile, "r") as rf:
            for line in rf:
                if line.startswith("alert"):
                    rules_list.append(line.strip())
        return rules_list

    def process_rules(self, rulelist):
        """Process rules into usable formats."""
        self.alertprotocols = []
        self.alertdestips = []
        self.alertsrcips = []
        self.alertsrcports = []
        self.alertdestports = []
        self.alertmsg = []

        for rule in rulelist:
            rulewords = rule.split()
            self.alertprotocols.append(rulewords[1] if rulewords[1] != "any" else "any")
            self.alertsrcips.append(rulewords[2] if rulewords[2] != "any" else "any")
            self.alertsrcports.append(int(rulewords[3]) if rulewords[3] != "any" else "any")
            self.alertdestips.append(rulewords[5] if rulewords[5] != "any" else "any")
            self.alertdestports.append(rulewords[6] if rulewords[6] != "any" else "any")
            self.alertmsg.append(" ".join(rulewords[7:]) if len(rulewords) > 7 else "")

    def sniff_thread(self):
        scp.sniff(prn=self.pkt_process, filter="", store=False, stop_filter=lambda x: not self.running)

    def pkt_process(self, pkt):
        """Process each packet, and check if it matches any of the rules."""
        if not self.running:
            return

        # Add packet summary to the listbox
        pkt_summary = pkt.summary()
        self.listbox1.insert("end", f"{pkt_summary}\n")  # Insert summary in Textbox

        # Check if the packet matches any rules
        is_suspicious, rule_msg = self.check_rules_warning(pkt)
        if is_suspicious:
            suspicious_summary = f"{pkt_summary} - {rule_msg}"
            self.suspiciouspackets.append(suspicious_summary)
            self.listbox2.insert("end", f"{suspicious_summary}\n")  # Insert suspicious packets in Textbox

    def check_rules_warning(self, pkt):
        """Check if the packet violates any of the defined rules."""
        if 'IP' in pkt:
            src_ip = pkt['IP'].src
            dest_ip = pkt['IP'].dst
            proto = self.proto_name_by_num(pkt['IP'].proto).lower()
            sport = pkt['IP'].sport if 'sport' in pkt['IP'].fields else "any"
            dport = pkt['IP'].dport if 'dport' in pkt['IP'].fields else "any"

            for i in range(len(self.alertprotocols)):
                if ((self.alertprotocols[i] == proto or self.alertprotocols[i] == "any") and
                    (self.alertsrcips[i] == src_ip or self.alertsrcips[i] == "any") and
                    (self.alertdestips[i] == dest_ip or self.alertdestips[i] == "any") and
                    (self.alertsrcports[i] == sport or self.alertsrcports[i] == "any") and
                    (self.alertdestports[i] == dport or self.alertdestports[i] == "any")):
                    return True, self.alertmsg[i]
        return False, ""

    def proto_name_by_num(self, proto_num):
        """Convert protocol number to name."""
        for name, num in vars(socket).items():
            if name.startswith("IPPROTO") and proto_num == num:
                return name[8:]
        return "Unknown"

    def start_capture(self):
        """Start packet sniffing."""
        self.running = True
        self.listbox1.delete("1.0", "end")  # Clear previous entries
        if not self.sniffthread.is_alive():
            self.sniffthread.start()

    def stop_capture(self):
        """Stop packet sniffing."""
        self.running = False

    def show_source_ip_counts(self):
        """Print source IP counts."""
        for src_ip, count in self.source_ip_counts.items():
            print(f"Source IP: {src_ip}, Count: {count}")
