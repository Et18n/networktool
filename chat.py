import scapy.all as scp
import threading
import socket
import customtkinter as ctk

# Function to read rules from a file
def readrules():
    rulefile = "rules.txt"
    ruleslist = []
    with open(rulefile, "r") as rf:
        ruleslist = rf.readlines()
    rules_list = []
    for line in ruleslist:
        if line.startswith("alert"):
            rules_list.append(line)
    return rules_list

# Global lists for alert protocols and messages
alertprotocols = []
alertdestips = []
alertsrcips = []
alertsrcports = []
alertdestports = []
alertmsg = []

# Function to process rules
def process_rules(rulelist):
    global alertprotocols, alertdestips, alertsrcips, alertsrcports, alertdestports, alertmsg
    alertprotocols = []
    alertdestips = []
    alertsrcips = []
    alertsrcports = []
    alertdestports = []
    alertmsg = []

    for rule in rulelist:
        rulewords = rule.split()
        alertprotocols.append(rulewords[1].lower() if rulewords[1] != "any" else "any")
        alertsrcips.append(rulewords[2].lower() if rulewords[2] != "any" else "any")
        alertsrcports.append(int(rulewords[3]) if rulewords[3] != "any" else "any")
        alertdestips.append(rulewords[5].lower() if rulewords[5] != "any" else "any")
        alertdestports.append(rulewords[6] if rulewords[6] != "any" else "any")
        alertmsg.append(" ".join([rulewords[x] for x in range(7, len(rulewords))]) if len(rulewords) > 7 else "")

process_rules(readrules())

# Packet Analyzer Class
class PacketAnalyzer(ctk.CTkFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.grid(padx=20, pady=20)

        self.suspiciouspackets = []
        self.updatepktlist = False
        self.running = False
        self.sus_readablepayloads = []

        # Create GUI components
        self.label1 = ctk.CTkLabel(self, text="All Packets:", anchor="w")
        self.label1.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.listbox1 = ctk.CTkTextbox(self, height=200, width=500)
        self.listbox1.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.listbox1.bind("<Double-1>", self.on_double_click)

        self.label2 = ctk.CTkLabel(self, text="Suspicious Packets:", anchor="w")
        self.label2.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        self.listbox2 = ctk.CTkTextbox(self, height=200, width=500)
        self.listbox2.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        # Buttons
        self.start_button = ctk.CTkButton(self, text="Start Capture", command=self.start_capture, fg_color="green")
        self.start_button.grid(row=2, column=0, padx=10, pady=10, sticky="w")

        self.stop_button = ctk.CTkButton(self, text="Stop Capture", command=self.stop_capture, fg_color="red")
        self.stop_button.grid(row=2, column=1, padx=10, pady=10, sticky="w")

        self.count_button = ctk.CTkButton(self, text="Show Counts", command=self.show_counts, fg_color="blue")
        self.count_button.grid(row=3, column=0, padx=10, pady=10, sticky="w")

        self.refresh_button = ctk.CTkButton(self, text="Refresh Rules", command=self.refresh_rules, fg_color="orange")
        self.refresh_button.grid(row=3, column=1, padx=10, pady=10, sticky="w")

        # Sniffing thread
        self.sniffthread = threading.Thread(target=self.sniff_thread, daemon=True)

    def sniff_thread(self):
        scp.sniff(prn=self.pkt_process, filter="", store=False, stop_filter=lambda x: not self.running)

    def pkt_process(self, pkt):
        """Process each packet and display summary."""
        if not self.running:
            return

        pkt_summary = pkt.summary()
        self.listbox1.insert("end", f"{pkt_summary}\n")  # Insert packet summary in listbox1

        # Check if the packet is suspicious based on predefined rules
        flagged, msg = self.check_rules_warning(pkt)
        if flagged:
            self.listbox2.configure(state="normal")  # Ensure listbox2 is editable
            self.listbox2.insert("end", f"{pkt_summary} - {msg}\n")
            self.listbox2.configure(state="disabled")  # Make it read-only after insertion
            self.listbox2.update()  # Force the UI to update
            self.suspiciouspackets.append(pkt)  # Add suspicious packet to the list

    def start_capture(self):
        """Start packet sniffing."""
        self.running = True
        self.listbox1.delete("1.0", "end")  # Clear previous entries
        self.listbox2.delete("1.0", "end")  # Clear suspicious packets listbox
        if not self.sniffthread.is_alive():
            self.sniffthread.start()

    def stop_capture(self):
        """Stop packet sniffing."""
        self.running = False

    def show_counts(self):
        """Show the counts of suspicious packets."""
        count = len(self.suspiciouspackets)
        ctk.CTkMessageBox.show_info("Suspicious Packets Count", f"Total suspicious packets: {count}")

    def refresh_rules(self):
        """Refresh the rules from the rules file."""
        process_rules(readrules())
        ctk.CTkMessageBox.show_info("Rules Updated", "The rules have been refreshed successfully.")

    def on_double_click(self, event):
        try:
            # Get the index of the clicked line based on mouse position
            clicked_line_index = self.listbox1.index(f"@{event.x},{event.y}").split('.')[0]
            # Get the entire line content
            clicked_packet_summary = self.listbox1.get(f"{clicked_line_index}.0", f"{clicked_line_index}.end").strip()
            # Show packet details in a new window
            if clicked_packet_summary:
                self.show_packet_details(clicked_packet_summary)
        except Exception as e:
            print(f"Error: {e}")

    def check_rules_warning(self, pkt):
        """Check packet against predefined suspicious rules."""
        process_rules(readrules())  # Process the rules again if necessary

        if 'IP' in pkt:
            try:
                src = pkt['IP'].src
                dest = pkt['IP'].dst
                proto = self.proto_name_by_num(pkt['IP'].proto).lower()
                sport = pkt['IP'].sport
                dport = pkt['IP'].dport

                for i in range(len(alertprotocols)):
                    chkproto = alertprotocols[i] if alertprotocols[i] != "any" else proto
                    chkdestip = alertdestips[i] if alertdestips[i] != "any" else dest
                    chksrcip = alertsrcips[i] if alertsrcips[i] != "any" else src
                    chksrcport = alertsrcports[i] if alertsrcports[i] != "any" else sport
                    chkdestport = alertdestports[i] if alertdestports[i] != "any" else dport

                    # Matching packet fields with rule
                    if (str(src).strip() == str(chksrcip).strip() and
                        str(dest).strip() == str(chkdestip).strip() and
                        str(proto).strip() == str(chkproto).strip() and
                        str(dport).strip() == str(chkdestport).strip() and
                        str(sport).strip() == str(chksrcport).strip()):
                        return True, str(alertmsg[i])
            except Exception as ex:
                print(f"Error in check_rules_warning: {ex}")
                pkt.show()

        return False, ""

    def proto_name_by_num(self, proto_num):
        """Convert a protocol number to its protocol name."""
        for name, num in vars(socket).items():
            if name.startswith("IPPROTO") and proto_num == num:
                return name[8:]  # Return the protocol name (without 'IPPROTO' prefix)
        return "Unknown"
    def analyze_packet_details(packet):
        details = []

        # Ethernet Frame
        details.append("Ethernet Frame:")
        details.append(f"  Src MAC: {packet[Ether].src}")
        details.append(f"  Dst MAC: {packet[Ether].dst}")
        details.append(f"  Ethernet Type: {packet[Ether].type}")

        # IP Header
        if packet.haslayer(IP):
            details.append("\nIP Header:")
            details.append(f"  Src IP: {packet[IP].src}")
            details.append(f"  Dst IP: {packet[IP].dst}")
            details.append(f"  IP Protocol: {packet[IP].proto}")
            details.append(f"  TTL: {packet[IP].ttl}")

        # TCP Header
        if packet.haslayer(TCP):
            details.append("\nTCP Header:")
            details.append(f"  Src Port: {packet[TCP].sport}")
            details.append(f"  Dst Port: {packet[TCP].dport}")
            details.append(f"  Flags: {packet[TCP].flags}")
            details.append(f"  Seq: {packet[TCP].seq}")
            details.append(f"  Ack: {packet[TCP].ack}")

        # UDP Header
        elif packet.haslayer(UDP):
            details.append("\nUDP Header:")
            details.append(f"  Src Port: {packet[UDP].sport}")
            details.append(f"  Dst Port: {packet[UDP].dport}")
            details.append(f"  Len: {packet[UDP].len}")

        # ICMP Header
        elif packet.haslayer(ICMP):
            details.append("\nICMP Header:")
            details.append(f"  Type: {packet[ICMP].type}")
            details.append(f"  Code: {packet[ICMP].code}")
            details.append(f"  Seq: {packet[ICMP].seq}")

        # Packet Payload
        if packet.haslayer(Raw):
            details.append("\nPacket Payload:")
            details.append(packet[Raw].load.decode(errors='ignore'))  # Decode the payload, ignore errors

        return "\n".join(details)
    def show_packet_details(self, packet_summary):
        """Display detailed information about the selected packet in a new window."""
        packet_details_window = ctk.CTkToplevel(self)
        packet_details_window.title("Packet Details")
        packet_details_window.geometry("400x300")
        packet_details_window.grab_set()

        # Find the clicked packet in the suspicious packets list
        for pkt in self.suspiciouspackets:
            if pkt.summary() == packet_summary:
                details_text = self.analyze_packet_details(pkt)  # Analyze the packet
                break
        else:
            details_text = "No detailed information available."

        # Display packet details in a textbox
        packet_details_text = ctk.CTkTextbox(packet_details_window, height=20, width=60)
        packet_details_text.grid(padx=10, pady=10)
        packet_details_text.insert("1.0", details_text)
        packet_details_text.configure(state="disabled") 
if __name__ == "__main__":
    # Create the main application window
    root = ctk.CTk()
    root.title("Packet Analyzer")
    root.geometry("800x600")

    # Initialize Packet Analyzer
    packet_analyzer = PacketAnalyzer(root)

    # Start the main loop
    root.mainloop()
