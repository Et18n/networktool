import scapy.all as scp
import threading
import socket
import customtkinter as ctk
from scapy.layers.inet import IP, TCP, UDP

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
        self.captured_packets = []
        self.suspiciouspackets = []
        self.updatepktlist = False
        self.running = False

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
        self.listbox2.bind("<Double-1>", self.on_double_click)

        # Buttons
        self.start_button = ctk.CTkButton(self, text="Start Capture", command=self.start_capture, fg_color="green")
        self.start_button.grid(row=2, column=0, padx=10, pady=10, sticky="w")

        self.stop_button = ctk.CTkButton(self, text="Stop Capture", command=self.stop_capture, fg_color="red")
        self.stop_button.grid(row=2, column=1, padx=10, pady=10, sticky="w")

        self.refresh_button = ctk.CTkButton(self, text="Refresh Rules", command=self.refresh_rules, fg_color="yellow")
        self.refresh_button.grid(row=3, column=0, padx=10, pady=10, sticky="w")

        # Sniffing thread
        self.sniffthread = threading.Thread(target=self.sniff_thread, daemon=True)

    def sniff_thread(self):
        scp.sniff(prn=self.pkt_process, filter="", store=False, stop_filter=lambda x: not self.running)

    def pkt_process(self, pkt):
        """Process each packet and display summary."""
        if not self.running:
            return
        self.captured_packets.append(pkt)
        pkt_summary = pkt.summary()
        self.listbox1.insert("end", f"{pkt_summary}\n")  # Insert packet summary in listbox1

        # Check if the packet is suspicious based on predefined rules
        flagged, msg = self.check_rules_warning(pkt)
        if flagged:
            self.listbox2.configure(state="normal")  # Ensure listbox2 is editable
            self.listbox2.insert("end", f"{pkt_summary} - {msg}\n")
            self.listbox2.configure(state="disabled")  # Make it read-only after insertion
            self.suspiciouspackets.append(pkt)  # Add suspicious packet to the list

    def start_capture(self):
        self.running = True
        self.listbox1.delete("1.0", "end")  # Clear previous entries
        self.listbox2.delete("1.0", "end")  # Clear suspicious packets listbox
        if not self.sniffthread.is_alive():
            self.sniffthread.start()

    def stop_capture(self):
        self.running = False

    def refresh_rules(self):
        process_rules(readrules())
        

    def on_double_click(self, event):
        try:
            # Identify which listbox was clicked (all packets or suspicious packets)
            widget = event.widget

            # Get the index of the clicked line
            clicked_index = widget.index(f"@{event.x},{event.y}").split('.')[0]

            # Retrieve the packet summary from the listbox
            clicked_summary = widget.get(f"{clicked_index}.0", f"{clicked_index}.end").strip()

            # Search for the packet in the suspicious packets list or all captured packets
            packet_list = (
                self.suspiciouspackets if widget == self.listbox2 else self.captured_packets
            )

            # Find the matching packet and display details
            for pkt in packet_list:
                if pkt.summary().strip() == clicked_summary:
                    self.show_packet_details(pkt)  # Pass the packet object
                    break
        except Exception as e:
            print(f"Error: {e}")


    def check_rules_warning(self, pkt):
        if 'IP' in pkt:
            try:
                src = pkt['IP'].src
                dest = pkt['IP'].dst
                proto = self.proto_name_by_num(pkt['IP'].proto).lower()
                sport = pkt.sport
                dport = pkt.dport

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

        return False, ""

    def proto_name_by_num(self, proto_num):
        """Convert a protocol number to its protocol name."""
        for name, num in vars(socket).items():
            if name.startswith("IPPROTO") and proto_num == num:
                return name[8:]  # Return the protocol name (without 'IPPROTO' prefix)
        return "Unknown"
    
    def show_packet_details(self, packet):
        """Display detailed packet information in a new window."""
        window = ctk.CTkToplevel(self)
        window.title("Packet Details")
        window.geometry("400x300")
        window.grab_set()

        # Recursively collect all layers and their details
        packet_details = self.inspect_packet(packet)

        # Create a textbox to display the packet details
        textbox = ctk.CTkTextbox(window, height=290, width=390)
        textbox.grid(padx=10, pady=10)

        textbox.insert("1.0", packet_details)  # Insert packet details
        textbox.configure(state="disabled")  # Make the textbox read-only

    def inspect_packet(self, packet):
        """Recursively collect details from all layers of the packet."""
        details = []

        # Iterate over all layers of the packet
        while packet:
            details.append(packet.show(dump=True))  # Collect details for this layer
            packet = packet.payload  # Move to the next layer

        return "\n".join(details)  # Combine all layer details


    
if __name__ == "__main__":
    root = ctk.CTk()
    root.title("Packet Analyzer")
    root.geometry("1100x600")
    PacketAnalyzer(root)
    root.mainloop()
