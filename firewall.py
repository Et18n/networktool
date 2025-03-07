import customtkinter as ctk
import subprocess
import tkinter as tk
from tkinter import messagebox

class FirewallApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window setup
        self.title("Firewall Control")
        self.geometry("400x300")

        # Create GUI elements
        self.create_gui()

    def create_gui(self):
        # Main frame
        main_frame = ctk.CTkFrame(self)
        main_frame.pack(padx=10, pady=10, fill="both", expand=True)

        # IP address entry
        ip_label = ctk.CTkLabel(main_frame, text="IP Address:")
        ip_label.pack(pady=5)
        
        self.ip_entry = ctk.CTkEntry(main_frame)
        self.ip_entry.pack(pady=5)

        # Block button
        block_button = ctk.CTkButton(main_frame, text="Block IP", command=self.block_ip)
        block_button.pack(pady=5)

        # Unblock button
        unblock_button = ctk.CTkButton(main_frame, text="Unblock IP", command=self.unblock_ip)
        unblock_button.pack(pady=5)

        # Show rules button
        show_rules_button = ctk.CTkButton(main_frame, text="Show Firewall Rules", command=self.show_firewall_rules)
        show_rules_button.pack(pady=5)

    def block_ip(self):
        ip_address = self.ip_entry.get()
        if ip_address:
            try:
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule", 
                                f"name=Block_{ip_address}", "dir=in", "action=block", 
                                f"remoteip={ip_address}"], check=True)
                messagebox.showinfo("Success", f"IP {ip_address} has been blocked.")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to block IP {ip_address}: {str(e)}")
        else:
            messagebox.showwarning("Input Error", "Please enter a valid IP address.")

    def unblock_ip(self):
        ip_address = self.ip_entry.get()
        if ip_address:
            try:
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", 
                                f"name=Block_{ip_address}"], check=True)
                messagebox.showinfo("Success", f"IP {ip_address} has been unblocked.")
            except subprocess.CalledProcessError as e:
                messagebox.showerror("Error", f"Failed to unblock IP {ip_address}: {str(e)}")
        else:
            messagebox.showwarning("Input Error", "Please enter a valid IP address.")

    def show_firewall_rules(self):
        self.rules_window = ctk.CTkToplevel(self)
        self.rules_window.title("Firewall Rules")
        self.rules_window.geometry("600x400")

        filter_label = ctk.CTkLabel(self.rules_window, text="Filter (rule name or IP):")
        filter_label.pack(pady=5)

        self.filter_entry = ctk.CTkEntry(self.rules_window)
        self.filter_entry.pack(pady=5)

        refresh_button = ctk.CTkButton(self.rules_window, text="Refresh", command=self.refresh_firewall_rules)
        refresh_button.pack(pady=5)

        self.rules_text = ctk.CTkTextbox(self.rules_window)
        self.rules_text.pack(fill="both", expand=True, padx=10, pady=10)

        self.refresh_firewall_rules()

    def refresh_firewall_rules(self):
        filter_value = self.filter_entry.get()
        filter_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
        if filter_value:
            filter_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={filter_value}"]

        try:
            result = subprocess.run(filter_cmd, capture_output=True, text=True, check=True)
            rules = result.stdout

            self.rules_text.configure(state="normal")
            self.rules_text.delete("1.0", "end")
            self.rules_text.insert("1.0", rules)
            self.rules_text.configure(state="disabled")
        except subprocess.CalledProcessError as e:
            messagebox.showerror("Error", f"Failed to retrieve firewall rules: {str(e)}")

if __name__ == "__main__":
    app = FirewallApp()
    app.mainloop()