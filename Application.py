import customtkinter as ctk
from portscanner_copy import ping_function, main, portscannez
from chat import PacketAnalyzer
from traceroute import TracerouteVisualizerApp
# Import full module rather than just functions
import arp
from firewall import FirewallApp  # Import the FirewallApp class
import re
import subprocess
import tkinter as tk
from tkinter import messagebox
import sys
import os
import threading
import time
import psutil
from datetime import datetime
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class BandwidthMonitor:
    def __init__(self, parent, notification_callback=None):
        self.parent = parent
        self.notification_callback = notification_callback
        
        # Store previous measurements
        self.prev_io = None
        self.threshold = 100.0  # Default 1 MB/s threshold
        self.alert_active = False
        self.running = True
        
        # Store data for graph
        self.time_data = []
        self.upload_data = []
        self.download_data = []
        self.total_data = []
        self.max_data_points = 60  # 1 minute of data
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_network, daemon=True)
        self.monitor_thread.start()
    
    def set_threshold(self, threshold):
        """Update the bandwidth threshold"""
        try:
            new_threshold = float(threshold)
            if new_threshold <= 0:
                raise ValueError("Threshold must be positive")
            self.threshold = new_threshold
            return True
        except ValueError:
            return False
    
    def convert_bytes(self, bytes_amount):
        """Convert bytes to human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_amount < 1024.0:
                return f"{bytes_amount:.2f} {unit}/s"
            bytes_amount /= 1024.0
        return f"{bytes_amount:.2f} TB/s"
    
    def bytes_to_mb(self, bytes_amount):
        """Convert bytes to MB for threshold comparison"""
        return bytes_amount / (1024 * 1024)
    
    def bytes_to_kb(self, bytes_amount):
        """Convert bytes to KB for graphing"""
        return bytes_amount / 1024
    
    def monitor_network(self):
        """Main monitoring loop"""
        start_time = time.time()
        while self.running:
            try:
                io = psutil.net_io_counters()
                
                if self.prev_io is not None:
                    # Calculate speeds
                    upload_bytes = io.bytes_sent - self.prev_io.bytes_sent
                    download_bytes = io.bytes_recv - self.prev_io.bytes_recv
                    
                    # Calculate total
                    total_bytes = upload_bytes + download_bytes
                    total_mb = self.bytes_to_mb(total_bytes)
                    
                    # Update data for graph
                    current_time = time.time() - start_time
                    self.time_data.append(current_time)
                    self.upload_data.append(self.bytes_to_kb(upload_bytes))
                    self.download_data.append(self.bytes_to_kb(download_bytes))
                    self.total_data.append(self.bytes_to_kb(total_bytes))
                    
                    # Limit data points
                    if len(self.time_data) > self.max_data_points:
                        self.time_data.pop(0)
                        self.upload_data.pop(0)
                        self.download_data.pop(0)
                        self.total_data.pop(0)
                    
                    # Check if we're exceeding threshold
                    if total_mb > self.threshold and not self.alert_active:
                        self.alert_active = True
                        if self.notification_callback:
                            message = f"Network flood detected! Traffic: {self.convert_bytes(total_bytes)}"
                            self.notification_callback(message)
                    elif total_mb <= self.threshold and self.alert_active:
                        self.alert_active = False
                
                self.prev_io = io
            except Exception as e:
                print(f"Error in monitoring: {str(e)}")
            
            time.sleep(1)
    
    def stop(self):
        """Stop the monitoring thread"""
        self.running = False
        if self.monitor_thread.is_alive():
            self.monitor_thread.join(timeout=2)

class BandwidthMonitorUI(ctk.CTkFrame):
    def __init__(self, parent, monitor):
        super().__init__(parent)
        self.monitor = monitor
        
        # Create GUI elements
        self.setup_gui()
    
    def setup_gui(self):
        # Stats frame
        stats_frame = ctk.CTkFrame(self)
        stats_frame.pack(fill="x", padx=10, pady=10)
        
        # Network stats
        self.upload_label = ctk.CTkLabel(stats_frame, text="Upload Speed: waiting for data...",
                                      font=("Helvetica", 12))
        self.download_label = ctk.CTkLabel(stats_frame, text="Download Speed: waiting for data...",
                                        font=("Helvetica", 12))
        self.total_label = ctk.CTkLabel(stats_frame, text="Total Speed: waiting for data...",
                                      font=("Helvetica", 12))
        
        self.upload_label.pack(pady=5, anchor="w")
        self.download_label.pack(pady=5, anchor="w")
        self.total_label.pack(pady=5, anchor="w")
        
        # Alert status
        self.status_label = ctk.CTkLabel(stats_frame, text="Status: Normal",
                                      text_color="green", font=("Helvetica", 14, "bold"))
        self.status_label.pack(pady=10)
        
        # Threshold control
        threshold_frame = ctk.CTkFrame(self)
        threshold_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(threshold_frame, text="Flood Detection Threshold (MB/s):",
                   font=("Helvetica", 12)).pack(side="left", padx=5)
        
        self.threshold_entry = ctk.CTkEntry(threshold_frame, width=80)
        self.threshold_entry.insert(0, str(self.monitor.threshold))
        self.threshold_entry.pack(side="left", padx=5)
        
        update_button = ctk.CTkButton(threshold_frame, text="Update",
                                    command=self.update_threshold)
        update_button.pack(side="left", padx=5)
        
        # Graph frame
        graph_frame = ctk.CTkFrame(self)
        graph_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create matplotlib figure
        self.fig = Figure(figsize=(6, 3), dpi=100)
        self.plot = self.fig.add_subplot(111)
        self.plot.set_title('Network Traffic')
        self.plot.set_xlabel('Time (s)')
        self.plot.set_ylabel('Speed (KB/s)')
        self.plot.grid(True)
        
        # Create canvas to display the figure
        self.canvas = FigureCanvasTkAgg(self.fig, master=graph_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        
        # Start update loop
        self.update_gui()
    
    def update_threshold(self):
        """Update the bandwidth threshold"""
        new_threshold = self.threshold_entry.get()
        if self.monitor.set_threshold(new_threshold):
            messagebox.showinfo("Threshold Updated", f"Bandwidth threshold updated to {new_threshold} MB/s")
        else:
            messagebox.showerror("Invalid Input", "Please enter a positive number for the threshold")
    
    def update_gui(self):
        """Update GUI with current data"""
        if len(self.monitor.time_data) > 0:
            # Get latest values
            latest_upload = self.monitor.upload_data[-1] * 1024  # Convert back to bytes
            latest_download = self.monitor.download_data[-1] * 1024
            latest_total = self.monitor.total_data[-1] * 1024
            
            # Update labels
            self.upload_label.configure(text=f"Upload Speed: {self.monitor.convert_bytes(latest_upload)}")
            self.download_label.configure(text=f"Download Speed: {self.monitor.convert_bytes(latest_download)}")
            self.total_label.configure(text=f"Total Speed: {self.monitor.convert_bytes(latest_total)}")
            
            # Update status
            if self.monitor.alert_active:
                self.status_label.configure(text="Status: TRAFFIC FLOOD DETECTED!", text_color="red")
            else:
                self.status_label.configure(text="Status: Normal", text_color="green")
            
            try:
                # Update graph
                self.plot.clear()
                self.plot.plot(self.monitor.time_data, self.monitor.upload_data, 'g-', label='Upload')
                self.plot.plot(self.monitor.time_data, self.monitor.download_data, 'b-', label='Download')
                self.plot.plot(self.monitor.time_data, self.monitor.total_data, 'r-', label='Total')
                
                # Update graph labels and appearance
                self.plot.set_title('Network Traffic')
                self.plot.set_xlabel('Time (s)')
                self.plot.set_ylabel('Speed (KB/s)')
                self.plot.grid(True)
                self.plot.legend(loc='upper left')
                
                # Set y-axis limits with some headroom
                if self.monitor.total_data:
                    max_value = max(max(self.monitor.total_data), 1)  # Avoid divisions by zero
                    self.plot.set_ylim([0, max_value * 1.2])  # 20% headroom
                
                # Draw the updated plot
                self.canvas.draw()
            except Exception as e:
                print(f"Error updating plot: {str(e)}")
        
        # Schedule next update
        self.after(1000, self.update_gui)

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # App Configuration
        self.title('Network Nexus Application')
        self.geometry(f'{self.winfo_screenwidth()}x{self.winfo_screenheight()}-10-10')
        self._set_appearance_mode('system')  # Use 'light' or 'dark' for testing if needed.
        self.state('normal')

        # Set grid configuration for responsiveness
        self.grid_rowconfigure(4, weight=1)  # Allow results frame to expand.
        self.grid_columnconfigure((0, 1), weight=1)  # Balance column widths.

        # Initialize bandwidth monitor
        self.bandwidth_monitor = BandwidthMonitor(self, self.show_notification)

        # Title
        ctk.CTkLabel(
            self, text='🌐 Welcome to the Network Nexus 🌐', 
            font=('Arial', 28, 'bold'), 
            fg_color='transparent'
        ).grid(row=0, column=0, columnspan=2, pady=20)

        # Domain/IP Entry Section
        self._create_label_and_entry('Select Domain/IP Address:', row=1, placeholder='e.g., google.com')

        # Operation Selection
        self._create_label_and_option_menu(
            'Select Operation:', ['Ping', 'Port Scan', 'Packet Analysis', 'Trace Route', 'ARP Spoof', 'Firewall', 'Bandwidth Monitor'], 
            row=2, command=self.operation_selected
        )

        # Traceroute Frame
        self.traceroute_frame = ctk.CTkFrame(self)
        self.traceroute_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)
        self.traceroute_frame.grid_remove()  # Hide until needed

        # Submit Button
        self.submit_btn = ctk.CTkButton(self, text='Submit', command=self.domain_entry, width=200)
        self.submit_btn.grid(row=3, column=0, columnspan=2, pady=10)

        # Results Frame
        self.results_frame = ctk.CTkFrame(self, border_width=2, corner_radius=8)
        self.results_frame.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)
        self.result_textbox = ctk.CTkTextbox(self.results_frame, wrap="word", state="disabled", font=('Courier New', 12))
        self.result_textbox.pack(fill="both", expand=True, padx=20, pady=20)

        # Frames for Additional Inputs
        self._create_port_scan_frame()
        self._create_packet_frame()
        self._create_bandwidth_monitor_frame()
        
        # Store reference to the packet analyzer instance
        self.packet_analyzer_instance = None
        
        # Store references to external windows
        self.arp_spoof_window = None
        self.firewall_window = None

    def _create_label_and_entry(self, text, row, placeholder):
        ctk.CTkLabel(self, text=text, font=('Arial', 14)).grid(row=row, column=0, sticky="w", padx=10, pady=5)
        entry = ctk.CTkEntry(self, placeholder_text=placeholder)
        entry.grid(row=row, column=1, padx=10, pady=5)
        if row == 1:  # Store domain entry specifically for later use.
            self.domain = entry

    def _create_label_and_option_menu(self, text, options, row, command):
        ctk.CTkLabel(self, text=text, font=('Arial', 14)).grid(row=row, column=0, sticky="w", padx=10, pady=5)
        option_menu = ctk.CTkOptionMenu(self, values=options, command=command)
        option_menu.grid(row=row, column=1, padx=10, pady=5)
        if row == 2:  # Store operation menu for later use.
            self.operation = option_menu

    def _create_port_scan_frame(self):
        self.portscan_frame = ctk.CTkFrame(self, border_width=2, corner_radius=8)
        self.portscan_frame.grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.portscan_frame.grid_remove()

        ctk.CTkLabel(self.portscan_frame, text='Select Port Scan Type:').grid(row=0, column=0, padx=10, pady=5)
        self.portscan_option_select = ctk.CTkOptionMenu(
            self.portscan_frame, values=['Automatic', 'Manual'], command=self.frame_generation
        )
        self.portscan_option_select.grid(row=0, column=1, padx=10, pady=5)

        self._create_port_range_frame()

    def _create_port_range_frame(self):
        self.port_range_frame = ctk.CTkFrame(self.portscan_frame, border_width=1, corner_radius=8)
        self.port_range_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.port_range_frame.grid_remove()

        ctk.CTkLabel(self.port_range_frame, text='Enter Start and End Ports:').grid(
            row=0, column=0, columnspan=2, padx=10, pady=5
        )
        self.start_port = ctk.CTkEntry(self.port_range_frame, placeholder_text='Start Port')
        self.start_port.grid(row=1, column=0, padx=10, pady=5)
        self.end_port = ctk.CTkEntry(self.port_range_frame, placeholder_text='End Port')
        self.end_port.grid(row=1, column=1, padx=10, pady=5)

        self.scan_btn = ctk.CTkButton(
            self.port_range_frame, text='Start Scan', command=self.start_port_scan, width=100
        )
        self.scan_btn.grid(row=2, column=0, columnspan=2, pady=10)

    def _create_packet_frame(self):
        self.packet_frame = ctk.CTkFrame(self, border_width=2, corner_radius=8)
        self.packet_frame.grid(row=6, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.packet_frame.grid_remove()

    def _create_bandwidth_monitor_frame(self):
        self.bandwidth_frame = ctk.CTkFrame(self, border_width=2, corner_radius=8)
        self.bandwidth_frame.grid(row=7, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.bandwidth_frame.grid_remove()
        
        # Create bandwidth monitor UI
        self.bandwidth_ui = BandwidthMonitorUI(self.bandwidth_frame, self.bandwidth_monitor)
        self.bandwidth_ui.pack(fill="both", expand=True)

    def operation_selected(self, operation):
        """Show or hide frames based on the selected operation."""
        self.portscan_frame.grid_remove()
        self.packet_frame.grid_remove()
        self.traceroute_frame.grid_remove()
        self.bandwidth_frame.grid_remove()

        # Store the operation but don't launch yet
        self.current_operation = operation

        if operation == 'Port Scan':
            self.portscan_frame.grid()
        elif operation == 'Packet Analysis':
            self.packet_frame.grid()
        elif operation == 'Trace Route':
            self.start_trace()
        # Remove immediate launching for ARP Spoof and Firewall
        # These will be launched only on Submit button click
        elif operation == 'Bandwidth Monitor':
            self.bandwidth_frame.grid()

    def show_notification(self, message):
        """Show notification when network flood is detected"""
        self.result_textbox.configure(state="normal")
        self.result_textbox.insert("end", f"⚠️ ALERT: {message}\n")
        self.result_textbox.configure(state="disabled")
        
        # Create a popup notification
        messagebox.showwarning("Network Flood Alert", message)

    def start_trace(self):
        target = self.domain.get()  # Get the domain/IP from the entry field
        if not target:
            self.append_result("Please enter a valid domain or IP address.")
            return

        # Clear the traceroute frame before adding new content
        for widget in self.traceroute_frame.winfo_children():
            widget.destroy()

        # Create and display the TracerouteVisualizerApp in the frame
        traceroute_app = TracerouteVisualizerApp(self.traceroute_frame, target)
        traceroute_app.pack(fill="both", expand=True)

        self.traceroute_frame.grid()  # Show the frame

    def frame_generation(self, mode):
        """Show port range inputs only if manual mode is selected."""
        if mode == 'Manual':
            self.port_range_frame.grid()
        else:
            self.port_range_frame.grid_remove()
            self.start_port_scan(automatic=True)

    def domain_entry(self):
        """Handle the operation selected by the user."""
        self.target = self.domain.get()
        operation = self.operation.get()

        self.result_textbox.configure(state="normal")
        self.result_textbox.delete("1.0", "end")  # Clear previous results
        self.result_textbox.configure(state="disabled")

        if operation == 'Ping':
            self.start_ping()
        elif operation == 'Port Scan':
            self.portscan_frame.grid()
        elif operation == 'Packet Analysis':
            self.start_packet_analysis()
        elif operation == 'Trace Route':
            self.start_trace()
        elif operation == 'ARP Spoof':
            self.launch_arp_spoof()
        elif operation == 'Firewall':
            self.launch_firewall()
        elif operation == 'Bandwidth Monitor':
            self.bandwidth_frame.grid()

    def start_ping(self):
        result = ping_function(self.target)
        self.append_result(result)

    def start_port_scan(self, automatic=False):
        try:
            if automatic:
                result = portscannez(self.target, 0, 10000)  # Automatic scan
            else:
                start_port = int(self.start_port.get())
                end_port = int(self.end_port.get())
                result = portscannez(self.target, start_port, end_port)

            # Convert the result dictionary to a string
            result_str = "\n".join([f"Port {port}: {protocols}" for port, protocols in result.items()])
            self.append_result(result_str)
        except ValueError:
            self.append_result("Invalid port range. Please enter valid numbers.")

    def start_packet_analysis(self):
        # Store reference to the packet analyzer for IP search functionality
        self.packet_analyzer_instance = PacketAnalyzer(self.packet_frame)

    def append_result(self, text):
        self.result_textbox.configure(state="normal")
        self.result_textbox.delete("1.0", "end")  # Clear previous results
        self.result_textbox.insert("end", text + "\n")
        self.result_textbox.configure(state="disabled")

    def launch_arp_spoof(self):
        """Launch ARP Spoofing tool in a separate window"""
        if not hasattr(self, 'arp_spoof_window') or self.arp_spoof_window is None or not self.arp_spoof_window.winfo_exists():
            # Create a new subprocess instead of trying to embed the ARP tool in a toplevel window
            import subprocess
            import sys
            import os
            
            try:
                # Launch arp.py as a separate process
                arp_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "arp.py")
                subprocess.Popen([sys.executable, arp_path])
                self.append_result("ARP Spoofing tool launched in a new window.")
            except Exception as e:
                self.append_result(f"Error launching ARP Spoofing tool: {str(e)}")
        else:
            self.arp_spoof_window.lift()  # Bring window to front if it already exists
            self.append_result("ARP Spoofing tool window is already open.")

    def launch_firewall(self):
        """Launch Firewall tool in a separate window"""
        import subprocess
        import sys
        import os
        
        try:
            # Launch firewall.py as a separate process
            firewall_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firewall.py")
            subprocess.Popen([sys.executable, firewall_path])
            self.append_result("Firewall tool launched in a new window.")
        except Exception as e:
            self.append_result(f"Error launching firewall: {str(e)}")
            
    def on_close(self):
        """Clean up before closing"""
        self.bandwidth_monitor.stop()
        self.destroy()

if __name__ == '__main__':
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_close)  # Handle cleanup on close
    app.mainloop()
