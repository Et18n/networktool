import customtkinter as ctk
from portscanner_copy import ping_function, main, portscannez
from chat import PacketAnalyzer
from traceroute import TracerouteVisualizerApp

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
            'Select Operation:', ['Ping', 'Port Scan', 'Packet Analysis', 'Trace Route'], 
            row=2, command=self.operation_selected
        )


        # tracerot
        self.traceroute_frame = ctk.CTkFrame(self)
        self.traceroute_frame.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)
        self.traceroute_frame.grid_remove()  # Hide until needed


        # Submit Button
        self.submit_btn = ctk.CTkButton(self, text='Submit', command=self.domain_entry, width=200)
        self.submit_btn.grid(row=3, column=0, columnspan=2, pady=10)

        # Results Frame
        self.results_frame = ctk.CTkFrame(self, border_width=2, corner_radius=8)
        self.results_frame.grid(row=4, column=0, columnspan=2, sticky="nsew", padx=10, pady=10)
        self.result_label = ctk.CTkLabel(
            self.results_frame, text="", font=('Arial', 12), wraplength=600, justify="left"
        )
        self.result_label.pack(padx=20, pady=20)

        # Frames for Additional Inputs
        self._create_port_scan_frame()
        self._create_packet_frame()

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

    def operation_selected(self, operation):
        """Show or hide frames based on the selected operation."""
        self.portscan_frame.grid_remove()
        self.packet_frame.grid_remove()

        if operation == 'Port Scan':
            self.portscan_frame.grid()
        elif operation == 'Packet Analysis':
            self.packet_frame.grid()
        elif operation=='Trace Route':
            self.start_trace()

    def start_trace(self):
        target = self.domain.get()  # Get the domain/IP from the entry field
        if not target:
            print("Please enter a valid domain or IP address.")
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

        self.result_label.configure(text="")  # Clear previous results

        if operation == 'Ping':
            self.start_ping()
        elif operation == 'Port Scan':
            self.portscan_frame.grid()
        elif operation == 'Packet Analysis':
            self.start_packet_analysis()
        elif operation == 'Trace Route':
            self.start_trace()

    def start_ping(self):
        self.result_label.configure(text=ping_function(self.target))

    def start_trace(self):
        traceroute_app = TracerouteVisualizerApp(self.target)
        traceroute_app.mainloop()

    def start_port_scan(self, automatic=False):
        
            
        try:
            if automatic:
                result = portscannez(self.target, 0, 10000)  # Automatic scan
            else:
                start_port = int(self.start_port.get())
                end_port = int(self.end_port.get())
                result = portscannez(self.target, start_port, end_port)

            self.result_label.configure(text=result)
        except:
            self.result_label.configure(text="Invalid port range. Please enter valid numbers.")

    def start_packet_analysis(self):
        PacketAnalyzer(self.packet_frame)

if __name__ == '__main__':
    app = App()
    app.mainloop()
