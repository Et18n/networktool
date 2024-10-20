import customtkinter as ctk
from portscanner_copy import ping_function, main, portscannez
from chat import PacketAnalyzer

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title('Network Utility Application')
        self.geometry(f'{self.winfo_screenwidth()}x{self.winfo_screenheight()}+0+0')
        self._set_appearance_mode('system')

        # Title
        ctk.CTkLabel(self, text='Welcome to the Network Utility', font=('Arial', 24, 'bold')).grid(row=0, column=0, columnspan=2, padx=10, pady=20)

        # Domain/IP Entry
        ctk.CTkLabel(self, text='Select Domain/IP Address:', font=('Arial', 14)).grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.domain = ctk.CTkOptionMenu(self, values=[ 'google.com', 'facebook.com', 'xavier.ac.in','localhost'])
        self.domain.grid(row=1, column=1, padx=10, pady=5)

        # Operation Selection
        ctk.CTkLabel(self, text='Select Operation:', font=('Arial', 14)).grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.operation = ctk.CTkOptionMenu(self, values=['Ping', 'Port Scan', 'Packet Analysis','Trace Route    '], fg_color='grey', button_color='grey')
        self.operation.grid(row=2, column=1, padx=10, pady=5)

        # Submit Button
        self.submit_btn = ctk.CTkButton(self, text='Submit', command=self.domain_entry)
        self.submit_btn.grid(row=3, column=0, columnspan=2, pady=20)

        # Results Frame
        self.results_frame = ctk.CTkFrame(self)
        self.results_frame.grid(row=4, column=0, columnspan=2   , padx=10, pady=20, sticky="nsew")

        self.result_label = ctk.CTkLabel(self.results_frame, text="", font=('Arial', 12), wraplength=600, justify="left")
        self.result_label.grid(pady=10)

        self.port_range_frame = ctk.CTkFrame(self)
        self.port_range_frame.grid(row=5, column=0, columnspan=2, pady=10, sticky="nsew")
        self.port_range_frame.grid_remove()  # Hide initially

        ctk.CTkLabel(self.port_range_frame, text='Enter start and end ports:').grid(row=0, column=0, columnspan=2, padx=10, pady=5)
        self.start_port = ctk.CTkEntry(self.port_range_frame, placeholder_text='Start Port')
        self.start_port.grid(row=1, column=0, padx=10, pady=5)
        self.end_port = ctk.CTkEntry(self.port_range_frame, placeholder_text='End Port')
        self.end_port.grid(row=1, column=1, padx=10, pady=5)

        self.scan_btn = ctk.CTkButton(self.port_range_frame, text='Start Scan', command=self.start_port_scan)
        self.scan_btn.grid(row=2, column=0, columnspan=2, pady=10)

        # Packet Analyzer Frame (hidden by default)
        self.packet_frame = ctk.CTkFrame(self)
        self.packet_frame.grid(row=5, column=0, columnspan=2, pady=10, sticky="nsew")
        self.packet_frame.grid_remove()

    def domain_entry(self):
        self.target = self.domain.get()
        self.operation_descision = self.operation.get()

        # Clear previous results
        self.result_label.configure(text="")

        if self.operation_descision == 'Ping':
            self.start_ping()
        elif self.operation_descision == 'Port Scan':
            self.port_range_frame.grid()
            self.start_port_scan()
        elif self.operation_descision == 'Packet Analysis':
            self.start_packet_analysis()

    def start_ping(self):
        self.result_label.configure(text=ping_function(self.target))

    def start_port_scan(self):
        try:
            start_port = int(self.start_port.get())
            end_port = int(self.end_port.get())
            result = portscannez(self.target, start_port, end_port)
            self.result_label.configure(text=result)
        except ValueError:
            self.display_result("Invalid port range. Please enter valid numbers.")

    def start_packet_analysis(self):
        self.packet_frame.grid()  # Show the packet analyzer frame
        PacketAnalyzer(self.packet_frame)  # Start the packet analyzer

if __name__ == '__main__':
    app = App()
    app.mainloop()