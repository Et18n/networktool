import customtkinter as ctk
from portscanner import ping_function, main,portscannez


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title('Network Utility Application')
        self.geometry(f'{self.winfo_screenwidth()}x{self.winfo_screenheight()}+0+0')
        self._set_appearance_mode('Dark')

        # Title
        ctk.CTkLabel(self, text='Welcome to the Network Utility', font=('Arial', 24, 'bold')).grid(row=0, column=0, columnspan=2, padx=10, pady=20)

        # Domain/IP Entry
        ctk.CTkLabel(self, text='Select Domain/IP Address:', font=('Arial', 14)).grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.domain = ctk.CTkOptionMenu(self, values=['ethanferrao.me', 'google.com', 'facebook.com', 'xavier.ac.in','localhost'])
        self.domain.grid(row=1, column=1, padx=10, pady=5)

        # Operation Selection
        ctk.CTkLabel(self, text='Select Operation:', font=('Arial', 14)).grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.operation = ctk.CTkOptionMenu(self, values=['Ping', 'Port Scan','Packet Capture'], fg_color='grey', button_color='grey')
        self.operation.grid(row=2, column=1, padx=10, pady=5)

        # Submit Button
        self.submit_btn = ctk.CTkButton(self, text='Submit', command=self.domain_entry)
        self.submit_btn.grid(row=3, column=0, columnspan=2, pady=20)

        # Results Frame
        self.results_frame = ctk.CTkFrame(self)
        self.results_frame.grid(row=4, column=0, columnspan=2, padx=10, pady=20, sticky="nsew")

        self.result_label = ctk.CTkLabel(self.results_frame, text="", font=('Arial', 12), wraplength=600, justify="left")
        self.result_label.grid(pady=10)

        # Dynamic Widgets for Port Scan
        self.port_range_frame = ctk.CTkFrame(self)
        self.port_range_frame.grid(row=5, column=0, columnspan=2, pady=10,padx=10, sticky="nsew")
        self.port_range_frame.grid_remove()  # Hide initially

        ctk.CTkLabel(self.port_range_frame, text='Enter start and end ports:').grid(row=0, column=0, columnspan=2, padx=10, pady=5)
        self.start_port = ctk.CTkEntry(self.port_range_frame, placeholder_text='Start Port')
        self.start_port.grid(row=1, column=0, padx=10, pady=5)
        self.end_port = ctk.CTkEntry(self.port_range_frame, placeholder_text='End Port')
        self.end_port.grid(row=1, column=1, padx=10, pady=5)

        self.scan_btn = ctk.CTkButton(self.port_range_frame, text='Start Scan', command=self.start_scan)
        self.scan_btn.grid(row=2, column=0, columnspan=2, pady=10)


        #Dynamic widget for Packet Capture
        self.packet_list=ctk.CTkFrame(self)
        self.packet_list.grid(row=6, column=0, columnspan=2,pady=10,padx=10,sticky="nsew")
        self.packet_list.grid_remove()

    def domain_entry(self):
        self.target = self.domain.get()
        self.operation_descision = self.operation.get()

        # Clear previous results
        self.result_label.configure(text="")

        if self.operation_descision == 'Ping':
            self.start_ping()
        elif self.operation_descision == 'Port Scan':
            self.port_range_frame.grid()  # Show port range input fields
        elif self.operation_descision=='Packet Capture':
            self.packet_list.grid()
            self.start_packets()

    def start_ping(self):
        self.port_range_frame.grid_remove()  # Hide the port range frame in case it was shown
        result = ping_function(self.target)
        self.display_result(result)

    def start_scan(self):
        try:
            start_port = int(self.start_port.get())
            end_port = int(self.end_port.get())
            result = portscannez(self.target, start_port, end_port)
            self.display_result(result)
        except ValueError:
            self.display_result("Invalid port range. Please enter valid numbers.")

    def start_packets(self):
        self.port_range_frame.grid_remove()
        self.result_label.grid_remove()


    def display_result(self, result):
        self.result_label.configure(text=result)


if __name__ == '__main__':
    app = App()
    app.mainloop()
