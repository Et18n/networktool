import customtkinter as ctk
import subprocess
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import re

class TracerouteVisualizerApp(ctk.CTkFrame):
    def __init__(self, parent, target_ip):
        super().__init__(parent)  # Initialize as a frame within the parent widget
        self.target_ip = target_ip  # Store the target IP
        self.setup_ui()

    def setup_ui(self):
        # UI components inside the traceroute frame
        label_title = ctk.CTkLabel(self, text="Traceroute Visualization", font=("Arial", 20, "bold"))
        label_title.pack(pady=10)

        button_traceroute = ctk.CTkButton(self, text="Start Traceroute", command=self.start_traceroute)
        button_traceroute.pack(pady=10)

    def run_nmap_traceroute(self, target_ip):
        try:
            result = subprocess.run(
                ["nmap", "-sn", "--traceroute", target_ip],
                capture_output=True, text=True, check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"Error: {e}"

    def parse_traceroute_output(self, output):
        hop_pattern = re.compile(r"([\d.]+)\s+ms\s+([\d.]+)")
        hops = [(match.group(1), match.group(2)) for match in hop_pattern.finditer(output)]
        return hops

    def visualize_topology(self, hops):
        G = nx.DiGraph()
        previous_node = "localhost"
        G.add_node(previous_node)

        for rtt, ip in hops:
            G.add_node(ip)
            G.add_edge(previous_node, ip)
            previous_node = ip

        fig, ax = plt.subplots(figsize=(6, 6))
        nx.draw(G, with_labels=True, node_color='lightblue', arrows=True, ax=ax)
        plt.title("Traceroute Visualization")
        return fig

    def start_traceroute(self):
        output = self.run_nmap_traceroute(self.target_ip)
        hops = self.parse_traceroute_output(output)
        fig = self.visualize_topology(hops)

        canvas = FigureCanvasTkAgg(fig, master=self)
        canvas.draw()
        canvas.get_tk_widget().pack(pady=10)



if __name__ == "__main__":
    app = TracerouteVisualizerApp()
    app.mainloop()
