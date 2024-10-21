import os
import socket
import sys
import concurrent.futures
import subprocess


def ping_function(target):
    try:
        output = subprocess.check_output(f"ping {target}", shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    except:
        output='Invalid Host'
    return output
   


def portscan_function(port):
    protocols = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)  # Increased the timeout for more reliable scanning
    result = sock.connect_ex((host, port))
    if result == 0:
        protocol_list= ['tcp', 'udp']
        for proto in protocol_list:
            try:
                service_name = socket.getservbyport(port, proto)
                print(f'Open Port {port}: Protocol {proto} ------> {service_name}  ')
                protocols[proto]=service_name
            except OSError:
                protocols[proto] = 'unknown'

    sock.close()
    return port,protocols


def port_scanner(host,start_port, end_port):
    open_ports = {}
    max_threads = 1000
    ports = range(start_port, end_port + 1)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        results = executor.map(portscan_function, ports)

        for port, protocols_data in results:
            if protocols_data:
                open_ports[port] = protocols_data

            # Print open ports with protocols and service names
        for port, protocols in open_ports.items():
            print(f"Port {port}: ")
            for protocol, service_name in protocols.items():
                print(f"  {protocol}: {service_name}")

    return open_ports

def portscannez(target,start_port,end_port):
    global  host
    host = socket.gethostbyname(target)

    open_ports = port_scanner(host,start_port, end_port)
    print('\n\n\n')

    return open_ports


def main(target, start_port, end_port):
    global max_threads
    global host
    max_threads = 1000  # Adjusted to 100 threads for better performance
    try:
        host = socket.gethostbyname(target)
        print(f"Resolved host {target} to {host}")
        result = f"Resolved host {target} to {host}\n"
    except socket.gaierror:
        print("Target is not resolvable")
        result="Target is not resolvable"
        return result

    # Ping the target
    ping_function(target)
    # Port scan
    result += f"Starting port scan from {start_port} to {end_port}\n"
    print(f"Starting port scan from {start_port} to {end_port}")
    open_ports = port_scanner(start_port, end_port)
    print("Open ports and corresponding services found:")
    for port, service in open_ports.items():
        print(f"Port {port}: {service}")


    return result


# Run the main function
if __name__ == "__main__":
    ping_function('xavier.ac.in')
