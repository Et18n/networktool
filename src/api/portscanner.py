from flask import Flask,jsonify,json
import os
import socket
import sys
import  concurrent.futures

app=Flask(__name__)
def ping_function(target):
    param = '-n' if sys.platform=='win32' else '-c'
    hostname = target
    response = os.system(f"ping {param} 1 {hostname}")
    print(f' The response is: {response}')
    if response == 0:
        print(f"{hostname} is up!")
        return "active"
    else:
        print(f"{hostname} is down!")
        return "inactive"

def portscan_function(port):
        open_ports=[]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            services=[]
            protocols = ['tcp', 'udp']
            for proto in protocols:
                try:
                    service_name = socket.getservbyport(port, proto)
                    print("Port No: {} Open Protocol: {} Service Name: {}".format(port, proto, service_name))
                    open_ports.append({"port": port, "protocol": proto, "service": service_name})
                except OSError:
                    pass
            return open_ports

def port_scanner(host, start_port, end_port, max_threads) :
    open_ports = []
    ports=range(start_port, end_port+1)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        results = executor.map(portscan_function,ports)
        for result in results:
            if result!=None:
                open_ports.extend(result)
                print(result)
    return open_ports


@app.route('/scan/<target>', methods=['GET'])
def scan(target):
    global host
    try:
        host = socket.gethostbyname(target)
    except socket.gaierror:
        return jsonify({"error": "Target is not resolvable"}), 400

    ping_status = ping_function(target)
    start_port = 1
    end_port = 1025
    max_threads = 1000

    open_ports = port_scanner(host, start_port, end_port, max_threads)

    return jsonify({
        "target":target,
        "ping_status": ping_status,
        "open_ports": open_ports
    })

if __name__ == "__main__":
    app.run(debug=True, host='127.0.0.1', port=80)
