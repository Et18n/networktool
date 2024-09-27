from tkinter import *
import scapy.all as scp
import os
import scapy.arch.windows as scpwinarch
import threading
import socket
import hashlib


def readrules():
    script_dir = os.path.dirname(__file__)
    rulefile = os.path.join(script_dir, 'rules.txt')
    
    ruleslist = []
    with open(rulefile, "r") as rf:
        ruleslist = rf.readlines()
    rules_list = []
    for line in ruleslist:
        if line.startswith("alert"):
            rules_list.append(line)
    print(rules_list)
    return rules_list


alertprotocols = []
alertdestips = []
alertsrcips = []
alertsrcports = []
alertdestports = []
alertmsg = []


def process_rules(rulelist):
    global alertprotocols
    global alertdestips
    global alertsrcips
    global alertsrcports
    global alertdestports
    global alertmsg

    alertprotocols = []
    alertdestips = []
    alertsrcips = []
    alertsrcports = []
    alertdestports = []
    alertmsg = []

    for rule in rulelist:
        rulewords = rule.split()
        if rulewords[1] != "any":
            protocol = rulewords[1]
            alertprotocols.append(protocol.lower())
        else:
            alertprotocols.append("any")
        if rulewords[2] != "any":
            srcip = rulewords[2]
            alertsrcips.append(srcip.lower())
        else:
            alertsrcips.append("any")
        if rulewords[3] != "any":
            srcport = int(rulewords[3])
            alertsrcports.append(srcport)
        else:
            alertsrcports.append("any")
        if rulewords[5] != "any":
            destip = rulewords[5]
            alertdestips.append(destip.lower())
        else:
            alertdestips.append("any")
        if rulewords[6] != "any":
            destport = rulewords[6]
            alertdestports.append(destport.lower())
        else:
            alertdestports.append("any")
        try:
            alertmsg.append(" ".join([rulewords[x] for x in range(7, len(rulewords))]))
        except:
            alertmsg.append("")
            pass

    print(alertprotocols)
    print(alertdestips)
    print(alertsrcips)
    print(alertsrcports)
    print(alertdestports)
    print(alertmsg)


process_rules(readrules())

source_ip_counts = {}


def count_source_ips(packets):
    # source_ip_counts = {}
    for pkt in packets:
        src_ip = pkt["IP"].src
        if src_ip in source_ip_counts:
            source_ip_counts[src_ip] += 1
        else:
            source_ip_counts[src_ip] = 1
    return source_ip_counts


suspiciouspackets = []
sus_packetactual = []
sus_readablepayloads = []
pkt_summary = []
pktsummarylist = []
updatepktlist = False


def proto_name_by_num(proto_num):
    for name, num in vars(socket).items():
        if name.startswith("IPPROTO") and proto_num == num:
            return name[8:]
    return "Protocol not found"


def check_rules_warning(pkt):
    global alertprotocols
    global alertdestips
    global alertsrcips
    global alertsrcports
    global alertdestports
    global alertmsg
    global sus_readablepayloads
    global updatepktlist

    if 'IP' in pkt:
        try:
            src = pkt['IP'].src
            dest = pkt['IP'].dst
            proto = proto_name_by_num(pkt['IP'].proto).lower()
            sport = pkt['IP'].sport
            dport = pkt['IP'].dport

            for i in range(len(alertprotocols)):
                if alertprotocols[i] != "any":
                    chkproto = alertprotocols[i]
                else:
                    chkproto = proto
                if alertdestips[i] != "any":
                    chkdestip = alertdestips[i]
                else:
                    chkdestip = dest
                if alertsrcips[i] != "any":
                    chksrcip = alertsrcips[i]
                else:
                    chksrcip = src
                if alertsrcports[i] != "any":
                    chksrcport = alertsrcports[i]
                else:
                    chksrcport = sport
                if alertdestports[i] != "any":
                    chkdestport = alertdestports[i]
                else:
                    chkdestport = dport

                if (str(src).strip() == str(chksrcip).strip() and
                        str(dest).strip() == str(chkdestip).strip() and
                        str(proto).strip() == str(chkproto).strip() and
                        str(dport).strip() == str(chkdestport).strip() and
                        str(sport).strip() == str(chksrcport).strip()):

                    print("Flagged Packets")

                    if proto == "tcp":
                        try:
                            print(pkt["TCP"])
                            readable_payload = bytes(pkt['TCP']).decode("UTF-8", "replace")
                            sus_readablepayloads.append(readable_payload)
                        except Exception as ex:
                            sus_readablepayloads.append("Error getting tcp payload!!")
                            print(ex)
                            pass
                    elif proto == "udp":
                        try:
                            readable_payload = bytes(pkt['UDP'].payload).decode("UTF-8", "replace")
                            sus_readablepayloads.append(readable_payload)
                        except Exception as ex:
                            sus_readablepayloads.append("Error getting udp payload!!")
                            print(ex)
                            pass
                    else:
                        sus_readablepayloads.append("not tcp or udp")
                    return True, str(alertmsg[i])
        except:
            pkt.show()

    return False, ""


ifaces = [str(x['name']) for x in scpwinarch.get_windows_if_list()]
capiface = ifaces[0]

source_ip_counts = {}


def convert_packet_to_hash(pkt):
    serialized_pkt = bytes(pkt)


    hash_value = hashlib.sha256(serialized_pkt).hexdigest()

    return hash_value


def sniff_thread():
    scp.sniff(prn=pkt_process, filter="", store=False, stop_filter=lambda x: not running)


def pkt_process(pkt):
    if not running:
        return  # Stop processing if the flag is False
    pkt_summary = pkt.summary()
    listbox1.insert(END, pkt_summary)

    sus_pkt, sus_msg = check_rules_warning(pkt)
    if sus_pkt == True:
        suspiciouspackets.append(pkt_summary)
        listbox2.insert(END, suspiciouspackets)
    return


def start_capture():
    global updatepktlist
    global running
    updatepktlist = True
    running = True  # Set running to True initially
    listbox1.delete(0, END)
    if not sniffthread.is_alive():
        sniffthread.start()


def stop_capture():
    global updatepktlist
    global running
    updatepktlist = False
    running = False  # Set running to False to stop the sniffing loop


def show_source_ip_counts():
    # Print source IP counts
    for src_ip, count in source_ip_counts.items():
        print(f"Source IP: {src_ip}, Count: {count}")


root = Tk()
root.title("Packet Analyzer")

# Labels and text boxes
label1 = Label(root, text="All Packets:")
label1.grid(row=0, column=0)
listbox1 = Listbox(root, height=20, width=100)
listbox1.grid(row=1, column=0)

label2 = Label(root, text="Suspicious Packets:")
label2.grid(row=0, column=1)
listbox2 = Listbox(root, height=20, width=150)
listbox2.grid(row=1, column=1)

# Buttons
start_button = Button(root, text="Start Capture", command=start_capture)
start_button.grid(row=2, column=0)
stop_button = Button(root, text="Stop Capture", command=stop_capture)
stop_button.grid(row=2, column=1)
refresh_rules_button = Button(root, text="Refresh Rules", )
refresh_rules_button.grid(row=3, column=0)
show_counts_button = Button(root, text="Show Counts", command=show_source_ip_counts)
show_counts_button.grid(row=3, column=1)

# Start the sniffing thread
sniffthread = threading.Thread(target=sniff_thread)

# Main loop
root.mainloop()
