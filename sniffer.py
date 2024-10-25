from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest

# Function to handle each packet that is captured
def handle_packet(packet):
    if IP in packet:  # Check if the packet contains an IP layer
        src_ip = packet[IP].src  # Get the source IP address
        dst_ip = packet[IP].dst  # Get the destination IP address
        proto = packet[IP].proto  # Get the protocol type (TCP/UDP)
        
        # Start building the output string with IP addresses
        output_info = f"Source: {src_ip} -> Destination: {dst_ip} | "

        # Check if it's a TCP packet
        if proto == 6:
            if packet.haslayer(TCP):  # Ensure it has a TCP layer
                src_port = packet[TCP].sport  # Source port
                dst_port = packet[TCP].dport  # Destination port

                # Determine the protocol based on ports
                if src_port == 80 or dst_port == 80:
                    output_info += "Protocol: HTTP"
                elif src_port == 443 or dst_port == 443:
                    output_info += "Protocol: HTTPS"
                elif src_port in [25, 587, 465] or dst_port in [25, 587, 465]:
                    output_info += "Protocol: SMTP"
                elif src_port in [21, 20] or dst_port in [21, 20]:
                    output_info += "Protocol: FTP"
                else:
                    output_info += "Protocol: TCP"

                output_info += f" | Src Port: {src_port}, Dst Port: {dst_port}"

        # Check if it's a UDP packet
        elif proto == 17:
            if packet.haslayer(UDP):  # Ensure it has a UDP layer
                src_port = packet[UDP].sport  # Source port
                dst_port = packet[UDP].dport  # Destination port

                # Check for DNS protocol
                if src_port == 53 or dst_port == 53:
                    output_info += "Protocol: DNS"
                else:
                    output_info += "Protocol: UDP"

                output_info += f" | Src Port: {src_port}, Dst Port: {dst_port}"

        else:
            output_info += "Protocol: Other"

        print(output_info)  # Print the captured packet information

        # Print details if it's an HTTP request
        if packet.haslayer(HTTPRequest):
            http_method = packet[HTTPRequest].Method  # Get HTTP method
            http_host = packet[HTTPRequest].Host  # Get HTTP host
            http_path = packet[HTTPRequest].Path  # Get HTTP path
            print(f"HTTP Request: {http_method} {http_host}{http_path}")

        # Print details if it's a DNS query
        if packet.haslayer(DNS) and packet[UDP].dport == 53:
            dns_query = packet[DNS].qd.qname.decode('utf-8')  # Decode DNS query
            print(f"DNS Query for: {dns_query}")

def run_sniffer():
    print("Start Capturing packets...")  # Message when starting
    sniff(prn=handle_packet, store=0)  # Start sniffing packets

if __name__ == "__main__":
    run_sniffer()  # Run the sniffer when the script starts
