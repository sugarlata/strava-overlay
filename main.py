import socket
from scapy.all import sniff, UDP, IP
import zwiftMessages_pb2

MY_IP_ADDRESS=socket.gethostbyname(socket.gethostname())


def packet_callback(packet):
    if packet[UDP].payload:
        incoming = packet[IP].dst == MY_IP_ADDRESS

        if incoming:
            process_incoming(packet)
        else:
            process_outgoing(packet)

        
def process_incoming(packet):

    protobuf_incoming = zwiftMessages_pb2.ServerToClient()
    try:
        protobuf_incoming.ParseFromString(bytes(packet[UDP].payload))
        print(protobuf_incoming.player_states)
    
    except Exception as e:
        print(f"Error: {str(e)}")
        

def process_outgoing(packet):
    
    skip = 5
    if bytes(packet[UDP].payload)[skip:skip+1].hex() == '08':
        pass
    elif bytes(packet[UDP].payload)[0:1].hex() == '08':
        skip = 0
    else:
        try:
            skip = int(bytes(packet[UDP].payload)[0:1].hex()) - 1
        except:
            pass
        
    protobuf_outgoing = zwiftMessages_pb2.ClientToServer()

    try:
        protobuf_outgoing.ParseFromString(bytes(packet[UDP].payload)[skip:-4])
        print(protobuf_outgoing.player_states)

    except Exception as e:
        print(f"Error: {str(e)}")

def main():
    print('Starting Sniffer')
    sniff(
        iface='Wi-Fi',
        filter='udp port 3022',
        prn=packet_callback,
        store=0
    )
    

if __name__ == '__main__':
    main()