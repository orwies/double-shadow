from scapy.all import sniff, Raw, Packet
from scapy.layers.inet import UDP

        
def filter_first_message(pkt):
    return UDP in pkt and pkt[UDP].dport == 13337

def filter_port(pkt):
    """ This function return True if the packet's destination port is valid """
    return UDP in pkt and 20068 <= pkt[UDP].dport <= 20193 and 20100 <= pkt[UDP].dport <= 20125

def filter_last_message(pkt: Packet):
    return pkt.haslayer(UDP) and  pkt[UDP].dport == 13338 and pkt[Raw].load == b'END'


def main():
    while True:
        length = sniff(count=1, lfilter=filter_first_message)[0].dport
        print(length[Raw].load)


        msg = []
        for _ in range(length):
            char = sniff(count=1, lfilter=filter_port, timeout=1)
            if len(char) == 0:
                break
            print(char)
            msg.append(chr(char[0][UDP].dport - 20003))


        print(''.join(msg))
            
        end = sniff(count=1, lfilter=filter_last_message)[0].dport
        print(end[Raw].load)


if __name__ == '__main__':
    main()
