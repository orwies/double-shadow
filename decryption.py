from scapy.layers.inet import UDP
from scapy.all import *
from scapy.packet import Raw

# Load the packets from pcap file
captured_pkts = rdpcap("secret_messages.pcap")

def decode_message(packet_list):
    """
    Decode the message by extracting and transforming port values.
    :param packet_list: List of captured packets
    :return: The decoded message
    """
    letters_map = [chr(i) for i in range(ord('a'), ord('z') + 1)]
    decrypted_messages = []

    idx = 0
    while idx < len(packet_list):
        if UDP in packet_list[idx] and packet_list[idx][UDP].dport == 1337:
            msg_length = int(packet_list[idx][Raw].load.decode())
            idx += 1
            hidden_message = ""

            for _ in range(msg_length):
                letter_idx = packet_list[idx][UDP].dport - 50003
                hidden_message += letters_map[letter_idx]
                idx += 1

            decrypted_messages.append(hidden_message.replace('x', ' '))
    return decrypted_messages

# Process captured packets
decoded_texts = decode_message(captured_pkts)
print(decoded_texts)
