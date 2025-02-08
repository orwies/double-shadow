from scapy.all import *
from scapy.layers.inet import UDP

def is_starting_packet(pkt) -> bool:
    """
    Detect the starting packet based on its destination port.
    :param pkt: Captured packet
    :return: True if it's the starting packet
    """
    return UDP in pkt and pkt[UDP].dport == 1337

def is_valid_data_packet(pkt) -> bool:
    """
    Check if a packet is valid based on the destination port.
    :param pkt: Captured packet
    :return: True if the packet is valid
    """
    return UDP in pkt and pkt[UDP].dport > 50034

def extract_message() -> str:
    """
    Extract and decrypt the transmitted message.
    :return: The decrypted message
    """
    # Wait for the start signal to capture message length
    initial_pkt = sniff(lfilter=is_starting_packet, count=1)[0]
    msg_length = int(initial_pkt[Raw].load.decode())

    # Capture the valid data packets
    data_packets = sniff(lfilter=is_valid_data_packet, count=msg_length)

    # Decode the message
    return ''.join([chr(pkt[UDP].dport - 50003) for pkt in data_packets])

if __name__ == "__main__":
    received_message = extract_message()
    print(f"Received Message: {received_message}")
