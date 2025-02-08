from scapy.all import *
from scapy.layers.inet import IP, UDP

DESTINATION_IP = 'your IP'

def initial_signal(msg_length: int):
    """
    Send initial signal indicating the message length
    :param msg_length: Length of the message
    """
    length_payload = str(msg_length).encode()
    init_pkt = IP(dst=DESTINATION_IP) / UDP(dport=1337) / Raw(load=length_payload)
    send(init_pkt)

def transmit_characters(data: str):
    """
    Transmit encrypted characters one by one via UDP.
    :param data: The message data
    """
    for char in data:
        encrypted_char = chr(ord(char) + 3)
        dport_val = ord(encrypted_char) + 50000
        send(IP(dst=DESTINATION_IP) / UDP(dport=dport_val))

def send_completion_signal():
    """
    Send the final 'end of transmission' signal
    """
    completion_pkt = IP(dst=DESTINATION_IP) / UDP(dport=1338) / Raw(load=b"FINISH")
    send(completion_pkt)

def handle_message(message: str):
    """
    Handle the entire process of sending a message.
    :param message: The message to send
    """
    initial_signal(len(message))
    transmit_characters(message)
    send_completion_signal()

if __name__ == "__main__":
    user_message = input("Type your message: ")
    handle_message(user_message)
