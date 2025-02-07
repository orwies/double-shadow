def encryption(character):
    ascii_value =ord(character)
    msg_port = ascii_value + 3 + 20000
    return msg_port


def decryption(msg_port):
    msg = msg_port - 20000 - 3
    character = chr(msg)
    return character