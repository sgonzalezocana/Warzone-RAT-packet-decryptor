from scapy.all import *
from scapy.layers.inet import TCP
from chepy import Chepy
import datetime
from binascii import unhexlify, hexlify
import argparse
import struct


key_new = "nevergonnagiveyouup"
key_old = "7761727a6f6e6531363000"

def get_id(response):
    parsed_response = response[16:18]
    return parsed_response

def save_to_file(name, content):
    with open(f'{datetime.datetime.now()}_{name}.txt', 'w') as f:
        f.write(str(content))

def RC4(input):
    decrypted = Chepy(input).hex_to_str().rc4_decrypt(key_old, hex_key = True).o
    return decrypted

def rc4plus(data, key, key_size=250):
    def movsx_scaja(dir):
        if struct.unpack("b", bytes([scaja[dir]]))[0] < 0:
            return 4294967040 + scaja[dir]
        else:
            return scaja[dir]

    scaja = []
    key = [0] * key_size
    for i in range(len(key_new)):
        key[i] = ord(key_new[i])

    for i in range(256):
        scaja.append(i)

    this_1 = 0
    for i in range(256):
        this_1 += scaja[i] + key[i % key_size]
        temp = 0xff & (scaja[0xff & this_1])
        value = scaja.index(temp)
        scaja[value] = scaja[i]
        scaja[i] = temp

    data = list(data)
    i = 0
    j = 0
    for x in range(len(data)):
        i += 1
        a = movsx_scaja(i % 256)
        j = (j + a)
        b = movsx_scaja(j % 256)
        scaja[i % 256] = b % 256
        scaja[j % 256] = a % 256
        c = (movsx_scaja((i << 5 ^ j >> 3) % 256) + movsx_scaja((j << 5 ^ i >> 3) % 256)) % 256
        data[x] = (data[x] ^ ((movsx_scaja((a + b) % 256) + movsx_scaja((c ^ 0xAA) % 256)) ^ movsx_scaja(
            (j + b) % 256)) % 256) % 256
        i += 1
    return data


def find_sent_command(command, content):
    if command == '00':
        print("Machine info request detected\n")
    elif command == '02':
        print("Enumerate processes request detected\n")
    elif command == '04':
        print("Enumerate disk request detected\n")
    elif command == '06':
        print("List directories request detected\n")
    elif command == '08':
        print("Read file request detected\n")
    elif command.lower() == '0a':
        print("Delete file request detected\n")
    elif command.lower() == '0c':
        print("Kill process request detected\n")
    elif command.lower() == '0e':
        print("Remote Shell request detected\n")
    elif command == '12':
        print("Get connected cameras request detected\n")
    elif command == '13':
        print("Detected transmission from webcam\n")
    elif command == '14':
        print("Camera started detected\n")
    elif command == '16':
        print("Camera stopped detected\n")
    elif command == '18':
        print("Heartebeat sent to infected machine\n")
    elif command.lower() == '1a':
        print("Uninstall bot detected\n")
    elif command.lower() == '1c':
        print("Upload file request detected\n")
    elif command.lower() == '1e':
        print("Send executable to infected machine request detected\n")
    elif command == '20':
        print("Browser password recovery detected\n")
    elif command == '22':
        print(f"Download and execute request detected  {content}\n")
    elif command == '24':
        print("Online keylogger activity detected\n")
    elif command == '26':
        print("Offline keylogger activity detected\n")
    elif command == '28':
        print("RDP activity detected\n")
    elif command.lower() == '2a':
        print("Reverse proxy started\n")
    elif command.lower() == '2c':
        print("Reverse proxy stopped\n")
    elif command == '30':
        print("VNC Port setup request\n")
    elif command == '32':
        print("VNC connection stopped\n")
    elif command == '33':
        print("Escalate privileges attemp detected\n")
    elif command == '38':
        print("Reverse sock port request detected\n")
    elif command.lower() == '3a':
        print("File execution detected\n")
    elif command.lower() == '3d':
        print("Get Log storage path Request detected\n")


def find_response_command(command_2, content):
    if command_2 == '01':
        save_to_file('MachineInfo', content)
    if command_2 == '03':
        save_to_file('Process_List', content)
    if command_2 == '05':
        save_to_file('Enumerate_disk', content)
    if command_2 == '07':
        save_to_file('Directories_list', content)
    if command_2 == '09':
        save_to_file('File_read', content)
    if command_2.lower() == '0b':
        print('Delete file response from bot detected\n')
    if command_2.lower() == '0f':
        save_to_file('Remote_shell', content)
    if command_2 == '11':
        save_to_file('Connected_cameras', content)
    if command_2 == '15':
        print('HeartBeat response from bot detected\n')
    if command_2 == '17':
        print('VNC Port setup response detected\n')
    if command_2 == '19':
        save_to_file('Password_recovery', content)
    if command_2.lower() == '1d':
        print('RDP response detected')
    if command_2 == '25':
        print('Download and execute response detected\n')
    if command_2.lower == '3b':
        print('Log storage path response detected\n')

def main():
    affected_packets_counter = 0
    packet_counter = 0
    counter = 0
    affected = []

    parser = argparse.ArgumentParser(description='Warzone RAT packet decryptor is a tool to detect and decrypt malicious '
                                                 'packets related to Warzone RAT malware from a PCAP file. This application'
                                                 ' can track all the activity performed by the malicious actor, showing the'
                                                 ' content of the packets exchanged between the C2 and the infected user.')
    parser.add_argument('-s', '--source', type=str, help='Path of the affected PCAP')
    parser.add_argument('-p', '--port', type=int, help='Local port used by the malware')
    args = parser.parse_args()

    packets = rdpcap(args.source)
    src_port = int(args.port)

    find = False
    for packet in packets:
        counter += 1
        if packet.haslayer(TCP):
            if packet.payload.original.hex().find('09123b42') != -1 or packet.payload.original.hex().find('05386bf4') != -1:
                find = True
                affected.append(counter)

    if find:
        print('Warzone RAT activity detected in PCAP!!')
        print(f'Affected packets {affected}')
    else:
        print('I have not found malicious activity associated to Warzone RAT')
        pass

    if src_port:
        for packet in packets:
            packet_counter +=1
            if packet.haslayer(TCP):
                if packet.payload.original.hex().find('09123b42') != -1:
                    print(f'Packet nº {packet_counter} - {packet.src}:{packet.sport}  -->  {packet.dst}:{packet.dport}')
                    affected_packets_counter += 1
                    position_crypted_data = packet.payload.original.hex().find('09123b42')
                    packet_content = packet.payload.original.hex()
                    decrypted_data= RC4(packet_content[position_crypted_data:]).hex()
                    command = get_id(decrypted_data)
                    if packet.sport == int(src_port):
                        find_sent_command(command, Chepy(decrypted_data).hex_to_str(ignore=True).remove_nullbytes())
                    else:
                        command_2 = get_id(decrypted_data)
                        content = Chepy(decrypted_data).hex_to_str(ignore=True).remove_nullbytes()
                        print(f'Detected response from the infected machine\n')
                        print(str(content)[4:] + "\n")
                        find_response_command(command_2, content)

                elif packet.payload.original.hex().find('05386bf4') != -1:
                    print(f'Packet nº {packet_counter} - {packet.src}:{packet.sport}  -->  {packet.dst}:{packet.dport}')
                    affected_packets_counter += 1
                    position_crypted_data = packet.payload.original.hex().find('05386bf4')
                    packet_content = packet.payload.original.hex()
                    encrypted_bytes = bytes(unhexlify(packet_content[position_crypted_data:]))
                    decrypted_data = rc4plus(encrypted_bytes, key_new)
                    decrypted_data_hex = hexlify(bytes(decrypted_data))
                    decrypted_data_hex_parsed = str(decrypted_data_hex[2:])
                    command = get_id(decrypted_data_hex_parsed)
                    if packet.sport == int(src_port):
                        find_sent_command(command, Chepy(decrypted_data_hex).hex_to_str(ignore=True).remove_nullbytes())
                    else:
                        command_2 = get_id(decrypted_data_hex_parsed)
                        content = Chepy(decrypted_data_hex).hex_to_str(ignore=True).remove_nullbytes()
                        print(f'Detected response from the infected machine\n')
                        print(str(content)[4:] + "\n")
                        find_response_command(command_2, content)
    else:
        print('Set a valid local port to continue')
        pass


    print(f'Detected {affected_packets_counter} packets related to Warzone RAT')


if __name__ == "__main__":
   main()
