#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]
        
    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        time.sleep(1)

def is_unicast(mac):
    return int(mac[:2], 16) % 2 == 0

def read_switch_config(switch_id):
    fin = open("./configs/switch{}.cfg".format(switch_id))
    
    # Read each line individually.
    lines = fin.readlines()

    # First line is the switch priority.
    switch_priority = int(lines[0])

    # Initialize VLAN table.
    vlan_table = {}

    # Remove first line (the priority)
    lines.pop(0)

    for line in lines:
        split_line = line.split()
        vlan_table.update({split_line[0]: int(split_line[1]) if split_line[1] != 'T' else 'T'})

    return switch_priority, vlan_table


# forward_frame(data, length, interface, vlan_id)
def forward_frame(frame, port, length, vlan_id): 
    send_to_link(port, length, frame)

def forwarding_frame(data, src_mac, dest_mac, vlan_id, interface, mac_table, interfaces, length):
    """
    Forward the Ethernet frame based on the MAC learning table and VLAN ID.
    
    Args:
        data (bytes): The raw frame data.
        src_mac (bytes): Source MAC address.
        dest_mac (bytes): Destination MAC address.
        vlan_id (int): VLAN ID or -1 if not present.
        interface (int): Interface the frame was received from.
        mac_table (dict): Mapping of MAC addresses to interfaces.
        interfaces (range): Range of available interfaces.
    """

    # Update MAC table
    mac_table[src_mac] = interface

    # If the frame is unicast and the destination MAC is in the MAC table
    if is_unicast(dest_mac):
        if dest_mac in mac_table:
            # Forward the frame to the known port
            target_port = mac_table[dest_mac]
            if target_port != interface:  # Avoid sending back on the same interface
                forward_frame(data, target_port, length, vlan_id)
        else:
            # Flood the frame to all other ports if MAC not known
            for port in interfaces:
                if port != interface:
                    forward_frame(data, port, length, vlan_id)
    else:
        if dest_mac != "01:80:c2:00:00:00":
            process_received_bpdu(data, length, interface)
            return
        # If frame is broadcast or multicast, flood to all ports except the source port
        for port in interfaces:
            if port != interface:
                forward_frame(data, port, length, vlan_id)



def process_received_bpdu(data, length, interface):
    
    global vlan_table
    global interface_status
    global is_root_bridge
    global interfaces
    global own_bridge_id
    global root_path_cost
    global root_bridge_id
    global root_port

    # Size         6          6             4               4               4
    # Format    dest_mac | src_mac | own_bridge_id | root_path_cost | root_bridge_id

    dest_mac = data[:6]
    src_mac = data[6:12]
    bpdu_own_bridge_id = int.from_bytes(data[12:16], byteorder='big')
    bpdu_root_path_cost = int.from_bytes(data[16:20], byteorder='big')
    bpdu_root_bridge_id = int.from_bytes(data[20:24], byteorder='big')





def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)

    global switch_priority, vlan_table, status
    switch_priority, vlan_table = read_switch_config(switch_id)


    mac_table = {}

    #print("# Starting switch with id {}".format(switch_id), flush=True)
    #print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    global status
    # Printing interface names
    status = {}
    for i in interfaces:
        # print(get_interface_name(i))
        name = get_interface_name(i)
        if vlan_table[name] == 'T':
             status[name] = "block"
        else:
             status[name] = "listen"


    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        # print(f'Destination MAC: {dest_mac}')
        # print(f'Source MAC: {src_mac}')
        # print(f'EtherType: {ethertype}')

        # print("Received frame of size {} on interface {}".format(length, interface), flush=True)
        intf_name = get_interface_name(interface)
        if vlan_id == -1 and vlan_table[intf_name] != 'T':
            vlan_id = vlan_table[name]

        # TODO: Implement forwarding with learning
        forwarding_frame(data, src_mac, dest_mac, vlan_id, interface, mac_table, interfaces, length)
        # TODO: Implement VLAN support
        # TODO: Implement STP support

        # data is of type bytes.
        # send_to_link(i, length, data)


if __name__ == "__main__":
    main()
