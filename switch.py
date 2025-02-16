#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

mac_table = {}
vlan_table = {}
switch_priority = None
interface_status = {}
interfaces = {}
is_root_bridge = True
own_bridge_id = None
root_path_cost = 0
root_bridge_id = None
root_port = None

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

def forward_frame(data, length, interface, vlan_id):
    # Check if port is in the same VLAN or is a trunk port
    if vlan_table[get_interface_name(interface)] == vlan_id or vlan_table[get_interface_name(interface)] == 'T':
        if interface_status[get_interface_name(interface)] != "blocking":
            # Add VLAN tag if the port is a trunk
            if vlan_table[get_interface_name(interface)] == 'T':
                data = data[:12] + create_vlan_tag(vlan_id) + data[12:]
                length += 4
            send_to_link(interface, length, data)

def process_frame(data, length, vlan_id, interface, src_mac, dest_mac, mac_table, vlan_table, interfaces):
    # Assign VLAN ID if the frame came from an access port without a VLAN tag
    if vlan_id == -1:
        if vlan_table[get_interface_name(interface)] != 'T':
            vlan_id = vlan_table[get_interface_name(interface)]
    elif dest_mac != "01:80:c2:00:00:00":
        if vlan_table[get_interface_name(interface)] == 'T':
            # If the frame came from a trunk port and is not a BPDU, remove VLAN tag
            data = data[0:12] + data[16:]
            length -= 4

    # Update MAC table to associate the source MAC address with the receiving interface
    mac_table[src_mac] = interface
    
    if dest_mac != "01:80:c2:00:00:00":
        # Handle unicast frames
        if int(dest_mac[:2], 16) % 2 == 0:
            # Forward to specific port if destination MAC is in MAC table
            if dest_mac in mac_table:
                forward_frame(data, length, mac_table[dest_mac], vlan_id)
            else:
                # Broadcast to all other ports if destination MAC not found
                for port in interfaces:
                    if port != interface:
                        forward_frame(data, length, port, vlan_id)
        else:
            # Handle multicast/broadcast: send to all other ports in same VLAN
            for port in interfaces:
                if port != interface:
                    forward_frame(data, length, port, vlan_id)
    else:
        # Handle BPDU frame
        receiving_bpdu(data, length, interface)

def send_bpdu_every_sec():

    global vlan_table, interfaces
    global is_root_bridge, own_bridge_id

    while True:
        # Send BDPU every second if necessary
        if is_root_bridge:
            bpdu = create_bpdu(get_switch_mac(), own_bridge_id, 0, own_bridge_id)
            for port in interfaces:
                if vlan_table[get_interface_name(port)] == 'T':
                    send_to_link(port, len(bpdu), bpdu)

        time.sleep(1)

def create_bpdu(src_mac, bpdu_own_bridge_id, bpdu_root_path_cost, bpdu_root_bridge_id):
    dest_mac = b"\x01\x80\xC2\x00\x00\x00"

    # Pack destination MAC address into binary format (6 bytes)
    dest_mac_packed = struct.pack("!6s", dest_mac)
    # Pack source MAC address into binary format (6 bytes)
    src_mac_packed = struct.pack("!6s", src_mac)
    # Pack own bridge ID into binary format (4 bytes)
    own_bridge_id_packed = struct.pack("!I", bpdu_own_bridge_id)
    # Pack root path cost into binary format (4 bytes)
    root_path_cost_packed = struct.pack("!I", bpdu_root_path_cost)
    # Pack root bridge ID into binary format (4 bytes)
    root_bridge_id_packed = struct.pack("!I", bpdu_root_bridge_id)

    bpdu = dest_mac_packed + src_mac_packed + own_bridge_id_packed + root_path_cost_packed + root_bridge_id_packed

    return bpdu

def receiving_bpdu(data, length, interface):
    
    global vlan_table, interface_status, interfaces
    global is_root_bridge, own_bridge_id, root_path_cost, root_bridge_id, root_port

    dest_mac = data[:6]
    src_mac = data[6:12]
    bpdu_own_bridge_id = int.from_bytes(data[12:16], byteorder='big')
    bpdu_root_path_cost = int.from_bytes(data[16:20], byteorder='big')
    bpdu_root_bridge_id = int.from_bytes(data[20:24], byteorder='big')

    # If the BPDU's root bridge ID is smaller, update root bridge info
    if bpdu_root_bridge_id < root_bridge_id:
        root_bridge_id = bpdu_root_bridge_id
        root_path_cost = bpdu_root_path_cost + 10
        root_port = interface

        # If the switch was previously the root bridge
        if is_root_bridge:
            # Set all trunk ports except the root port to blocking
            for port in interfaces:
                if vlan_table[get_interface_name(port)] == 'T':
                    if port != root_port:
                        interface_status[get_interface_name(port)] = "blocking"

            is_root_bridge = False
            root_port_name = get_interface_name(root_port)

        if interface_status[root_port_name] == "blocking":
            interface_status[root_port_name] = "listening"

        # Update and forward the received BPDU on all trunk ports
        bpdu = create_bpdu(get_switch_mac(), own_bridge_id, root_path_cost, bpdu_root_bridge_id)
        for port in interfaces:
            if vlan_table[get_interface_name(port)] == 'T':
                send_to_link(port, len(bpdu), bpdu)

    elif bpdu_root_bridge_id == root_bridge_id:
        if interface == root_port:
            if bpdu_root_path_cost + 10 < root_path_cost:
                root_path_cost = bpdu_root_path_cost + 10

        else:
            if bpdu_root_path_cost > root_path_cost:
                # If the port is in blocking state, set it to listening
                if interface_status[get_interface_name(interface)] == "blocking":
                    interface_status[get_interface_name(interface)] == "listening"

    elif bpdu_own_bridge_id == own_bridge_id:
        interface_status[get_interface_name(interface)] = "blocking"
          
    if own_bridge_id == root_bridge_id:
        for port in interfaces:
            interface_status[get_interface_name(port)] = "listening"

def read_switch_config(switch_id):
    with open(f"./configs/switch{switch_id}.cfg") as fin:
        lines = fin.readlines()

    # First line is the switch priority
    switch_priority = int(lines.pop(0))
    vlan_table = {}
    # Process each remaining line to populate VLAN table
    for line in lines:
        split_line = line.split()
        # Map interface to VLAN ID, converting to integer unless it's 'T' (trunk port)
        vlan_table[split_line[0]] = int(split_line[1]) if split_line[1] != 'T' else 'T'

    return switch_priority, vlan_table

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    global mac_table, vlan_table, switch_priority, interfaces, interface_status
    global own_bridge_id, root_path_cost, root_bridge_id

    # own_bridge_id = switch_priority
    own_bridge_id, vlan_table = read_switch_config(switch_id)
    root_bridge_id = own_bridge_id

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    
    #print("# Starting switch with id {}".format(switch_id), flush=True)
    #print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bpdu_every_sec)
    t.start()

    # Start all trunk ports in blocking mode and rest in listening mode.
    for port in interfaces:
        interface_status[get_interface_name(port)] = "blocking" if vlan_table[get_interface_name(port)] == 'T' else "listening"

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

        #print(f'Destination MAC: {dest_mac}')
        #print(f'Source MAC: {src_mac}')
        #print(f'EtherType: {ethertype}')
        #print("Received frame of size {} on interface {}".format(length, interface), flush=True)
       
        process_frame(data, length, vlan_id, interface, src_mac, dest_mac, mac_table, vlan_table, interfaces)

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()