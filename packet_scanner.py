#!/usr/bin/env python

import dpkt
import datetime
import socket
import argparse
import pdb


# convert IP addresses to printable strings 
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# add your own function/class/method defines here.
final_probe_list = []
final_scan_list = []
probes_found = 0
scans_found = 0

def get_ports(W_p, N_p, W_s, N_s, port_list = []):
    count_probe = 1
    count_scan = 1
    global probes_found
    global scans_found
    global final_tcp_probe_list
    global final_tcp_scan_list
    
    for i, j in enumerate(port_list):
        if (i+1) >= len(port_list):
            next_scan = port_list[i]
        else:
            next_scan = port_list[i+1]
        width = (next_scan[0] - j[0]).total_seconds()
        
        if j[1] == next_scan[1] and width <= W_p:
            if i == len(port_list)-1 and count_probe >= N_p:
                final_probe_list.append(port_list[i-count_probe+1:i+1][:])
                probes_found += 1
            if i == len(port_list)-1 and count_scan >= N_s:
                final_scan_list.append(port_list[i-count_scan+1:i+1][:])
                scans_found += 1
            
            count_probe += 1
            count_scan += 1
            
        elif j[1] != next_scan[1] and count_probe >= N_p:
            final_probe_list.append(port_list[i-count_probe+1:i+1][:])
            probes_found += 1
            count_probe = 1

            if (next_scan[1] - j[1]) >= W_s:
                final_scan_list.append(port_list[i-count_scan+1:i+1][:])
                scans_found += 1
                count_scan = 1
            else:
                count_scan += 1

        elif (j[1] != next_scan[1] or j[1] == next_scan[1]) and (next_scan[1] - j[1]) <= W_s:
            count_scan += 1
            if j[1] == next_scan[1] and width >= W_p:
                if (count_probe >= N_p):
                    final_probe_list.append(port_list[i-count_probe+1:i+1][:])
                    probes_found += 1
                count_probe = 1
                
        elif (j[1] != next_scan[1] or j[1] == next_scan[1]) and count_scan >= N_s:
            final_scan_list.append(port_list[i-count_scan+1:i+1][:])
            scans_found += 1
            count_scan = 1
            if j[1] == next_scan[1] and width >= W_p:
                count_probe = 1
                      
        else:
            count_scan = 1
            count_probe = 1
        
def print_result(flag, port_list = []):
    packets = 0
    counter = 0
    
    for i,j in enumerate(port_list):
        for k,l in enumerate(port_list[i]):
            if k == 0 and flag == 1:
                print "Probe: [{} Packets]".format(len(port_list[i]))
            elif k == 0 and flag == 2:
                print "Scan: [{} Packets]".format(len(port_list[i]))       
            print "\tPacket [TimeStamp: {}, {}, Source IP: {}]".format(j[k][0], j[k][1], j[k][2])

        counter += 1
        

def main():
    # parse all the arguments to the client
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 2')
    parser.add_argument('-f', '--filename', type=str, help='pcap file to input', required=True)
    parser.add_argument('-t', '--targetip', type=str, help='a target IP address', required=True)
    parser.add_argument('-l', '--wp', type=int, help='Wp', required=True)
    parser.add_argument('-m', '--np', type=int, help='Np', required=True)
    parser.add_argument('-n', '--ws', type=int, help='Ws', required=True)
    parser.add_argument('-o', '--ns', type=int, help='Ns', required=True)

    # get the parameters into local variables
    args = vars(parser.parse_args())
    file_name = args['filename']
    target_ip = args['targetip']
    W_p = args['wp']
    N_p = args['np']
    W_s = args['ws']
    N_s = args['ns']

    input_data = dpkt.pcap.Reader(open(file_name,'r'))
    
    tcp_list = []
    udp_list = []
    for timestamp, packet in input_data:
        # this converts the packet arrival time in unix timestamp format
        # to a printable-string
        time_string = datetime.datetime.utcfromtimestamp(timestamp)
        # your code goes here ...
    
        eth = dpkt.ethernet.Ethernet(packet)

        if eth.type != dpkt.ethernet.ETH_TYPE_IP:
            continue

        ip = eth.data
        if inet_to_str(ip.dst) != target_ip:
            continue

        #check for TCP packet
        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp = ip.data
            tcp_list.append((time_string, tcp.dport, inet_to_str(ip.src)))
            tcp_list.sort(key=lambda tup:tup[1])

        elif ip.p == dpkt.ip.IP_PROTO_UDP:
            udp = ip.data
            udp_list.append((time_string, udp.dport, inet_to_str(ip.src)))
            udp_list.sort(key=lambda tup:tup[1])
            
    count = 1
    global final_probe_list
    global probes_found
    global scans_found
        
    get_ports(W_p, N_p, W_s, N_s, tcp_list)
    print "Reports for TCP"
    print "Found", probes_found, "probes"
    print_result(1, final_probe_list)
    print "Found", scans_found, "scans"
    print_result(2, final_scan_list)

    
    
    probes_found = 0
    scans_found = 0
    del final_probe_list[:]
    del final_scan_list[:]
    get_ports(W_p, N_p, W_s, N_s, udp_list)

    print "Reports for UDP"
    print "Found", probes_found, "probes"
    print_result(1, final_probe_list)
    print "Found", scans_found, "scans"
    print_result(2, final_scan_list)


# execute a main function in Python
if __name__ == "__main__":
    main()
