# Packet-Stream-Scanner
Program that scans .pcap files to identify probes and scans in a stream of packets.
Intuitively, a probe is when an agent makes repeated attempts to access or discover a service on a port. A scan is a when an agent tries to map large parts of the IP address/port space to see if there are any running services on those ports. The program will read in a packet trace as a pcap file, a target IP address, and output a list of probes and scans found against that IP address, as well as the originating IP addresses of the probes and scans. 
