#! /usr/bin/env python

###################################################################################################
# Script to generate specific random streams intended to verify correct load-balance in LAGs.
# An inverse stream is sent from destination to source to perform MAC learning.
# It can operate in two modes:
# 1) Limited: in this mode, the total number of packets that should be sent is known and was
#    defined by options -n. First, all inverted packets are sent from destination to source.
#    After, if they were all received, the target flow is sent from source to destination.
#    We verify that all sent packets were received. In case of errors, TrafficFlow::Monitor
#    statistics are displayed.
# 2) Unlimited: in this mode we continually send packets. As we don't know how many we should send,
#    normal and inverted flows are sent simultaneously. We can't ensure MAC learning, but as inverted
#    stream is started first, in normal conditions MAC learning should be OK.
###################################################################################################

import l2tester
import sys

from scapy.packet import Raw
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP, TCP, ICMP
from l2tester.packet import MPLS

from optparse import OptionParser

def check_monitor_errors(monitor):
	""" Verify that TrafficFlow_Monitor executed with no errors.
	@param monitor       Instance that should be verified.
	"""
	stats = l2tester.TrafficFlow_Statistics()
	monitor.get_statistics(stats)

	if stats.loop_detected_intervals > 0 :
		raise Exception("Loop detected during {0} ms.".format(stats.loop_detected_ms))
	elif stats.received_packets == 0 :
		raise Exception("No packets received.")
	elif stats.traffic_interruption_intervals > 0 :
		raise Exception("Traffic interrupted during {0} ms. Received {1} from {2} sent packets.".format(
				stats.traffic_interruption_ms, stats.received_packets, stats.sent_packets))


def main():
	parser = OptionParser(usage="""%prog [options] <src> <dst>
	    src               : Source ethernet interface. Ex: eth0
	    dst               : Destination ethernet interface. Ex: eth1
	""")

	parser.add_option("-c", "--criteria",
			help="""
			Load balance criteria: src-mac, dst-mac, src-dst-mac,
			                       src-ip, dst-ip, src-dst-ip,
			                       mpls-top-sec, mpls-top, mpls-sec,
			                       src-tcp, dst-tcp, src-dst-tcp,
			                       src-udp, dst-udp, src-dst-udp
			""", default="src-dst-mac",
			action="store", type="string", dest="criteria")

	parser.add_option("-i", "--interval",
		help="Define packet interval in milliseconds.", default=100,
		action="store", type="int", dest="interval")

	parser.add_option("-n", "--num_packets",
		help="Send specified number of packets. Default: send indefinitely.", default=0,
		action="store", type="int", dest="num_packets")

	parser.add_option("-d", "--debug",
		help="Enable L2tester debuging.", default=False,
		action="store_true", dest="debug")

	(options, args) = parser.parse_args()

	if len(args) < 2:
		parser.error("must specify interfaces to use")
	if options.debug:
		l2tester.Logger.config_log_level( l2tester.Logger.L2T_LOG_DEBUG ) 
	if options.criteria not in ["dst-ip", "dst-mac", "src-dst-ip", "src-dst-mac", "src-ip", "src-mac", "src-udp", "dst-udp", "src-dst-udp",
								"src-tcp", "dst-tcp", "src-dst-tcp", "mpls-top-sec", "mpls-top", "mpls-sec"]:
		parser.error("invalid criteria '{0}'".format(options.criteria))

	if_src = args[0]
	if_dst = args[1]

	try:

		if_src_action = l2tester.Action()
		if_src_action.type = l2tester.Action.ACTION_RANDOMIZE
		if_src_action.seed = 10

		if_src_filter = l2tester.EthernetFilter()

		if_dst_action = l2tester.Action()
		if_dst_action.type = l2tester.Action.ACTION_RANDOMIZE
		if_dst_action.seed = 10

		if_dst_filter = l2tester.EthernetFilter()

		if 'udp' in options.criteria:
			if_src_action.mask = 0xFFFF000000000000
			if_src_action.range_first = 1
			if_src_action.range_last = 0x03FF # Port 1023

			if_src_filter.dst_mac = '10:00:01:02:03:FF'
			if_src_filter.compile()
			if_src_packet = Ether(src = '10:00:01:02:03:04', dst = '10:00:01:02:03:FF') / IP(src='192.168.42.01', dst='192.168.42.02') / UDP(sport=18, dport=50) /Raw( '\0' * 100 )

			if_dst_action.mask = 0xFFFF000000000000
			if_dst_action.range_first = 1
			if_dst_action.range_last = 0x03FF # Port 1023

			if_dst_filter.src_mac = '10:00:01:02:03:FF'
			if_dst_filter.compile()
			if_dst_packet = Ether(src = '10:00:01:02:03:FF', dst = '10:00:01:02:03:04') / IP(src='192.168.42.02', dst='192.168.42.01') / UDP(sport=50, dport=18) /Raw( '\0' * 100 )

			if options.criteria == 'src-dst-udp':

				# Source Interface generate random source and destination UDP port

				if_src_extra_action = l2tester.Action()
				if_src_extra_action.type = l2tester.Action.ACTION_RANDOMIZE
				if_src_extra_action.mask = 0xFFFF000000000000
				if_src_extra_action.byte = 34    # Source UDP port
				if_src_extra_action.range_first = 1
				if_src_extra_action.range_last = 0x03FF # Port 1023

				if_src_action.byte = 36          # Destination UDP port
				if_src_action.chain_action(if_src_extra_action)

				# Destination Interface generate random source and destination UDP port (but seeds are inverted)

				if_dst_extra_action = l2tester.Action()
				if_dst_extra_action.type = l2tester.Action.ACTION_RANDOMIZE
				if_dst_extra_action.mask = 0xFFFF000000000000
				if_dst_extra_action.byte = 36    # Destination UDP port
				if_dst_extra_action.range_first = 1
				if_dst_extra_action.range_last = 0x03FF # Port 1023

				if_dst_action.byte = 34          # Source UDP port
				if_dst_action.chain_action(if_dst_extra_action)

			elif options.criteria == 'src-udp':
				if_src_action.byte = 34
				if_dst_action.byte = 36
			else: # options.criteria == 'dst-udp':
				if_src_action.byte = 36
				if_dst_action.byte = 34

		if 'tcp' in options.criteria:
			if_src_action.mask = 0xFFFF000000000000
			if_src_action.range_first = 1
			if_src_action.range_last = 0x03FF # Port 1023

			if_src_filter.dst_mac = '10:00:01:02:03:FF'
			if_src_filter.compile()
			if_src_packet = Ether(src = '10:00:01:02:03:04', dst = '10:00:01:02:03:FF') / IP(src='192.168.42.01', dst='192.168.42.02') / TCP(sport=21, dport=57) /Raw( '\0' * 100 )

			if_dst_action.mask = 0xFFFF000000000000
			if_dst_action.range_first = 1
			if_dst_action.range_last = 0x03FF # Port 1023

			if_dst_filter.src_mac = '10:00:01:02:03:FF'
			if_dst_filter.compile()
			if_dst_packet = Ether(src = '10:00:01:02:03:FF', dst = '10:00:01:02:03:04') / IP(src='192.168.42.02', dst='192.168.42.01') / TCP(sport=57, dport=21) /Raw( '\0' * 100 )

			if options.criteria == 'src-dst-tcp':

				# Source Interface generate random source and destination UDP port

				if_src_extra_action = l2tester.Action()
				if_src_extra_action.type = l2tester.Action.ACTION_RANDOMIZE
				if_src_extra_action.mask = 0xFFFF000000000000
				if_src_extra_action.byte = 34    # Source TCP port
				if_src_extra_action.range_first = 1
				if_src_extra_action.range_last = 0x03FF # Port 1023

				if_src_action.byte = 36          # Destination TCP port
				if_src_action.chain_action(if_src_extra_action)

				# Destination Interface generate random source and destination TCP port (but seeds are inverted)

				if_dst_extra_action = l2tester.Action()
				if_dst_extra_action.type = l2tester.Action.ACTION_RANDOMIZE
				if_dst_extra_action.mask = 0xFFFF000000000000
				if_dst_extra_action.byte = 36    # Destination TCP port
				if_dst_extra_action.range_first = 1
				if_dst_extra_action.range_last = 0x03FF # Port 1023

				if_dst_action.byte = 34          # Source TCP port
				if_dst_action.chain_action(if_dst_extra_action)

			elif options.criteria == 'src-tcp':
				if_src_action.byte = 34
				if_dst_action.byte = 36
			else: # options.criteria == 'dst-tcp'
				if_src_action.byte = 36
				if_dst_action.byte = 34

		if 'ip' in options.criteria:

			checksum_action = l2tester.Action()
			checksum_action.byte = 24
			checksum_action.type = l2tester.Action.ACTION_IPV4_CHECKSUM

			if_src_action.mask = 0xFFFFFFFF00000000
			if_src_action.range_first = 1
			if_src_action.range_last = 0xE0000000 # Create random IPs smaller than first multicast 224.0.0.0

			if_src_filter.dst_mac = '10:00:01:02:03:FF'
			if_src_filter.compile()
			if_src_packet = Ether(src = '10:00:01:02:03:04', dst = '10:00:01:02:03:FF') / IP(src='192.168.42.01', dst='192.168.42.02') / Raw( '\0' * 100 )

			if_dst_action.mask = 0xFFFFFFFF00000000
			if_dst_action.range_first = 1
			if_dst_action.range_last = 0xE0000000 # Create random IPs smaller than first multicast 224.0.0.0

			if_dst_filter.src_mac = '10:00:01:02:03:FF'
			if_dst_filter.compile()
			if_dst_packet = Ether(src = '10:00:01:02:03:FF', dst = '10:00:01:02:03:04') / IP(src='192.168.42.02', dst='192.168.42.01') / Raw( '\0' * 100 )

			if options.criteria == 'src-dst-ip':

				# Source Interface generate random source and destination IP

				if_src_extra_action = l2tester.Action()
				if_src_extra_action.type = l2tester.Action.ACTION_RANDOMIZE
				if_src_extra_action.mask = 0xFFFFFFFF00000000
				if_src_extra_action.byte = 26    # Source IP
				if_src_extra_action.range_first = 1
				if_src_extra_action.range_last = 0xE0000000 # Create random IPs smaller than first multicast 224.0.0.0
				if_src_extra_action.chain_action( checksum_action )

				if_src_action.byte = 30          # Destination IP
				if_src_action.chain_action(if_src_extra_action)

				# Destination Interface generate random source and destination IP (but seeds are inverted)

				if_dst_extra_action = l2tester.Action()
				if_dst_extra_action.type = l2tester.Action.ACTION_RANDOMIZE
				if_dst_extra_action.mask = 0xFFFFFFFF00000000
				if_dst_extra_action.byte = 30    # Destination IP
				if_dst_extra_action.range_first = 1
				if_dst_extra_action.range_last = 0xE0000000 # Create random IPs smaller than first multicast 224.0.0.0
				if_dst_extra_action.chain_action( checksum_action )

				if_dst_action.byte = 26          # Source IP
				if_dst_action.chain_action(if_dst_extra_action)

			else:

				# For single IP, chain action directly to checksum.
				if_src_action.chain_action(checksum_action)
				if_dst_action.chain_action(checksum_action)

				if options.criteria == 'dst-ip':
					if_src_action.byte = 30      # Destination IP
					if_dst_action.byte = 26      # Source IP
				elif options.criteria == 'src-ip':
					if_src_action.byte = 26      # Source IP
					if_dst_action.byte = 30      # Destination IP

		if 'mpls' in options.criteria:
			if_src_action.mask = 0xFFFFF00000000000
			if_src_action.range_first = 16 # Labels 0 to 15 are reserved.
			if_src_action.range_last = 0xFFFFF #Last valid label (2^20 - 1).

			if_src_filter.dst_mac = '10:00:01:02:03:FF'
			if_src_filter.compile()
			if_src_packet = Ether(src = '10:00:01:02:03:04', dst = '10:00:01:02:03:FF') / MPLS(s=0) / MPLS() / IP(src='192.168.42.01', dst='192.168.42.02') / ICMP() / Raw( '\0' * 100 )

			if_dst_action.mask = 0xFFFFF00000000000
			if_dst_action.range_first = 0x10 # Labels 0 to 15 are reserved.
			if_dst_action.range_last = 0xFFFFF # Last valid label (2^20 - 1).

			if_dst_filter.src_mac = '10:00:01:02:03:FF'
			if_dst_filter.compile()
			if_dst_packet = Ether(src = '10:00:01:02:03:FF', dst = '10:00:01:02:03:04') / MPLS(s=0) / MPLS() / IP(src='192.168.42.02', dst='192.168.42.01') / ICMP() / Raw( '\0' * 100 )

			if options.criteria == 'mpls-top-sec':
				# Source Interface generates random MPLS top and second labels

				if_src_extra_action = l2tester.Action()
				if_src_extra_action.type = l2tester.Action.ACTION_RANDOMIZE
				if_src_extra_action.mask = 0xFFFFF00000000000
				if_src_extra_action.byte = 14    # Top label
				if_src_extra_action.range_first = 0x10 # Labels 0 to 15 are reserved.
				if_src_extra_action.range_last = 0xFFFFF # Last valid label (2^20 - 1).

				if_src_action.byte = 18          # Second label
				if_src_action.chain_action(if_src_extra_action)

				# Destination Interface generates random MPLS top and second labels

				if_dst_extra_action = l2tester.Action()
				if_dst_extra_action.type = l2tester.Action.ACTION_RANDOMIZE
				if_dst_extra_action.mask = 0xFFFFF00000000000
				if_dst_extra_action.byte = 14     # Top label
				if_dst_extra_action.range_first = 0x10 # Labels 0 to 15 are reserved.
				if_dst_extra_action.range_last = 0xFFFFF # Last valid label (2^20 - 1).

				if_dst_action.byte = 18          # Second label
				if_dst_action.chain_action(if_dst_extra_action)

			elif options.criteria == 'mpls-top':
				if_src_action.byte = 14
				if_dst_action.byte = 14
			else: # options.criteria == 'mpls-sec':
				if_src_action.byte = 18
				if_dst_action.byte = 18

		if 'mac' in options.criteria:

			if_src_action.mask = 0xFEFFFFFFFFFF0000

			if_src_filter.outer_tpid = 0x5010
			if_src_filter.compile()
			if_src_packet = Ether(src = '10:00:01:02:03:01', dst = '10:00:01:02:03:02', type = 0x5010) / Raw( '\0' * 100 )

			if_dst_action.mask = 0xFEFFFFFFFFFF0000

			if_dst_filter.outer_tpid = 0x5011
			if_dst_filter.compile()
			if_dst_packet = Ether(src = '10:00:01:02:03:02', dst = '10:00:01:02:03:01', type = 0x5011) / Raw( '\0' * 100 )

			if options.criteria == 'src-dst-mac':

				# Source Interface generate random source and destination MAC

				if_src_extra_action = l2tester.Action()
				if_src_extra_action.type = l2tester.Action.ACTION_RANDOMIZE
				if_src_extra_action.mask = 0xFEFFFFFFFFFF0000
				if_src_extra_action.byte = 6    # Source MAC

				if_src_action.byte = 0          # Destination MAC
				if_src_action.chain_action(if_src_extra_action)

				# Destination Interface generate random source and destination MAC (but seeds are inverted)

				if_dst_extra_action = l2tester.Action()
				if_dst_extra_action.type = l2tester.Action.ACTION_RANDOMIZE
				if_dst_extra_action.mask = 0xFEFFFFFFFFFF0000
				if_dst_extra_action.byte = 0     # Destination MAC

				if_dst_action.byte = 6           # Source MAC
				if_dst_action.chain_action(if_dst_extra_action)

			elif options.criteria == 'dst-mac':
				if_src_action.byte = 0           # Destination MAC
				if_dst_action.byte = 6           # Source MAC

			else: # options.criteria == 'src-mac'
				if_src_action.byte = 6           # Destination MAC
				if_dst_action.byte = 0           # Source MAC

		src_to_dst_monitor = l2tester.TrafficFlow_Monitor( if_src, if_dst, str(if_src_packet), options.interval, if_src_action, if_src_filter )

		if options.num_packets:
			# Limited Mode
			try:
				sys.stdout.write("Learning MACs... ")
				dst_to_src_monitor = l2tester.TrafficFlow_Monitor(if_dst, if_src, str(if_dst_packet), options.interval, if_dst_action, if_dst_filter)
				dst_to_src_monitor.run(options.num_packets if 'mac' in options.criteria else 1) #Send more than one packet on the other direction only if criteria is by MAC
				check_monitor_errors(dst_to_src_monitor)
				sys.stdout.write("OK!\n")
				sys.stdout.write("Sending random stream... ")
				src_to_dst_monitor.run(options.num_packets)
				check_monitor_errors(src_to_dst_monitor)
				sys.stdout.write("OK!\n")
			except Exception as e:
				sys.stdout.write(str(e) + "\n")

			return
		else:
			# Unlimited Mode
			# Inverted stream is defined as simple sender (and not as monitor) because it will operate concurrently with monitored stream.
			dst_to_src_sender = l2tester.Sender( if_dst, str(if_dst_packet) )
			dst_to_src_sender.set_action( if_dst_action )
			dst_to_src_sender.manual_bandwidth( 1, 1000000 * options.interval )

			dst_to_src_sender.start()

			print """
===============================================================================
   Timestamp (ms) |       Delta (ms) | Event
-------------------------------------------------------------------------------"""
			last_event_ms = 0
			src_to_dst_monitor.start()
			while True:
				try :
					event = src_to_dst_monitor.iterate_event(0, True, 1000);
					if event:
						print " {0:>16} | {1:>16} | {2}".format(
								event.timestamp_ms, event.timestamp_ms - last_event_ms,
								l2tester.TrafficFlow_Event.type_to_str(event.type))
						last_event_ms = event.timestamp_ms
						if event.type == l2tester.TrafficFlow_Event.TEST_FINISHED :
							break;

				except KeyboardInterrupt:
					src_to_dst_monitor.stop()

		dst_to_src_sender.stop()

		stats = l2tester.TrafficFlow_Statistics()
		src_to_dst_monitor.get_statistics(stats)

		print """
===============================================================================
  Traffic Interruption
    Total     : {0} ms
    Intervals : {1}
  Loop Detection
    Total     : {2} ms
    Intervals : {3}
  Packets
    Sent      : {4}
    Received  : {5}
    Dropped   : {6}
  {7}
===============================================================================
""".format(
				stats.traffic_interruption_ms,
				stats.traffic_interruption_intervals,
				stats.loop_detected_ms,
				stats.loop_detected_intervals,
				stats.sent_packets,
				stats.received_packets,
				stats.dropped_packets,
				" ** MONITOR ABORTED **" if stats.error_detected else "")

	except Exception as e:
		print e

if __name__ == "__main__":
	main()
