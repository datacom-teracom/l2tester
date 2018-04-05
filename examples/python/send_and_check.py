###################################################################################################
# This script demonstrate the use of the SendAndCheck feature.
# From source interface, 2 tagged and 2 untagged packets are sent.
# In destination, we expect 1 tagged and 3 untagged. If interfaces are direct connect,
# we will see:
# - 3 received packets: 1 tagged and 2 untagged
# - 1 missed packet: 1 untagged
# - 1 unexpected packet: 1 tagged
###################################################################################################

import l2tester
import sys

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q

def print_frame_mapping(mapping):
	""" Print to stdout the received frame mapping.
	@param mapping           Dictionary of interfaces to frame list.
	"""
	if mapping:
		for iface, frame_list in mapping.items():
			print "  * " + iface + ":"
			for frame in frame_list:
				print "    - " + Ether(frame).summary()
	else:
		print "  * None"

if len(sys.argv) < 3 :

	print """
  Usage: python {0} <src> <dst>
  Arguments
    src               : Source ethernet interface. Ex eth0
    dst               : Destination ethernet interface. Ex eth1
  """.format(sys.argv[0])

else:

	if_src = sys.argv[1]
	if_dst = sys.argv[2]

	try:

		untag = Ether(src = '10:00:01:02:03:04', dst = 'FF:FF:FF:FF:FF:FF', type = 0x5010) / Raw('\0' * 100)
		tag100 = Ether(src = '10:00:01:02:03:04', dst = 'FF:FF:FF:FF:FF:FF') / Dot1Q(vlan=100, type = 0x5010) / Raw('\0' * 100)

		filter = l2tester.EthernetFilter()
		filter.src_mac = '10:00:01:02:03:04'
		filter.compile()

		send_frames = {
			if_src : 2 * [ str(untag), str(tag100) ],
		}

		expected_frames = {
			if_src : [],
			if_dst : [ str(tag100) ] + 3 * [ str(untag) ],
		}

		send_and_check = l2tester.SendAndCheck(send_frames, expected_frames, 1000, filter)
		send_and_check.run()

		print "\nReceived frames:"
		print_frame_mapping(send_and_check.get_received_frames())

		print "\nMissed frames:"
		print_frame_mapping(send_and_check.get_missed_frames())

		print "\nUnexpected frames:"
		print_frame_mapping(send_and_check.get_unexpected_frames())

	except Exception as e:
		print e
