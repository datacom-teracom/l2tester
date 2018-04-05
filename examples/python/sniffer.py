###################################################################################################
# Example of Sniffer extension in target language.
###################################################################################################

import l2tester
import sys, time
from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q

class PySniffer(l2tester.Sniffer):
	""" Extend L2T::Sniffer to perform actions in Python for each captured packet.
	"""
	def __init__(self, timeout_ms):
		""" Initialize base class.
		@param timeout_ms    Base time for select operation in milliseconds.
		"""
		l2tester.Sniffer.__init__(self, timeout_ms)

	def received_packet(self, iface, filter, packet):
		""" Reimplement C++ virtual method. Called for each received packet that matches any filter.
		@param iface         Interface index that received the packet.
		@param filter        Filter index that matched the packet.
		@param packet        Packet in raw string format.
		@param return        Always return True to keep reception going.
		"""
		print Ether(packet).summary()
		return True

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

	# Change logging LEVEL for l2tester module
	l2tester.Logger.config_log_level( l2tester.Logger.L2T_LOG_DEBUG )

	# Create Sniffer using passed interface.
	recv = PySniffer(1000)
	recv.add_interfaces([if_dst])
	recv.add_filter()

	# Start sniffer
	recv.start()

	# Create new TxStream
	frame0 = Ether( src= '10:00:01:02:03:04', dst= 'FF:FF:FF:FF:FF:FF' ) / Dot1Q(vlan=10) / Raw( load=78*'\0' )
	tx0 = l2tester.Sender(if_src, str(frame0))
	band = 500;
	tx0.auto_bandwidth(band)
	tx0.start()

	time.sleep(4)

	recv.stop()
	tx0.stop()

