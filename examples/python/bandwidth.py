###################################################################################################
# L2T::Bandwidth example:
#   This script is intended to be used as an example of how to use l2tester Bandwidth functionality.
#   We configure 2 TxStreams, using different VLANs and 2 Streams filtering by VLANs.
#   For the first part, we progressively increase the bandwidth of the first TxStream.
#   Test Stream deletion and recreation and for the second part, progressively decrease the
#   bandwidth of the first TxStream.
###################################################################################################

import l2tester
import sys
from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q

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
	recv = l2tester.Bandwidth_Monitor([if_dst])

	# Create Streams
	f0 = l2tester.EthernetFilter()
	f0.outer_vlan = 10
	f0.dst_mac = 'FF:FF:FF:FF:FF:FF'
	f0.compile()
	rx0 = recv.new_stream(f0)

	f1 = l2tester.EthernetFilter()
	f1.outer_vlan = 20
	f1.compile()
	rx1 = recv.new_stream(f1)

	# Start sniffer
	recv.start()

	# Create new TxStream
	frame0 = Ether( src= '10:00:01:02:03:04', dst= 'FF:FF:FF:FF:FF:FF' ) / Dot1Q(vlan=10) / Raw( load=78*'\0' )
	tx0 = l2tester.Sender(if_src, str(frame0))
	band = 500000;
	tx0.auto_bandwidth(band)
	tx0.start()

	# Another TxStream
	frame1 = Ether( src= '10:00:01:02:03:05', dst= 'FF:FF:FF:FF:FF:FF' ) / Dot1Q(vlan=20) / Raw( load=78*'\0' )
	tx1 = l2tester.Sender(if_src, str(frame1))
	tx1.auto_bandwidth(3000000)
	tx1.start()

	print "First round."

	# Iterate over results
	for i in range(10):
		for stream in [ rx0, rx1 ]:
			# The default behavior of 'iterate_reading' is to way until next one is available.
			# No waiting is needed.
			m = stream.iterate_reading()
			print " [{0}] {1} bps / {2} pps".format( m.timestamp_ms, m.bits_per_sec, m.packets_per_sec )
		# TxStream 0 grows periodically:
		band = int(band * 1.2)
		# Show that we can change bandwidth in runtime!
		tx0.auto_bandwidth(band)

	# Remove Stream during sniffing
	recv.delete_stream(rx0)
	print "Deleted Stream 0."

	for i in range(5):
		m = rx1.iterate_reading()
		print " [{0}] {1} bps / {2} pps".format( m.timestamp_ms, m.bits_per_sec, m.packets_per_sec )

	# Recreate Stream while sniffing!
	rx0 = recv.new_stream(f0)
	print "Recreated Stream 0."

	for i in range(10):
		for stream in [ rx0, rx1 ]:
			m = stream.iterate_reading()
			print " [{0}] {1} bps / {2} pps".format( m.timestamp_ms, m.bits_per_sec, m.packets_per_sec )

	recv.stop()
	tx0.stop()
	tx1.stop()

	print "Second round."

	recv.start()
	tx0.start()
	tx1.start()

	# Iterate over results
	for i in range(10):
		for stream in [ rx0, rx1 ]:
			m = stream.iterate_reading()
			print " [{0}] {1} bps / {2} pps".format( m.timestamp_ms, m.bits_per_sec, m.packets_per_sec )
		# TxStream 0 shrink periodically:
		band = int(band * 0.8)
		tx0.auto_bandwidth(band)

	recv.stop()
	tx0.stop()
	tx1.stop()
