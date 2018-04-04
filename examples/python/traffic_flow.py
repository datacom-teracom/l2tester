
import l2tester
import sys

from scapy.packet import Raw
from scapy.layers.l2 import Ether

#l2tester.Logger.config_log_level( l2tester.Logger.L2T_LOG_DEBUG )

if len(sys.argv) < 3 :

	print """
  Usage: python traffic_flow.py <src> <dst> [interval]
  Arguments
    src               : Source ethernet interface. Ex: eth0
    dst               : Destination ethernet interface. Ex: eth1
    interval          : Interval in ms for monitor precision. Default: 10 ms.
  """

else:
	if_src = sys.argv[1]
	if_dst = sys.argv[2]

	# Get interval if user supplied!
	interval_ms = 10
	if len(sys.argv) > 3 :
		interval_ms = int(sys.argv[3])

	try:

		action = l2tester.Action()
		action.type = l2tester.Action.ACTION_INCREMENT
		action.mask = 0x0FFF000000000000
		action.byte = 14
		action.range_first = 1
		action.range_last = 4094;

		filter = l2tester.EthernetFilter()
		filter.src_mac = '10:00:01:02:03:04'
		filter.compile()

		packet = Ether(src = '10:00:01:02:03:04', dst = 'FF:FF:FF:FF:FF:FF', type = 0x5010) / Raw('\0' * 100)
		monitor = l2tester.TrafficFlow_Monitor(if_src, if_dst, str(packet), interval_ms, action, filter)

		print """
===============================================================================
   Timestamp (ms) |       Delta (ms) | Event
-------------------------------------------------------------------------------"""
		last_event_ms = 0
		monitor.start()
		while True:
			try :
				event = monitor.iterate_event(0, True, 1000)
				if event:
					print " {0:>16} | {1:>16} | {2}".format(
						event.timestamp_ms, event.timestamp_ms - last_event_ms,
						l2tester.TrafficFlow_Event.type_to_str(event.type) )
					last_event_ms = event.timestamp_ms
					if event.type == l2tester.TrafficFlow_Event.TEST_FINISHED :
						break

			except KeyboardInterrupt:
				monitor.stop()

		stats = l2tester.TrafficFlow_Statistics()
		monitor.get_statistics( stats )

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
				" ** MONITOR ABORTED **" if stats.error_detected else "" )

	except Exception as e:
		print e
