###################################################################################################
# This script send packets in all VLANs [1-4094] with all possible priorities [0-7].
###################################################################################################

import l2tester
import sys
import time

from scapy.packet import Raw
from scapy.layers.l2 import Ether, Dot1Q

# Uncomment to enable debugs.
#l2tester.Logger.config_log_level( l2tester.Logger.L2T_LOG_DEBUG )

if len(sys.argv) < 2 :

	print """
  This script send packets in all VLANs [1-4094] with all possible priorities [0-7].
  Usage: python send_all_vlans.py <iface> [interval]
  Arguments
    iface             : Interface that will output frames. Ex: eth0
    interval          : Interval in ms between each frame. Default: 1 ms.
  """

else:
	if_src = sys.argv[1]
	# Get interval if user supplied!
	interval_ms = 1.0
	if len(sys.argv) > 2 :
		interval_ms = float(sys.argv[2])
	try:

		action_vlan = l2tester.Action()
		action_vlan.type = l2tester.Action.ACTION_INCREMENT
		action_vlan.mask = 0x0FFF000000000000
		action_vlan.byte = 14
		action_vlan.range_first = 1
		action_vlan.range_last = 4094

		action_prio = l2tester.Action()
		action_prio.type = l2tester.Action.ACTION_INCREMENT
		action_prio.mask = 0xE000000000000000
		action_prio.byte = 14
		action_prio.range_first = 0
		action_prio.range_last = 7

		action_vlan.chain_action(action_prio, l2tester.Action.ACTION_CHAIN_WHEN_FINISHED)
		packet = Ether(src = '10:00:01:02:03:04', dst = 'FF:FF:FF:FF:FF:FF') / Dot1Q(vlan = 0, type = 0x5010) / Raw('\0' * 100)

		sender = l2tester.Sender(if_src, str(packet))
		sender.manual_bandwidth(1, int(interval_ms*1000000));
		sender.set_action(action_vlan)

		started = time.time()
		sender.run(4094*8)
		print "Took %.3f s" % (time.time() - started)

	except Exception as e:
		print e
