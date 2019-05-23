import random
import re

from scapy.packet import Packet, Raw, Padding, bind_layers, bind_bottom_up, bind_top_down
from scapy.fields import IntField, BitField, ByteField
from scapy.layers.l2 import Ether, Dot3, Dot1Q, LLC, SNAP, STP
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.utils import checksum

from interface import mac_address

## Class MAC Address ##############################################################################

class MacAddress(list):

	def __init__(self, value):
		""" Constructor
		@value MAC address represented as a string (XX:XX:XX:XX:XX:XX)
		"""
		list.__init__(self)
		if type(value) == list:
			self.extend(value)
			filter(lambda x: type(x) == int and x >= 0 and x <= 255, self)
			if len(self) != 6:
				raise TypeError("A MacAddress is a list of 6 integers in the range [0..255]")
		elif type(value) == str:
			if not re.match ("^([\da-fA-F]{2}:){5}[\da-fA-F]{2}$", value):
				raise TypeError("A MacAddress is a hexadecimal string in the format XX:XX:XX:XX:XX:XX")
			self.extend(map(lambda x: int(x, 16), value.split(':')))
		else:
			self.extend(6 * [0])

	def __setitem__(self, key, value):
		""" Sets an octet of the MAC address
		@param key Octet index
		@param value New value to the octet
		"""
		list.__setitem__(self, key, value % 255)

	def __getslice__(self, i, j):
		""" Returns a slice of the MAC address
		@param i Slice's first element 
		@param j Slice's last element
		"""
		return MacAddress(list.__getslice__(self, i, j))

	def __str__(self):
		""" Returns the MAC address as a string
		"""
		return ':'.join(map(lambda x: "%02X" % x, self))


## Enhance Dot1Q ##################################################################################
# Default scapy implementation does not calculate length field in 802.1Q tags when enconding with
# 802.3 frame format. If the next layer after Dot1Q is LLC, then we consider the type field as length.
#

def dot1q_summary(self):
	""" Redefined summary for Dot1Q header.
	"""
	s = 'vlan %d' % self.vlan
	if self.prio > 0:
		s += ', prio %d' % (self.prio)
	if self.type != None and self.type > 1535:
		s += ' (0x%x)' % self.type
	elif self.type == None or self.type <= 1500:
		s += ' (802.3)'
	else:
		s += ' (invalid)'
	return s, [Ether, Dot1Q, Dot3]

Dot1Q.mysummary = dot1q_summary

def dot1q_post_build(self, packet, payload):
	""" Implement post build to calculate length for 802.3 frame.
	"""
	if self.type == None or self.type <= 1500 :
		l = len(payload)
		packet = packet[:2] + chr((l >> 8) & 0xff) + chr(l & 0xff)
		self.type = l
	return packet + payload

Dot1Q.post_build = dot1q_post_build

bind_layers(Dot3, Dot1Q, len = 0x8100)
bind_layers(Dot1Q, LLC, type = None)
bind_bottom_up(Ether, Dot1Q, type = 0x9100)
bind_bottom_up(Ether, Dot1Q, type = 0x9200)
bind_bottom_up(Ether, Dot1Q, type = 0x88a8)

## L2T packet extension ###########################################################################

class L2T( Packet ):
	""" Define simple L2 header containing only a uint32 sequence number as data.
	Binds with ethernet layer using 0x5010 ethertype.
	"""
	name = 'L2T'
	fields_desc = [ IntField('l2t_seq', 0) ]

	def mysummary(self):
		""" Summary of L2T packet.
		"""
		return 'seq : %d' % (self.l2t_seq), [Ether, Dot1Q, Dot3]

bind_layers(Ether, L2T, type = 0x5010)
bind_layers(SNAP, L2T, code = 0x5010)

## MPLS packet extension ###########################################################################

class MPLS( Packet ):
	"""
	"""
	name = "MPLS-Unicast"
	fields_desc = [ BitField("label", 3, 20),
					BitField("exp", 0, 3),
					BitField("s", 1, 1),
					ByteField("ttl", 255) ]

	def mysummary(self):
		""" Summary of MPLS packet.
		"""
		s = 'label: %s' % ( self.label )
		if (self.exp != 0):
			s += ', exp: %s' % ( self.exp )
		if (self.s != 1):
			s += ', s: %s' % ( self.s )
		s += ', ttl: %s' % ( self.ttl )
		return s, [Ether, Dot1Q, Dot3]

	def guess_payload_class(self, payload):
		"""Implements guess_payload_class to identify MPLS packets with internal Ethernet header"""
		# If bottom of stack is zero, the next layer is MPLS for sure.
		if len(payload) >= 1:
			if self.s == 0:
				return MPLS

			ip_version = (payload[0] >> 4) & 0xF
			if ip_version == 4:
				return IP
			elif ip_version == 6:
				return IPv6
			else:
				return Ether

		return Padding

bind_layers(Ether, MPLS, type=0x8847)
bind_bottom_up(Ether, MPLS, type=0x8848)
bind_layers(Dot1Q, MPLS, type=0x8847)
bind_bottom_up(Dot1Q, MPLS, type=0x8848)
bind_top_down(MPLS, MPLS, s=0)

## Redefine IP summary ############################################################################

def ip_summary(self):
	""" Redefined summary for IP header.
	It's same as defined in scapy, but also request to output Dot1Q header.
	"""
	s = '%s > %s' % ( self.src, self.dst )
	if self.frag:
		s += ", frag %i" % (self.frag)
	if self.tos:
		s += ", dscp %i" % (self.tos >> 2)
	return s, [Ether, Dot3, Dot1Q, MPLS]

IP.mysummary = ip_summary

## Redefine ICMP summary ############################################################################

def icmp_summary(self):
	""" Redefined summary for ICMP header.
	It's same as defined in scapy, but also request to output Dot1Q, MPLS and IP header.
	"""

	s = self.sprintf("ICMP %ICMP.type% %ICMP.code%")
	return s, [Ether, Dot3, Dot1Q, MPLS, IP]

ICMP.mysummary = icmp_summary

## Random MAC address genrator ####################################################################

def random_mac(type='unicast'):
	""" Generate a random MAC address.
	@param type              'unicast'   : force only unicast MAC address.
	                         'multicast' : force only multicast MAC address
	                                       otherwise, accept any type.
	"""
	bytes = [ int(255*random.random()) for r in xrange(6) ]

	if type == 'unicast':
		bytes[0] &= 0xFE
	elif type == 'multicast':
		bytes[0] |= 0x01

	return MacAddress(bytes)

## Extend frame with custom payload based on pattern ##############################################

def add_payload(frame, size, pattern):
	"""
	@param frame             Frame to be extended.
	@param size              Target size of final frame (counting 4 bytes of FCS).
	@param pattern           [optional] Pattern string used to fill frame until size is reached. Default is '\0'.
	                         * 'random' to fill the payload with random bytes.
	@return                  Return extended frame.
	"""
	current_size = len(frame) + 4 #FCS

	if size > current_size:
		if pattern == 'random':
			fill = ''.join([chr(int(random.random()*255)) for byte in xrange(size - current_size)])
		else:
			copies, remain = divmod(size - current_size, len(pattern))
			fill = pattern * copies + pattern[:remain]

		frame = frame / Raw(load = fill)

	return frame

## Utility to create frames using MAC interfaces ##################################################

def l2_frame_from_to(source, destination, vlans = [], seq = 10, size = 64, pattern = '\0', framing = "Ethernet II"):
	""" Create a frame using interfaces MACs.
	@param source            Name of the source interface, or source MAC address.
	                         It can also be:
	                         * 'unicast' to use a random unicast address as source MAC.
	@param destination       Name of the destination interface, or destination MAC address.
	                         It can also be:
	                         * 'broadcast' to use 'FF:FF:FF:FF:FF:FF' as destination MAC.
	                         * 'multicast' to use a random multicast address as destination MAC.
	                         * 'unicast' to use a random unicast address as destination MAC.
	@param vlans             [optional] List of VLAN Tags.
	                         List can be composed by single integer representing VLAN, or tuple (int, int) for VLAN and prio.
	                         Ex: [(100, 3), 20] will add two tags, one with VLAN 100, prio 3 and another with VLAN 20, prio 0.
	@param seq               [optional] Number of sequence
	@param size              [optional] Size of created frame. A padding based on 'pattern' is added to complete
	                         the frame until size is reached (counting 4 bytes of FCS)
	@param pattern           [optional] Pattern string used to fill payload. Default is '\0'.
	                         * 'random' to fill the payload with random bytes.
	@param framing           [optional] Type of frame:
	                         * "Ethernet II" : Ethertype > 1535 and hold information about next layer.
	                         * "802.3" : Ethertype <= 1500 represent payload length. Next header is LLC.
	"""

	if "eth" in destination:
		dst_mac = mac_address(destination)
	elif destination == 'broadcast':
		dst_mac = 'FF:FF:FF:FF:FF:FF'
	elif destination == 'multicast':
		dst_mac = str(random_mac('multicast'))
	elif destination == 'unicast':
		dst_mac = str(random_mac('unicast'))
	else:
		dst_mac = str(destination)

	if "eth" in source:
		src_mac = str(mac_address(source))
	elif source == 'unicast':
		src_mac = str(random_mac('unicast'))
	else:
		src_mac = str(source)

	# When the next layer is Dot1Q, Dot3 will be evaluated as Ether anyway (0x8100 > 1536),
	# To keep consistency between creation and dissection, already use Ether even for 802.3 framing.
	# The difference will be made as Dot1Q will be followed by LLC header.

	if framing == "Ethernet II" or vlans:
		frame = Ether(src = src_mac, dst = dst_mac)
	elif framing == "802.3":
		frame = Dot3(src = src_mac, dst = dst_mac)
	else:
		raise ValueError("Excpected only 'Ethernet II' or '802.3' as framing types.")

	for v in vlans:
		if type(v) == int:
			frame = frame / Dot1Q(vlan = v)
		elif type(v) == tuple:
			frame = frame / Dot1Q(vlan = v[0], prio = v[1])
		else:
			raise TypeError("Expected list with int or tuple for VLANs parameter.")

	if framing == "802.3":
		frame = frame / LLC() / SNAP()

	if seq != None:
		frame = frame / L2T(l2t_seq = seq)

	return add_payload(frame, size, pattern)

## Utility to create IP frames ####################################################################

def l3_frame_from_to(ip_src, ip_dst, if_src, if_dst, vlans = [], dscp = 0, size = 64, pattern = '\0', framing = "Ethernet II", ttl = 64):
	""" Create a frame using interfaces MACs.
	@param ip_src            Source IP address.
	@param ip_dst            Destination IP address.
	@param if_src            Name of the source interface, or source MAC address.
	                         It can also be:
	                         * 'unicast' to use a random unicast address as source MAC.
	@param if_dst            Name of the destination interface, or destination MAC address.
	                         It can also be:
	                         * 'broadcast' to use 'FF:FF:FF:FF:FF:FF' as destination MAC.
	                         * 'multicast' to use a random multicast address as destination MAC.
	                         * 'unicast' to use a random unicast address as destination MAC.
	@param vlans             [optional] List of VLAN Tags.
	                         List can be composed by single integer representing VLAN, or tuple (int, int) for VLAN and prio.
	                         Ex: [(100, 3), 20] will add two tags, one with VLAN 100, prio 3 and another with VLAN 20, prio 0.
	@param dscp              [optional] DSCP value for the frame.
	@param size              [optional] Size of created frame.
	@param pattern           [optional] String used to fill payload. Default is '\0'.
	                         * 'random' to fill the payload with random bytes.
	@param framing           [optional] Type of frame:
	                         * "Ethernet II" : Ethertype > 1535 and hold information about next layer.
	                         * "802.3" : Ethertype <= 1500 represent payload length. Next header is LLC.
	@param ttl               [optional] TTL value for the frame. Default is 64.
	"""

	frame = l2_frame_from_to(if_src, if_dst, vlans = vlans, seq = None, size = 0, framing = framing)

	# The DSCP value of the packet is the 6 most significant bits of the 8 bits
	# of the tos field. Therefore, we must trail with 2 zeros on the lsb side.
	tos_val = dscp << 2

	frame = frame / IP(dst = ip_dst, src = ip_src, tos = tos_val, ttl = ttl)

	return add_payload(frame, size, pattern)

## Utility to create dummy protocols frames #######################################################

pdu_info = {
	'stp'    : { 'mac' : '01:80:c2:00:00:00', 'load' : LLC() / STP() },
	'rstp'   : { 'mac' : '01:80:c2:00:00:00', 'load' : LLC() / STP(version = 2) / Raw('\0') },
	'lldp'   : { 'mac' : '01:80:c2:00:00:0e', 'type' : 0x88cc, 'load' : Raw('\0' * 282) },
	'lacp'   : { 'mac' : '01:80:c2:00:00:02', 'type' : 0x8809, 'load' : Raw('\x01') / Raw('\0' * 109) },
	'marker' : { 'mac' : '01:80:c2:00:00:02', 'type' : 0x8809, 'load' : Raw('\x02') / Raw('\0' * 49) },
	'oam'    : { 'mac' : '01:80:c2:00:00:02', 'type' : 0x8809, 'load' : Raw('\x03') / Raw('\0' * 49) },
	'lbd'    : { 'mac' : '01:80:c2:00:00:02', 'type' : 0x8809, 'load' : Raw('\xFF') / Raw('\0' * 49) },
	'cdp'    : { 'mac' : '01:00:0c:cc:cc:cc', 'load' : LLC() / SNAP(OUI = 0x00000C, code = 0x2000) / Raw('\0' * 370) },
	'pagp'   : { 'mac' : '01:00:0c:cc:cc:cc', 'load' : LLC() / SNAP(OUI = 0x00000C, code = 0x0104) / Raw('\0' * 62) },
	'udld'   : { 'mac' : '01:00:0c:cc:cc:cc', 'load' : LLC() / SNAP(OUI = 0x00000C, code = 0x0111) / Raw('\0' * 60) },
	'vtp'    : { 'mac' : '01:00:0c:cc:cc:cc', 'load' : LLC() / SNAP(OUI = 0x00000C, code = 0x2003) / Raw('\0' * 77) },
	'pvst'   : { 'mac' : '01:00:0c:cc:cc:cd', 'load' : LLC() / SNAP(OUI = 0x00000C, code = 0x010b) / STP() },
	'dtp'    : { 'mac' : '01:00:0c:cc:cc:cd', 'load' : LLC() / SNAP(OUI = 0x00000C, code = 0x2004) / Raw('\0' * 31) },
	'gvrp'   : { 'mac' : '01:80:c2:00:00:21', 'load' : LLC(dsap = 0x42, ssap = 0x42, ctrl = 0x03) / Raw('\x00\x01') / Raw('\0' * 41) },
	'gmrp'   : { 'mac' : '01:80:c2:00:00:20', 'load' : LLC(dsap = 0x42, ssap = 0x42, ctrl = 0x03) / Raw('\x00\x01') / Raw('\0' * 41) },
	'dot1x'  : { 'mac' : '01:80:c2:00:00:03', 'type' : 0x888e, 'load' : Raw('\0' * 64) },
	'eaps'   : { 'mac' : '00:e0:2B:00:00:04', 'load' : LLC() / SNAP(OUI = 0x00E02B, code = 0x00BB) / Raw('\0' * 84) },
	'erps'   : { 'mac' : '01:19:a7:00:00:01', 'type' : 0x8902, 'load' : Raw('\x00\x28') / Raw('\0' * 35) },
}

def protocol_frame(protocol, source='unicast', vlans = []):
	""" Create a frame that has the minimum fields to be recognized as a determined protocol.
	    It's not intended to be a valid PDU, only to be seen as one by the switch filter.
	@param protocol          Protocol name. Valid options are:
	                         * stp, lldp, lacp, marker, oam, lbd, cdp, pagp, udld, vtp, pvst, dtp, gvrp, gmrp, dot1x
	@param source            Name of the source interface, or source MAC address.
	                         * 'unicast' to use a random unicast address as source MAC.
	@param vlans             [optional] List of VLAN Tags.
	                         List can be composed by single integer representing VLAN, or tuple (int, int) for VLAN and prio.
	                         Ex: [(100, 3), 20] will add two tags, one with VLAN 100, prio 3 and another with VLAN 20, prio 0.
	"""
	if protocol not in pdu_info:
		raise Exception("Unknown protocol name {0}".format(protocol))

	info = pdu_info[protocol]

	# Define source MAC address.
	if "eth" in source:
		src_mac = str(mac_address(source))
	elif source == 'unicast':
		src_mac = str(random_mac('unicast'))
	else:
		src_mac = str(source)
	if protocol == 'eaps':
		src_mac = "00:e0:2b:00:00:01"

	if 'type' in info or vlans :
		pdu = Ether(src = src_mac, dst = info['mac'])
		for v in vlans:
			if type(v) == int:
				pdu = pdu / Dot1Q(vlan = v)
			elif type(v) == tuple:
				pdu = pdu / Dot1Q(vlan = v[0], prio = v[1])
			else:
				raise TypeError("Expected list with int or tuple for VLANs parameter.")
		if 'type' in info :
			pdu.lastlayer().type = info['type']
	else:
		pdu = Dot3(src = src_mac, dst = info['mac'])

	pdu = pdu / info['load']

	# Add Padding and return.
	padding = 64 + (4 * len(vlans)) - len(pdu) + 4 #FCS
	if padding > 0 :
		pdu = pdu / Raw('\0' * padding)

	#Process PDU so length field is correctly calculated.
	pdu = Ether(str(pdu))

	return pdu
