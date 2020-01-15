import logging

from . import l2tester

logger = logging.getLogger("Bandwidth")

# If logger name Bandwidth has no handlers, add simple one:
if not logger.handlers:
	logger.setLevel(logging.INFO)
	logger.addHandler(logging.StreamHandler())

## Bandwidth RX ####################################################################################

class Stream():
	""" Wrapper around l2tester.Stream
	    Provide current bandwidth check.
	"""

	def __init__(self, instance, name):
		""" Initialize this Stream.
		@param instance      Reference to l2tester Stream.
		@param name          Name for this Stream. Used for log purpose only.
		"""
		self.instance = instance
		self.name = name

	def get_bandwidth_readings(self):
		""" Return list with bandwidth measurements, requires a stopped Stream.
		"""
		if not self.instance:
			logger.error("Can't check bandwidth on deleted Stream.")
			raise AssertionError("Can't check bandwidth on deleted Stream.")
		raw_measures = []
		reading = self.instance.iterate_reading(1);

		while reading:
			raw_measures.append(reading)
			reading = self.instance.iterate_reading(0, False);

		return map(lambda r : r.bits_per_sec / 1000.0, raw_measures)

	def check_bandwidth(self, target_bandwidth, num_readings = 3, tolerance = 0.05, num_ignored_readings = 0):
		""" Check if current bandwidth is as expected.
		@param target_bandwidth       Desired bandwidth in Kbps to check against.
		@param num_readings           Number of measures used to calculate current bandwidth.
		@param tolerance              Tolerance in percentage.
		@param num_ignored_readings   Cuts num_ignored_readings samples from the highest and lowest ends
		                              of the readings. If num_ignored_readings > 0, then the function
		                              will calculate the "modified mean" from the samples for comparison
		                              with target bandwidth. Example:
		                              if num_readings = 5 and num_ignored_readings = 1 and previous
		                              samples was 3, 1, 3, 3 and 5, then samples 1 and 5 will be
		                              ignored.
		"""
		if not self.instance:
			logger.error("Can't check bandwidth on deleted Stream.")
			raise AssertionError("Can't check bandwidth on deleted Stream.")
			return

		measures = [ self.instance.iterate_reading(-1).bits_per_sec / 1000.0 ]
		for i in range(num_readings - 1):
			measures.append(self.instance.iterate_reading().bits_per_sec / 1000.0)

		if (num_ignored_readings is not 0) and ((num_ignored_readings * 2) < num_readings):
			measures.sort()
			measures = measures[num_ignored_readings:-num_ignored_readings]

		current_bandwidth = 0.0;
		for measure in measures:
			current_bandwidth += measure

		current_bandwidth = current_bandwidth / len(measures)

		if (current_bandwidth >= (1.0 - tolerance) * target_bandwidth
				and current_bandwidth <= (1.0 + tolerance) * target_bandwidth ):
			logger.info("%s Measured %.1f Kbps as expected.", self.name, current_bandwidth)
		else:
			logger.error("%s Expected %.1f Kbps but measured %.1f Kbps.", self.name, float(target_bandwidth), current_bandwidth)
			raise AssertionError("{0} Expected {1:.1f} Kbps but measured {2:.1f} Kbps.".format(self.name, float(target_bandwidth), current_bandwidth))

		return current_bandwidth

class Monitor(l2tester.Bandwidth_Monitor):
	""" Define a Bandwidth Monitor based on l2tester.
	"""

	def __init__(self, interfaces, measure_interval=0.5):
		""" Create a new Monitor for bandwidth measurement.
		@param interfaces        List of interfaces to monitor.
		@param measure_interval  Interval in seconds between each measure.
		"""
		l2tester.Bandwidth_Monitor.__init__(self, interfaces, int(measure_interval*1000))

	def new_stream(self, dst_mac=None, src_mac=None, outer_tpid=None, outer_vlan=None, outer_prio=None, inner_tpid=None, inner_vlan=None, inner_prio=None, generic_filter=None):
		""" Create a new Stream associated with this Monitor.
		@param dst_mac       Filter by Destination MAC.
		@param src_mac       Filter by Source MAC.
		@outer_tpid          Filter by Outer TPID or Ethertype for untagged frames.
		@outer_vlan          Filter by Outer Vlan (Service VLAN)
		@outer_prio          Filter by Outer 802.1p priority
		@inner_tpid          Filter by Inner TPID or Ethertype for tagged frames.
		@inner_vlan          Filter by Inner Vlan (Costumer VLAN)
		@inner_prio          Filter by Outer 802.1p priority
		@generic_filter      Generic user-defined filtered frames
		"""

		filter_desc = []
		name = "[Global]"

		if generic_filter is None:
			filter = l2tester.EthernetFilter()

			if dst_mac != None:
				filter.dst_mac = dst_mac
				filter_desc.append("dstMac " + dst_mac)
			if src_mac != None:
				filter.src_mac = src_mac
				filter_desc.append("srcMac " + src_mac)
			if outer_tpid != None:
				filter.outer_tpid = outer_tpid
				filter_desc.append("oTpid " + str(outer_tpid))
			if outer_vlan != None:
				filter.outer_vlan = outer_vlan
				filter_desc.append("oVlan " + str(outer_vlan))
			if outer_prio != None:
				filter.outer_prio = outer_prio
				filter_desc.append("oPrio " + str(outer_prio))
			if inner_tpid != None:
				filter.inner_tpid = inner_tpid
				filter_desc.append("iTpid " + str(inner_tpid))
			if inner_vlan != None:
				filter.inner_vlan = inner_vlan
				filter_desc.append("iVlan " + str(inner_vlan))
			if inner_prio != None:
				filter.inner_prio = inner_prio
				filter_desc.append("iPrio " + str(inner_prio))

			filter.compile()
		else:
			filter = generic_filter
			filter_desc.append("User-Defined")

		if filter_desc:
			name = "[" + ", ".join(filter_desc) + "]"

		return Stream(l2tester.Bandwidth_Monitor.new_stream(self, filter), name)

	def delete_stream(self, stream):
		""" Delete a Stream and remove it from monitored streams.
		"""
		l2tester.Bandwidth_Monitor.delete_stream(self, stream.instance)
		stream.instance = None


## Bandwidth TX ####################################################################################

class Sender(l2tester.Sender):
	""" Define a Bandwidth output stream based on l2tester.
	"""

	def __init__(self, interface, packet):
		""" Create a new Sender. Nothing is sent until bandwidth is configured and start is called.
		@interface           Name of interface to output bandwidth.
		@packet              Scapy packet to be sent (or simple string as packet data).
		"""
		self.iface_name = interface
		self.packet = packet
		l2tester.Sender.__init__(self, interface, str(packet))

	def auto_bandwidth(self, bandwidth):
		""" Configure target bandwidth.
		@param bandwidth     Target bandwidth in Kbps.
		"""
		l2tester.Sender.auto_bandwidth(self, int(bandwidth*1000))

	def manual_bandwidth(self, frames, interval):
		""" Configure target bandwidth.
		@param frames   Number of frames sent per interval.
		@param interval Interval in seconds between each burst.
		"""
		l2tester.Sender.manual_bandwidth(self, frames, int(interval)*1000000000)

	def start(self):
		""" Start sending bandwidth.
		"""
		logger.info("Sending %d Kbps from %s interface.", self.get_bandwidth()/1000, self.iface_name)

		if hasattr(self.packet, 'summary'):
			logger.info(" * Data: %s (%d bytes)", self.packet.summary(), len(self.packet))
			logger.info("{}".format(self.packet.display()))

		l2tester.Sender.start(self)
