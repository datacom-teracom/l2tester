###################################################################################################
# Example of Sniffer extension in target language.
# Currently not working as SWIG Director for Ruby should encapsulate call in another thread:
# http://sourceforge.net/p/swig/bugs/1344/
###################################################################################################

require 'rubygems'
require 'racket'
require 'l2tester'

#
# Extend L2T::Sniffer to perform actions in Ruby for each captured packet.
#
class RubySniffer < L2tester::Sniffer

  #
  # Initialize base class.
  #
  def initialize(timeout)
    super(timeout)
  end

  #
  # Reimplement C++ virtual method. Called for each received packet that matches any filter.
  #
  # @param iface   [Fixnum] Interface index that received the packet.
  # @param filter  [Fixnum] Filter index that matched the packet.
  # @param packet  [String] Packet in raw string format.
  #
  def received_packet(iface, filter, packet)
    puts "Received Frame"
    f = Racket::Racket.new # Exception is raised :(
    true
  end
end

if ARGV.size < 2

  puts <<-EOS
  Usage: python sniffer.fb <src> <dst>
  Arguments
    src               : Source ethernet interface. Ex eth0
    dst               : Destination ethernet interface. Ex eth1
  EOS

else

  if_src = ARGV[0]
  if_dst = ARGV[1]

  # Change logging LEVEL for l2tester module
  L2tester::Logger.config_log_level(L2tester::Logger::L2T_LOG_DEBUG)

  # Create Sniffer using passed interface.
  recv = RubySniffer.new(1000)
  recv.add_interfaces([if_dst])
  recv.add_filter()

  # Start sniffer
  recv.start()

  # Create new TxStream
  frame0 = Racket::Racket.new
  frame0.l2 = Racket::L2::Ethernet.new
  frame0.l2.src_mac = "10:00:01:02:03:04"
  frame0.l2.dst_mac = 'FF:FF:FF:FF:FF:FF'
  frame0.l2.ethertype = 0x8100
  frame0.l3 = Racket::L2::VLAN.new("\0"*78)
  frame0.l3.priority = 0
  frame0.l3.cfi = 0
  frame0.l3.id = 10
  frame0.l3.type = 0x5010

  tx0 = L2tester::Sender.new(if_src, frame0.pack)
  tx0.auto_bandwidth(500)
  tx0.start()

  sleep(4.0)

  recv.stop()
  tx0.stop()

end
