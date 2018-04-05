###################################################################################################
# This script demonstrate the use of the SendAndCheck feature.
# From source interface, 2 tagged and 2 untagged packets are sent.
# In destination, we expect 1 tagged and 3 untagged. If interfaces are direct connect,
# we will see:
# - 3 received packets: 1 tagged and 2 untagged
# - 1 missed packet: 1 untagged
# - 1 unexpected packet: 1 tagged
###################################################################################################

require 'rubygems'
require 'racket'
require 'l2tester'

#
# Print to stdout the received frame mapping.
#
# @param mapping [Hash]   Hash mapping interfaces to frame list.
#
def print_frame_mapping(mapping)

  if mapping.size > 0

    mapping.each do | iface, frame_list |
      puts "  * #{iface}:"
      frame_list.each do |frame|
        puts "    - " + Racket::L2::Ethernet.new(frame).pretty()
      end
    end

  else
    puts "  * None"
  end

end

if ARGV.size  < 1

  puts <<-EOS
  Usage: ruby send_and_check.rb <src> <dst>
  Arguments
    src               : Source ethernet interface. Ex eth0
    dst               : Destination ethernet interface. Ex eth1
  EOS

else

  untag = Racket::Racket.new
  untag.l2 = Racket::L2::Ethernet.new("\0"*100)
  untag.l2.src_mac = "10:00:01:02:03:04"
  untag.l2.dst_mac = 'FF:FF:FF:FF:FF:FF'
  untag.l2.ethertype = 0x5010

  tag100 = Racket::Racket.new
  tag100.l2 = Racket::L2::Ethernet.new
  tag100.l2.src_mac = "10:00:01:02:03:04"
  tag100.l2.dst_mac = 'FF:FF:FF:FF:FF:FF'
  tag100.l2.ethertype = 0x8100
  tag100.l3 = Racket::L2::VLAN.new("\0"*100)
  tag100.l3.priority = 0
  tag100.l3.cfi = 0
  tag100.l3.id = 0
  tag100.l3.type = 0x5010

  if_src = ARGV[0]
  if_dst = ARGV[1]

  filter = L2tester::EthernetFilter.new
  filter.src_mac = '10:00:01:02:03:04'
  filter.compile()

  send_frames = {
    if_src => [ untag.pack, tag100.pack ] * 2,
  }

  expected_frames = {
    if_src => [],
    if_dst => [ tag100.pack ] + [ untag.pack ] * 3,
  }

  send_and_check = L2tester::SendAndCheck.new(send_frames, expected_frames, 1000, filter)
  send_and_check.run()

  puts "\nReceived frames:"
  print_frame_mapping(send_and_check.get_received_frames())

  puts "\nMissed frames:"
  print_frame_mapping(send_and_check.get_missed_frames())

  puts "\nUnexpected frames:"
  print_frame_mapping(send_and_check.get_unexpected_frames())

end
