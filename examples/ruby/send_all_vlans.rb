###################################################################################################
# This script send packets in all VLANs [1-4094] with all possible priorities [0-7].
###################################################################################################

require 'rubygems'
require 'racket'
require 'l2tester'

# Uncomment to enable debugs.
#L2tester::Logger.config_log_level(L2tester::Logger::L2T_LOG_DEBUG)

if ARGV.size  < 1

  puts <<-EOS
  This script send packets in all VLANs [1-4094] with all possible priorities [0-7].
  Usage: ruby send_all_vlans.rb <iface> [interval]
  Arguments
    iface             : Interface that will output frames. Ex: eth0
    interval          : Interval in ms between each frame. Default: 1 ms.
  EOS

else
  # Get interval if user supplied!
  interval_ms = ARGV.size > 1 ? ARGV[1].to_f : 1.0

  begin
    action_vlan = L2tester::Action.new
    action_vlan.type = L2tester::Action::ACTION_INCREMENT
    action_vlan.mask = 0x0FFF000000000000
    action_vlan.byte = 14
    action_vlan.range_first = 1
    action_vlan.range_last = 4094

    action_prio = L2tester::Action.new
    action_prio.type = L2tester::Action::ACTION_INCREMENT
    action_prio.mask = 0xE000000000000000
    action_prio.byte = 14
    action_prio.range_first = 0
    action_prio.range_last = 7

    action_vlan.chain_action(action_prio, L2tester::Action::ACTION_CHAIN_WHEN_FINISHED)
    packet = Racket::Racket.new
    packet.l2 = Racket::L2::Ethernet.new
    packet.l2.src_mac = "10:00:01:02:03:04"
    packet.l2.dst_mac = 'FF:FF:FF:FF:FF:FF'
    packet.l2.ethertype = 0x8100
    packet.l3 = Racket::L2::VLAN.new("\0"*100)
    packet.l3.priority = 0
    packet.l3.cfi = 0
    packet.l3.id = 0
    packet.l3.type = 0x5010

    sender = L2tester::Sender.new(ARGV[0], packet.pack)
    sender.manual_bandwidth(1, (interval_ms*1000000).to_i);
    sender.set_action(action_vlan)

    started = Time.now
    sender.run(4094*8)
    puts "Time elapsed #{Time.now - started} s"

  rescue Exception => e
    puts e
  end
end