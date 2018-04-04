###################################################################################################
# L2T::Bandwidth example:
#   This script is intended to be used as an example of how to use l2tester Bandwidth functionality.
#   We configure 2 TxStreams, using different VLANs and 2 Streams filtering by VLANs.
#   For the first part, we progressively increase the bandwidth of the first TxStream.
#   Test Stream deletion and recreation and for the second part, progressively decrease the
#   bandwidth of the first TxStream.
###################################################################################################

require 'rubygems'
require 'racket'
require 'l2tester'

if ARGV.size  < 2
  puts <<-EOS
   Usage: ruby bandwidth.rb <src> <dst>
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
  recv = L2tester::Bandwidth_Monitor.new([if_dst])

  # Create Streams
  f0 = L2tester::EthernetFilter.new()
  f0.outer_vlan = 10
  f0.dst_mac = "FF:FF:FF:FF:FF:FF"
  f0.compile()
  rx0 = recv.new_stream(f0)

  f1 = L2tester::EthernetFilter.new()
  f1.outer_vlan = 20
  f1.compile()
  rx1 = recv.new_stream(f1)

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
  band = 500000;
  tx0.auto_bandwidth(band)
  tx0.start()

  # Another TxStream
  frame1 = Racket::Racket.new
  frame1.l2 = Racket::L2::Ethernet.new
  frame1.l2.src_mac = "10:00:01:02:03:05"
  frame1.l2.dst_mac = 'FF:FF:FF:FF:FF:FF'
  frame1.l2.ethertype = 0x8100
  frame1.l3 = Racket::L2::VLAN.new("\0"*78)
  frame1.l3.priority = 0
  frame1.l3.cfi = 0
  frame1.l3.id = 20
  frame1.l3.type = 0x5010

  tx1 = L2tester::Sender.new(if_src, frame1.pack)
  tx1.auto_bandwidth(3000000)
  tx1.start()

  puts "First round."

  # Iterate over results
  0.upto(10) do |i|
    [ rx0, rx1 ].each do |stream|
      # The default behavior of 'iterate_reading' is to way until next one is available.
      # No waiting is needed.
      m = stream.iterate_reading()
      puts " [#{m.timestamp_ms}] #{m.bits_per_sec} bps / #{m.packets_per_sec} pps"
    end
    # TxStream 0 grows periodically:
    band = band * 1.2
    # Show that we can change bandwidth in runtime!
    tx0.auto_bandwidth(band.to_i)
  end
  # Remove Stream during sniffing
  recv.delete_stream(rx0)
  puts "Deleted Stream 0."

  0.upto(5) do |i|
    m = rx1.iterate_reading()
    puts " [#{m.timestamp_ms}] #{m.bits_per_sec} bps / #{m.packets_per_sec} pps"
  end
  # Recreate Stream while sniffing!
  rx0 = recv.new_stream(f0)
  puts "Recreated Stream 0."

  0.upto(10) do |i|
    [ rx0, rx1 ].each do |stream|
      m = stream.iterate_reading()
      puts " [#{m.timestamp_ms}] #{m.bits_per_sec} bps / #{m.packets_per_sec} pps"
    end
  end

  recv.stop()
  tx0.stop()
  tx1.stop()

  puts "Second round."

  recv.start()
  tx0.start()
  tx1.start()

  # Iterate over results
  0.upto(10) do |i|
    [ rx0, rx1 ].each do |stream|
      m = stream.iterate_reading()
      puts " [#{m.timestamp_ms}] #{m.bits_per_sec} bps / #{m.packets_per_sec} pps"
    end
    # TxStream 0 shrink periodically:
    band = band * 0.8
    tx0.auto_bandwidth(band.to_i)
  end

  recv.stop()
  tx0.stop()
  tx1.stop()
end