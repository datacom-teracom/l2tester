
require 'rubygems'
require 'racket'
require 'l2tester'

# Uncomment to enable debugs.
#L2tester::Logger.config_log_level(L2tester::Logger::L2T_LOG_DEBUG)

if ARGV.size  < 2

  puts <<-EOS
  Usage: ruby traffic_flow.rb <src> <dst> [interval]
  Arguments
    src               : Source ethernet interface. Ex: eth0
    dst               : Destination ethernet interface. Ex: eth1
    interval          : Interval in ms for monitor precision. Default: 10 ms.
  EOS

else

  if_src = ARGV[0]
  if_dst = ARGV[1]

  # Get interval if user supplied!
  interval_ms = ARGV.size > 2 ? ARGV[2].to_i : 10

  begin

    action = L2tester::Action.new
    action.type = L2tester::Action::ACTION_INCREMENT
    action.mask = 0x0FFF000000000000
    action.byte = 14
    action.range_first = 1
    action.range_last = 4094;

    filter = L2tester::EthernetFilter.new
    filter.src_mac = '10:00:01:02:03:04'
    filter.compile()

    packet = Racket::Racket.new
    packet.l2 = Racket::L2::Ethernet.new("\0"*100)
    packet.l2.src_mac = "10:00:01:02:03:04"
    packet.l2.dst_mac = 'FF:FF:FF:FF:FF:FF'
    packet.l2.ethertype = 0x5010

    monitor = L2tester::TrafficFlow_Monitor.new(if_src, if_dst, packet.pack, interval_ms, action, filter)

    puts <<-EOS
===============================================================================
   Timestamp (ms) |       Delta (ms) | Event
-------------------------------------------------------------------------------
EOS

    last_event_ms = 0
    monitor.start()
    while true
      begin
        event = monitor.iterate_event(0, true, 1000)
        if event != nil
          puts " %16d | %16d | %s" % [event.timestamp_ms, event.timestamp_ms - last_event_ms, L2tester::TrafficFlow_Event.type_to_str(event.type)]
          last_event_ms = event.timestamp_ms
          if event.type == L2tester::TrafficFlow_Event::TEST_FINISHED
            break
          end
        end
      rescue SignalException => e
        monitor.stop()
      end
    end
    stats = L2tester::TrafficFlow_Statistics.new
    monitor.get_statistics(stats)

    puts <<-EOS
===============================================================================
  Traffic Interruption
    Total     : #{stats.traffic_interruption_ms} ms
    Intervals : #{stats.traffic_interruption_intervals}
  Loop Detection
    Total     : #{stats.loop_detected_ms} ms
    Intervals : #{stats.loop_detected_intervals}
  Packets
    Sent      : #{stats.sent_packets}
    Received  : #{stats.received_packets}
    Dropped   : #{stats.dropped_packets}
  #{stats.error_detected ? "** MONITOR ABORTED **" : "" }
===============================================================================
EOS

  rescue Exception => e
    puts e
  end
end