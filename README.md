# L2 Tester

l2tester is a set of tools projected to network traffic tests using the PC interfaces.
Its inner working is made by readings and writings of Linux *raw sockets*. It is completely
agnostic to the contents of packets. So, despite the name, it is possible to send packets
of any format (e.g. IP, TCP, UDP, PDUs). It is possible to send packets with any source or
destination MAC (even if it is not the sending interface MAC) or any IP (no mattering
configured interfaces or routes).

It is implemented in C++ due to performance requirements associated to the sending and
receiving of a large amount of packets. However, to allow easy integration with most of
existing frameworks, all of its API is exported as extensions for languages: **Python**,
**Ruby** and **Lua** (referenced generically as *target language* in this document). It may
also be used in C++ for conceiving small applications aiming manual tests. The wrappers for
target languages are automatically generated through SWIG. The main advantages of this approach
are performance and having access to l2tester in different frameworks through similar API.


## Create your packets

L2 Tester is NOT a tool for creating packets!
Its purpose is to send and receive a bunch of bytes
Use Scapy for generating packets  http://www.secdev.org/projects/scapy/doc/

However, L2 Tester includes some functions to ease generation of commonly used packets (for python):

    l2_frame_from_to(from_ethA, to_ethB, {optionals})
    l3_frame_from_to(from_ip, to_ip, from_ethA, to_ethB, {optionals})
    protocol_frame(protocol, {optionals})

Current protocols are: `stp`, `lldp`, `lacp`, `marker`, `oam`, `lbd`, `cdp`, `pagp`, `udld`,
`vtp`, `pvst`, `dtp`, `gvrp`, `gmrp`, `dot1x`.

Remember: packets with any protocol can be created with Scapy!


## Tests for verifying the content of packets

It is easy to send and check packets for network interfaces. The following example creates 2 broadcast
packets with VLAN IDs 10 and 20, send them from `eth0` and receive them dived at `eth1` and `eth2`.

    frameA = Ether(src='10:00:01:02:03:04', dst='FF:FF:FF:FF:FF:FF') / Dot1Q(vlan=10) / Raw(load=100*'\0')
    frameB = Ether(src='10:00:01:02:03:04', dst='FF:FF:FF:FF:FF:FF') / Dot1Q(vlan=20) / Raw(load=100*'\0')

    send_and_check(
        send_frames = {
            'eth0' : 10 * [frameA] + 13 * [frameB]
        },
        expected_frames = {
            'eth0' : [],
            'eth1' : 10 * [frameA]
            'eth2  : 13 * [frameB]
        }
    )


Other functions: `send_frame`, `send_from_to`


## Bandwidth tests - Sender

The L2Tester may be used to generate a traffic stream.

The following example sets up a stream of 50kbps for `eth0`:

    sender = l2tester.Sender('eth0', packet)
    sender.auto_bandwidth(50000) # 50 Kbps, or
    sender.manual_bandwidth(1, 10000000) # 1 pkt each 10 ms
    sender.start() # Starts assincronously

    # do something

    sender.stop()

Obs.: The max bandwidth capacity depends on the computer.
For old computers it is recommended to send up to 20Mbps of data.


### Actions: INCREMENT, DECREMENT, RANDOMIZE

Optionally, actions can modify a range of bytes of the flow:

    #                                           byte = 14
    #                                           |
    # FF FF FF FF FF FF 10 00 01 02 03 04 81 00 00 00 50 10 00 00 00 00 ...
    #                                           0F FF 00 00 00 00 00 00
    #                                           /------- mask --------/
    action = l2tester.Action()
    action.type = l2tester.Action.ACTION_INCREMENT
    action.mask = 0x0FFF000000000000
    action.byte = 14
    action.range_first = 1
    action.range_last = 4094
    sender.set_action(action)


## Bandwidth tests - Monitor

It is also possible to configure Monitors with filters to get statistics
of an interface:

    monitor = Monitor(["eth3"])
    monitor_stream0 = monitor.new_stream()
    monitor_stream1 = monitor.new_stream({filters e.g.: outer_vlan=7})
    monitor.start()

    # Start sender

    monitor_stream0.check_bandwidth(1000, {options})
    monitor_stream1.check_bandwidth(128, {options})
    graph_points = monitor_stream0.get_bandwidth_readings()



## Programming Languages and Integrations

L2 Tester is written in C++. With Swig, it is also available for:
- Python;
- Ruby;
- Lua.


Current L2 Tester has been tested with kernel version 3.13.0 (Ubuntu 14.04) and inside KVM and Vagrant.

It integrates naturally with Python and Ruby test frameworks.

It is fast! It will not increase the time of your tests beyond the acceptable.


## Sharknado

Sharknado is an experimental GUI for L2 Tester (there are lots of bugs in there!)

## License

L2 tester is distributed under the [MIT license](https://choosealicense.com/licenses/mit/).

However, if you are using the Python wrappers, the combined work is distributed under
[GPLv2+](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html), since it uses Scapy. The
wrapper code is still licensed under MIT license so it can be moved/copied to less restrictive
licenses than GPLv2 if you wish.


## Contributing

+ Fork it
+ Create your feature branch (`git checkout -b my-new-feature`)
+ Commit your changes (`git commit -am 'Add some feature'`)
+ Push to the branch (`git push origin my-new-feature`)
+ Create new Pull Request

We need contribution for:
- Adding unit tests;
- Improving Sharknado.
