
try:
    from pyroute2 import IPRoute
except:
    raise Exception("""
l2tester.interface depends on the following module:
 * pyroute2 : available at https://pypi.python.org/pypi/pyroute2

Download .tar.gz, extract it, enter folder and run 'sudo python setup.py install' to install this module.
""")

import socket
import struct
import fcntl
import ctypes
import os
import re
import logging

from select import select

# From <linux/if_ether.h>
ETH_P_ALL = 0x0003

# From <linux/socket.h>
SOL_PACKET = 263

# From <linux/if_packet.h>
PACKET_MR_PROMISC = 1
PACKET_ADD_MEMBERSHIP = 0x0001
PACKET_DROP_MEMBERSHIP = 0x0002

## Ethtool ########################################################################################

# From <linux/ethtool.h>
ETHTOOL_GSET = 0x00000001
ETHTOOL_SSET = 0x00000002

# From <linux/sockios.h>
SIOCETHTOOL = 0x8946


class Ethtool():
    """ Implement ethtool functionality by ioctl with struct ethtool_cmd from <linux/ethtool.h>
    struct ethtool_cmd {
        u32 cmd;
        u32 supported; /* Features this interface supports */
        u32 advertising; /* Features this interface advertises */
        u16 speed; /* The forced speed, 10Mb, 100Mb, gigabit */
        u8 duplex; /* Duplex, half or full */
        u8 port; /* Which connector port */
        u8 phy_address;
        u8 transceiver; /* Which transceiver to use */
        u8 autoneg; /* Enable or disable autonegotiation */
        u32 maxtxpkt; /* Tx pkts before generating tx int */
        u32 maxrxpkt; /* Rx pkts before generating rx int */
        u32 reserved[4];
    };
    """

    st_format = "IIIHBBBBBII16x"

    def __init__(self, if_name):
        """ Initialize ethtool.
        @param if_name       Name of interface.
        """
        self.data = ctypes.create_string_buffer(44)  # sizeof(struct ethtool_cmd)
        self.__unpack()
        self.ifreq_input = struct.pack('16sI12x', if_name, ctypes.addressof(self.data))
        self.sockfd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)

    def get(self):
        """ Request ethtool information using ioctl. Update object parameters.
        """
        self.cmd = ETHTOOL_GSET
        self.__pack()
        fcntl.ioctl(self.sockfd, SIOCETHTOOL, self.ifreq_input)
        self.__unpack()

    def set(self):
        """ Configure ethtool information using ioctl.
        Must be preceded by a 'get' if not all fields are changed.
        """
        self.cmd = ETHTOOL_SSET
        self.__pack()
        fcntl.ioctl(self.sockfd, SIOCETHTOOL, self.ifreq_input)

    def __unpack(self):
        """ [private] Extract fields from buffer.
        """
        unpacked = struct.unpack(self.st_format, self.data[:])
        self.cmd = unpacked[0]
        self.supported = unpacked[1]
        self.advertising = unpacked[2]
        self.speed = unpacked[3]
        self.duplex = unpacked[4]
        self.port = unpacked[5]
        self.phy_address = unpacked[6]
        self.transceiver = unpacked[7]
        self.autoneg = unpacked[8]
        self.maxtxpkt = unpacked[9]
        self.maxrxpkt = unpacked[10]

    def __pack(self):
        """ Updated buffer with current fields.
        """
        packed = struct.pack(self.st_format,
                             self.cmd,
                             self.supported,
                             self.advertising,
                             self.speed,
                             self.duplex,
                             self.port,
                             self.phy_address,
                             self.transceiver,
                             self.autoneg,
                             self.maxtxpkt,
                             self.maxrxpkt)
        for i in xrange(44):
            self.data[i] = packed[i]

## Interface ######################################################################################


class Interface():
    """ Define ethernet interface using low level RAW sockets.
    NOTE: To create RAW sockets, you must be superuser or have 'cap_net_raw' capabilities.
          You can set the capabilities to python using:
          $ sudo setcap cap_mac_admin,cap_net_raw,cap_net_admin=eip /usr/bin/python2.6
    """

    netlink = IPRoute()

    def __init__(self, name, eth_type=ETH_P_ALL):
        """ Initialize interface. Open socket and set interface in promiscuous mode.
        @param name          Name of the interface. Ex: 'eth0'
        @param eth_type      Ethernet protocols read by this interface. Default: ALL PROTOCOLS.
        """
        self.logger = logging.getLogger("PC eth")
        self.eth_type = eth_type
        self.name = name
        self.added_ips = []
        self.is_vlan = False

        # If the interface is not part of IPDB, it can be a VLAN
        if not self.netlink.link_lookup(ifname=self.name):
            vlan_match = re.match(
                "^(?P<base_interface>eth\d+)\.(?P<vlan_id>[1-9]\d{1,3})$", self.name)
            if vlan_match is None:
                raise Exception("Invalid interface name " + self.name)
            base = vlan_match.group('base_interface')
            vid = int(vlan_match.group('vlan_id'))

            base_idx = self.netlink.link_lookup(ifname=base)
            if not base_idx:
                raise Exception("Invalid base interface name " + self.name)

            try:
                request = {
                        'index': 0,
                        'ipaddr': [],
                        'link': base_idx[0],
                        'flags': 0,
                        'ifname': self.name,
                        'ports': [],
                        'IFLA_LINKINFO': {
                                'attrs': [
                                        ['IFLA_INFO_DATA', {
                                                'attrs': [['IFLA_VLAN_ID', vid]]
                                        }],
                                        ['IFLA_INFO_KIND', 'vlan']
                                ]
                        }
                }
                # Send request to create new interface with VLAN
                self.netlink.link('add', **request)
                self.is_vlan = True

            except:
                self.logger.critical("Couldn't create interface %s", self.name)
                raise

        # Get Interface Index, set to UP, get MTU and MAC Address
        self.if_index = self.netlink.link_lookup(ifname=self.name)[0]
        self.netlink.link('set', index=self.if_index, state='up')
        info = dict(self.netlink.get_links(self.if_index)[0]['attrs'])
        self.mac_address = info['IFLA_ADDRESS'].upper()
        self.mtu = info['IFLA_MTU']

        # Create socket to receive/send frames:
        self.sockfd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(self.eth_type))
        self.sockfd.bind((self.name, self.eth_type))

        # Enable promiscuous mode:
        self.set_promiscuous(True)

        # By default, start using auto-negotiation
        self.using_forced_speed_duplex = False

    def __del__(self):
        """ Destructor. Disable promiscuous mode on interface.
        """

        # Clean added IP addresses.
        for ip in self.added_ips:
            self.__set_ip_address(ip[0], ip[1], 'delete')

        # Remove VLAN if it was created.
        if self.is_vlan:
            self.netlink.link('delete', index=self.if_index)

        # Disable promiscuous mode:
        self.set_promiscuous(False)

        # Leave interface with auto-negotiation enabled:
        if self.using_forced_speed_duplex:
            self.enable_auto_negotiation()

    def recv(self):
        """ Receive a packet. If it's an outgoing packet ignore it.
        """
        packet, address = self.sockfd.recvfrom(self.mtu)
        return packet if address[2] != socket.PACKET_OUTGOING else None

    def send(self, packet):
        """ Send a packet through this interface.
        """
        self.sockfd.sendto(str(packet), 0, (self.name, self.eth_type))

    def flush(self):
        """ Remove all packets from read buffer.
        """
        self.sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 0)
        while True:
            r, w, e = select([self.sockfd.fileno()], [], [], 0)
            if r:
                os.read(self.sockfd.fileno(), self.mtu)
            else:
                break
        self.sockfd.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)

    def set_promiscuous(self, enable):
        """ Enable/Disable promiscuous mode on interface.
        @param enable        True to enable, False to disable.
        """
        cmd = PACKET_ADD_MEMBERSHIP if enable else PACKET_DROP_MEMBERSHIP
        mreq = struct.pack('IHH8s', self.if_index, PACKET_MR_PROMISC, 0, bytes())
        self.sockfd.setsockopt(SOL_PACKET, cmd, mreq)

    def add_ip_address(self, ip_address):
        """ Adds an IP address/network mask (the default prefix is 24)
        @param ip_address    The IP address followed optionally by mask size. Ex: 192.168.0.24/24
        """
        self.__set_ip_address(ip_address, socket.AF_INET, 'add')
        self.added_ips.append((ip_address, socket.AF_INET))

    def del_ip_address(self, ip_address):
        """ Deletes an IP address/network mask (the default prefix is 24)
        @param ip_address    The IP address followed optionally by mask size. Ex: 192.168.0.24/24
        """
        self.__set_ip_address(ip_address, socket.AF_INET, 'delete')
        self.added_ips.remove((ip_address, socket.AF_INET))

    def add_ipv6_address(self, ipv6_address):
        """ Adds an IPv6 address/network mask (the default prefix is 24)
        @param ip_address    The IPv6 address followed optionally by mask size. Ex: 56::1/24
        """
        self.__set_ip_address(ipv6_address, socket.AF_INET6, 'add')
        self.added_ips.append((ipv6_address, socket.AF_INET6))

    def del_ipv6_address(self, ipv6_address):
        """ Deletes an IPv6 address/network mask (the default prefix is 24)
        @param ip_address    The IPv6 address followed optionally by mask size. Ex: 56::1/24
        """
        self.__set_ip_address(ipv6_address, socket.AF_INET6, 'delete')
        self.added_ips.remove((ipv6_address, socket.AF_INET6))

    def enable_auto_negotiation(self):
        """ Enable auto-negotiation for Ethernet link.
        """
        ethtool = Ethtool(self.name)
        ethtool.get()
        ethtool.advertising = ethtool.supported
        ethtool.autoneg = 1
        ethtool.set()

        self.using_forced_speed_duplex = False
        self.logger.info("[%s] Enabled Auto-negotiation.", self.name)

    def force_speed_duplex(self, speed, duplex):
        """ Configure interface speed/duplex disabling auto-negotiation.
        @param speed         Set forced speed. Values: 10, 100, 1000, 2500, 10000.
        @param duplex        Set forced duplex.
        """

        if not speed in [10, 100, 1000, 2500, 10000]:
            raise ValueError("Speed can only be: 10, 100, 1000, 2500 or 10000 Mbps.")

        ethtool = Ethtool(self.name)
        ethtool.get()
        ethtool.speed = speed
        ethtool.duplex = 1 if duplex else 0
        ethtool.autoneg = 0
        ethtool.set()

        self.using_forced_speed_duplex = True
        self.logger.info("[%s] Configured forced speed: %d Mbps / %s duplex",
                         self.name, speed, "full" if duplex else "half")

    def has_ip_address(self, ip_address):
        """ Returns True if the address is already configured in the interface, and False otherwise
        @param ip_address The IP address to be checked
        """
        return (self.__check_ip_address(ip_address, socket.AF_INET)
                or self.__check_ip_address(ip_address, socket.AF_INET6))

    def set_mtu(self, mtu):
        """ Configure interface MTU.
        @param mtu           New value for MTU.
        """
        self.netlink.link('set', index=self.if_index, mtu=mtu)

    def set_mac_address(self, mac_address):
        """ Configure a new MAC address at this interface
        @param mac_address The MAC address to be set
        """
        self.netlink.link('set', index=self.if_index, address=mac_address)
        self.mac_address = mac_address

    def __check_ip_address(self, ip_address, ip_family):
        """ Returns True if the address is already configured in the interface, and False otherwise
        @param ip_address The IP address to be checked
        @param ip_family socket.AF_INET if ip_address is an IPv4 address; socket.AF_INET6 otherwise
        """
        address_types = ['IFA_ADDRESS', 'IFA_LOCAL',
                         'IFA_BROADCAST', 'IFA_ANYCAST', 'IFA_MULTICAST']
        for interface in self.netlink.get_addr(family=ip_family):
            if interface['index'] != self.if_index:
                continue
            for address in interface['attrs']:
                if address[0] in address_types and address[1] == ip_address:
                    return True
        return False

    def __set_ip_address(self, ip_address, ip_family, action):
        """ Adds or deletes an IP address/network mask (optional)
        @param ip_address    The IP address followed optionally by mask size. Ex: 192.168.0.24/24; 56::1/24
        @param ip_family     socket.AF_INET to IPv4 addresses; socket.AF_INET6 to IPv6 addresses
        @param action        'add' or 'del', to add or delete an IP address, respectively
        """

        ip_and_mask = ip_address.split('/')
        ip_version = 4 if ip_family == socket.AF_INET else 6
        network_mask = 24 if len(ip_and_mask) < 2 else int(ip_and_mask[1])
        exists = self.__check_ip_address(ip_and_mask[0], ip_family)

        if (action == 'add' and exists) or (action == 'delete' and not exists):
            self.logger.info('No need to %s the IP%d address %s/%d from/to %s because it already %sexists',
                             action, ip_version, ip_and_mask[0], network_mask, self.name, '' if exists else 'does not ')
            return

        self.logger.info("%s IPv%d address %s/%d in %s", action, ip_version,
                         ip_and_mask[0], network_mask, self.name)
        self.netlink.addr(action, self.if_index,
                          address=ip_and_mask[0], mask=network_mask, family=ip_family)


## Access PC interfaces ############################################################################

interface_instances = {}


def get_interface(if_name):
    """ Get interface reference. It's used to avoid multiple sockets for the same interface.
    """
    if not if_name in interface_instances:
        interface_instances[if_name] = Interface(if_name)
    return interface_instances[if_name]


def mac_address(if_name):
    """ Shortcut to get_interface(if_name).mac_address.
    """
    return get_interface(if_name).mac_address


def delete_interfaces():
    """ Delete all created interfaces.
    """
    for if_name in interface_instances.keys():
        del interface_instances[if_name]
