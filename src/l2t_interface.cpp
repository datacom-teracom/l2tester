/*************************************************************************************************/
/**
 * \file
 * \brief Define classes used as interfaces in L2 tester.
 */
/*************************************************************************************************/

#include <cstdlib>
#include <cstring>
#include <cstdio>

extern "C" {
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <net/if.h>           // For IFNAMSIZ
#include <linux/if_packet.h>  // For struct sockaddr_ll
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
}

#include "l2t_interface.h"
#include "l2t_logger.h"

/*************************************************************************************************/

namespace L2T {

/**************************************************************************************************
 ** L2T::Ethernet **
 **************************************************************************************************/

Interface::Interface(const std::string &_ifname, unsigned short _ether_type) throw(L2T::Exception)
    : sockfd(-1), name(_ifname)
{
    L2T_INFO << "Creating new Ethernet " << _ifname << ".";

    int flags;
    struct ifreq iface_req;
    struct packet_mreq pkt_mreq;

    /* Create socket */
    if ((this->sockfd = ::socket(PF_PACKET, SOCK_RAW, htons(_ether_type))) < 0) {
        throw Exception(L2T_ERROR_SOCKET, "Couldn't open socket.");
    }

    L2T_DEBUG << " - Got sockfd " << this->sockfd << ".";

    /* Configure this socket! */
    try {
        /* Copy interface name to requisition */
        ::memset(&iface_req, 0, sizeof(struct ifreq));
        ::snprintf(iface_req.ifr_name, sizeof(iface_req.ifr_name), "%s", this->name.c_str());

        /* Get FD flags */
        getFdFlags(flags);

        /* Configure as Non Blocking */
        flags |= O_NONBLOCK | O_NDELAY;

        /* Set FD flags */
        setFdFlags(flags);

        /* Get interface index */
        getInterfaceIndex(iface_req);
        this->index = iface_req.ifr_ifindex;

        /* Set interface TX queue length */
        iface_req.ifr_qlen = 3000;
        setInterfaceTxQueueLength(iface_req);

        /* Set socket promisc */
        ::memset(&pkt_mreq, 0, sizeof(struct packet_mreq));
        pkt_mreq.mr_ifindex = this->index;
        pkt_mreq.mr_type = PACKET_MR_PROMISC;

        /* Set socket options */
        setSocketOptions(pkt_mreq);

        /* Configure buffers */
        int value = 500000; /* Empirical large enough value for buffers size. */
        setBufferSize(value);

        /* Prepare sockaddr_ll */
        struct sockaddr_ll address;
        ::memset(&address, 0, sizeof(struct sockaddr_ll));
        address.sll_family = AF_PACKET;
        address.sll_protocol = htons(_ether_type);
        address.sll_ifindex = this->index;
        address.sll_halen = ETH_ALEN;

        /* Bind socket to interface */
        bindInterfaceSocket(address);

        /* Get interface flags */
        getInterfaceFlags(iface_req);

        /* Configure interface as promiscuous */
        iface_req.ifr_flags |= IFF_PROMISC;

        /* Set interface flags */
        setInterfaceFlags(iface_req);

        FD_ZERO(&this->readset);
        FD_SET(this->sockfd, &this->readset);

        /* If something went wrong, close socket and propagate error. */
    }
    catch (Exception &e) {
        ::close(this->sockfd);
        throw;
    }
}

/*************************************************************************************************/

Interface::~Interface()
{
    L2T_DEBUG << "Deleting Ethernet " << this->name << ".";

    struct ifreq iface_req;

    /* Copy interface name to requisition */
    ::memset(&iface_req, 0, sizeof(struct ifreq));
    ::snprintf(iface_req.ifr_name, sizeof(iface_req.ifr_name), "%s", this->name.c_str());

    /* Configure interface as non promiscuous.
     * In case of error, there's nothing we can do. */
    if (::ioctl(this->sockfd, SIOCGIFFLAGS, &iface_req) == 0) {
        iface_req.ifr_flags &= ~IFF_PROMISC;
        ::ioctl(this->sockfd, SIOCSIFFLAGS, &iface_req);
    }

    close(this->sockfd);
}

/*************************************************************************************************/

void Interface::send(void *_packet, size_t _size) throw(L2T::Exception)
{
    if (_size < ETH_ZLEN) {
        throw Exception(L2T_ERROR_INVALID_CONFIG, "Couldn't send packet: too small.");
    }
    if (::send(this->sockfd, _packet, _size, 0) < 0) {
        L2T_ERROR << "Failed send with error " << Errno(errno);
        throw Exception(L2T_ERROR_SOCKET, "Couldn't send packet.");
    }
}

/*************************************************************************************************/

int Interface::receive(void *_packet, size_t _size, int _timeout) throw(L2T::Exception)
{
    int packet_size = 0;
    struct timeval tv;
    if (_timeout > 0) {
        tv.tv_sec = _timeout / 1000;
        tv.tv_usec = (_timeout % 1000) * 1000;
    }

    int sel = ::select(FD_SETSIZE, &this->readset, NULL, NULL, _timeout > 0 ? &tv : NULL);

    if (sel == -1) { /* Error in select function */

        /* The fd_set were left in undefined state. Readjusts it! */
        FD_ZERO(&this->readset);
        FD_SET(this->sockfd, &this->readset);
        L2T_ERROR << "Failed select with error " << Errno(errno);
        throw Exception(L2T_ERROR_GENERIC, "Select returned with error.");

    } else if (sel == 0) { /* select timedout */

        /* Reset bit for next call! */
        FD_SET(this->sockfd, &this->readset);
        throw Exception(L2T_ERROR_TIMEOUT, "Timeout receiving packet.");

    } else if (sel) {

        if (FD_ISSET(this->sockfd, &this->readset)) { /* Packet to receive in interface */
            packet_size = ::recvfrom(this->sockfd, _packet, _size, 0, NULL, 0);
            if (packet_size < 0) {
                L2T_ERROR << "Failed recvfrom with error " << Errno(errno);
                throw Exception(L2T_ERROR_SOCKET, "Couldn't recvfrom socket.");
            }
        } else {
            throw Exception(L2T_ERROR_SOCKET, "Select returned, but not for intended socket.");
        }
    }
    return packet_size;
}

/*************************************************************************************************/

void Interface::flush() throw(L2T::Exception)
{
    L2T_DEBUG << "Flushing Ethernet " << this->name << ".";

    /* Set receving buffers to zero. */
    int value = 0;
    if (::setsockopt(this->sockfd, SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value)) < 0) {
        L2T_ERROR << "Failed setsockopt SO_RCVBUFFORCE with error " << Errno(errno);
        throw Exception(L2T_ERROR_SOCKET, "Couldn't set receive buffer.");
    }

    char buffer[ETH_FRAME_LEN];

    /* Read from interface until it runs out */
    while (true) {
        try {
            this->receive(buffer, ETH_FRAME_LEN, 1);
        }
        catch (Exception &e) {
            break;
        }
    }

    /* Reset buffer configuration */
    value = 500000; /* Empirical large enough value for buffers size. */
    if (::setsockopt(this->sockfd, SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value)) < 0) {
        L2T_ERROR << "Failed setsockopt SO_RCVBUFFORCE with error " << Errno(errno);
        throw Exception(L2T_ERROR_SOCKET, "Couldn't set receive buffer.");
    }
}

/*************************************************************************************************/

std::string Interface::get_mac_address()
{
    struct ifreq iface_req;

    /* Copy interface name to requisition */
    ::memset(&iface_req, 0, sizeof(struct ifreq));
    ::snprintf(iface_req.ifr_name, sizeof(iface_req.ifr_name), "%s", this->name.c_str());

    /* Get interface hardware address */
    if (::ioctl(this->sockfd, SIOCGIFHWADDR, &iface_req) < 0) {
        L2T_ERROR << "Failed ioctl SIOCGIFHWADDR with error " << Errno(errno);
        throw Exception(L2T_ERROR_SOCKET, "Couldn't get interface MAC.");
    }

    uint8_t *mac_bytes = reinterpret_cast<uint8_t *>(iface_req.ifr_hwaddr.sa_data);
    std::stringstream mac_str;

    mac_str << std::hex << std::uppercase << std::setfill('0');
    for (uint32_t i = 0; i < 6; i++) {
        mac_str << std::setw(2) << (int)(mac_bytes[i]) << (i < 5 ? ":" : "");
    }
    return mac_str.str();
}

void Interface::getFdFlags(int &flags) throw(L2T::Exception)
{
    if ((flags = ::fcntl(this->sockfd, F_GETFL)) < 0) {
        L2T_ERROR << "Failed fcntl F_GETFL with error " << Errno(errno);
        throw Exception(L2T_ERROR_SOCKET, "Couldn't get FD flags.");
    }
}

void Interface::setFdFlags(const int &flags) throw(L2T::Exception)
{
    if (::fcntl(this->sockfd, F_SETFL, flags) < 0) {
        L2T_ERROR << "Failed fcntl F_SETFL with error " << Errno(errno);
        throw Exception(L2T_ERROR_SOCKET, "Couldn't set FD flags.");
    }
}

void Interface::getInterfaceIndex(struct ifreq &iface_req) throw(L2T::Exception)
{
    if (::ioctl(this->sockfd, SIOCGIFINDEX, &iface_req) < 0) {
        L2T_ERROR << "Failed ioctl SIOCGIFINDEX with error " << Errno(errno);
        throw Exception(L2T_ERROR_SOCKET, "Couldn't get interface index.");
    }
}

void Interface::setInterfaceTxQueueLength(struct ifreq &iface_req) throw(L2T::Exception)
{
    if (::ioctl(this->sockfd, SIOCSIFTXQLEN, &iface_req) < 0) {
        L2T_ERROR << "Failed ioctl SIOCSIFTXQLEN with error " << Errno(errno);
        throw Exception(L2T_ERROR_SOCKET, "Couldn't set TX queue.");
    }
}

void Interface::setSocketOptions(struct packet_mreq &pkt_mreq) throw(L2T::Exception)
{
    if (::setsockopt(this->sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, (void *)&pkt_mreq,
                     sizeof(struct packet_mreq)) < 0) {
        L2T_ERROR << "Failed setsockopt PACKET_ADD_MEMBERSHIP with error " << Errno(errno);
        throw Exception(L2T_ERROR_SOCKET, "Couldn't set socket to promiscuous mode.");
    }
    int enable_packet_auxdata = 1;  // Sets PACKET_AUXDATA metadata to true. A variable must be
                                    // declared because setsockopt only accept pointers.

    // Enables PACKET_AUXDATA metadata, which is responsible to get VLAN
    if (::setsockopt(this->sockfd, SOL_PACKET, PACKET_AUXDATA, &enable_packet_auxdata,
                     sizeof(enable_packet_auxdata)) < 0) {
        L2T_ERROR << "Failed setsockopt PACKET_AUXDARA " << Errno(errno);
        throw Exception(L2T_ERROR_SOCKET, "Couldn't set socket to use aux data.");
    }
}

void Interface::setBufferSize(int &value) throw(L2T::Exception)
{
    if (::setsockopt(this->sockfd, SOL_SOCKET, SO_RCVBUFFORCE, &value, sizeof(value)) < 0) {
        L2T_ERROR << "Failed setsockopt SO_RCVBUFFORCE with error " << Errno(errno);
        throw Exception(L2T_ERROR_SOCKET, "Couldn't set receive buffer.");
    }

    if (::setsockopt(this->sockfd, SOL_SOCKET, SO_SNDBUFFORCE, &value, sizeof(value)) < 0) {
        L2T_ERROR << "Failed setsockopt SO_SNDBUFFORCE with error " << Errno(errno);
        throw Exception(L2T_ERROR_SOCKET, "Couldn't set send buffer.");
    }
}

void Interface::bindInterfaceSocket(struct sockaddr_ll &address) throw(L2T::Exception)
{
    if (::bind(this->sockfd, (struct sockaddr *)&address, sizeof(struct sockaddr_ll)) < 0) {
        L2T_ERROR << "Failed bind error " << Errno(errno);
        throw Exception(L2T_ERROR_SOCKET, "Couldn't bind socket.");
    }
}

void Interface::getInterfaceFlags(struct ifreq &iface_req) throw(L2T::Exception)
{
    if (::ioctl(this->sockfd, SIOCGIFFLAGS, &iface_req) < 0) {
        L2T_ERROR << "Failed ioctl SIOCGIFFLAGS with error " << Errno(errno);
        throw Exception(L2T_ERROR_SOCKET, "Couldn't get interface flags.");
    }
}

void Interface::setInterfaceFlags(struct ifreq &iface_req) throw(L2T::Exception)
{
    if (::ioctl(this->sockfd, SIOCSIFFLAGS, &iface_req) < 0) {
        L2T_ERROR << "Failed ioctl SIOCSIFFLAGS with error " << Errno(errno);
        throw Exception(L2T_ERROR_SOCKET, "Couldn't set interface flags.");
    }
}

/*************************************************************************************************/
} /* namespace L2T */
