/*************************************************************************************************/
/**
 * \file
 * \brief Define class used as Network Interface in L2 tester.
 */
/*************************************************************************************************/

#ifndef L2T_INTERFACE_H
#define L2T_INTERFACE_H

#include "l2t_exception.h"

#include <string>
#include <map>

extern "C" {
#include <net/ethernet.h>  // For ETH_ALEN, ETH_HLEN, ETH_ZLEN
}

namespace L2T {

/**
 * \brief Class that represent an Ethernet Interface.
 *        It uses RAW sockets to send and receive packets.
 */
class Interface {
   public:
    /**
     * \brief Construct new Interface to send and receive raw packets.
     * \param _ifname         Interface name. Ex: "eth0"
     * \param _ether_type     Protocol type used to bind this interface.
     *                        Can be used to filter incoming packets to specific ether type.
     *                        Default is to receive all packets.
     */
    Interface(const std::string &_ifname,
              unsigned short _ether_type = ETH_P_ALL) throw(L2T::Exception);

    /**
     * \brief Destroy interface, releasing resources.
     */
    ~Interface();

    /**
     * \brief Send the packet through the interface.
     * \param _packet    Pointer to the packet.
     * \param _size      Size of the packet. Must be greater than ETH_ZLEN.
     */
    void send(void *_packet, size_t _size) throw(L2T::Exception);

    /**
     * \brief Receive a packet in the interface.
     * \param _packet    Pointer to memory area that will receive the packet.
     * \param _size      Size of the packet buffer.
     * \param _timeout   Timeout to receive packet. Zero to block indefinitely.
     * \return           Return size of the received packet.
     */
    int receive(void *_packet, size_t _size, int _timeout = 0) throw(L2T::Exception);

    /**
     * \brief Remove all packets pending in RX buffers.
     */
    void flush() throw(L2T::Exception);

    /**
     * \brief Return MAC address for this interface.
     * \return MAC address as in the format "XX:XX:XX:XX:XX:XX".
     */
    std::string get_mac_address();

    /**
     * \brief Return the socket file descriptor associated with this interface.
     * \return Socket FD.
     */
    inline int get_socket_fd()
    {
        return this->sockfd;
    }

    /**
     * \brief Return the interface name.
     * \return Interface name.
     */
    inline const std::string &get_name()
    {
        return this->name;
    }

   private:
    int sockfd;       /**< File descriptor of the associated socket. */
    std::string name; /**< Name of the interface */
    int index;        /**< Interface index. */
    fd_set readset;   /**< File descriptor set used for select */

    /**
     * \brief Return the file descriptor flags
     * \param flags File descriptor flags
     */
    void getFdFlags(int &flags) throw(L2T::Exception);

    /**
     * \brief Set the file descriptor flags
     * \param flags File descriptor flags
     */
    void setFdFlags(const int &flags) throw(L2T::Exception);

    /**
     * \brief Return the Interface index
     * \param iface_req Socket iterface
     */
    void getInterfaceIndex(struct ifreq &iface_req) throw(L2T::Exception);

    /**
     * \brief Set the Interface TX queue length
     * \param iface_req Socket iterface
     */
    void setInterfaceTxQueueLength(struct ifreq &iface_req) throw(L2T::Exception);

    /**
     * \brief Set socket options
     * \param pkt_mreq Socket options
     */
    void setSocketOptions(struct packet_mreq &pkt_mreq) throw(L2T::Exception);

    /**
     * \brief Set size of Rx and Tx buffers
     * \param value buffer size
     */
    void setBufferSize(int &value) throw(L2T::Exception);

    /**
     * \brief Bind the socket to the interface
     * \param address Socket address
     */
    void bindInterfaceSocket(struct sockaddr_ll &address) throw(L2T::Exception);

    /**
     * \brief Return the Interface flags
     * \param iface_req Socket iterface
     */
    void getInterfaceFlags(struct ifreq &iface_req) throw(L2T::Exception);

    /**
     * \brief Set the Interface flags
     * \param iface_req Socket iterface
     */
    void setInterfaceFlags(struct ifreq &iface_req) throw(L2T::Exception);
};

} /* namespace L2T */

/** Mapping of interface names and interface pointers **/
typedef std::map<std::string, L2T::Interface *> InterfaceMap;

#endif /* L2T_INTERFACE_H */
