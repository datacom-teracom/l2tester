/*************************************************************************************************/
/**
 * \file
 * \brief Define class to tunnel packet between interfaces.
 */
/*************************************************************************************************/

#ifndef L2T_TUNNEL_H
#define L2T_TUNNEL_H

#include "l2t_sniffer.h"
#include "l2t_interface.h"

namespace L2T {

/*************************************************************************************************/

/**
 * \brief Used to create a tunnel between two interfaces.
 *        Every packet received in one interface is delivered unmodified to the other.
 */
class Tunnel : protected Sniffer {
   public:
    /**
     * \brief Construct new Tunnel.
     * \param _first         The first interface. Ex: "eth0"
     * \param _second        The second interface. Ex: "eth1"
     */
    Tunnel(const std::string &_iface0, const std::string &_iface1) throw(L2T::Exception);

    /**
     * \brief Configure filter used to select traffic to be forwarded.
     * \param _filter        Filter to be used. Default: Match all.
     */
    void set_filter(Filter *_filter = NULL);

    /**
     * \brief Used to prevent traffic arriving in interfaces from being forwarded.
     *        Packets can still be delivered to blocked interfaces.
     * \param _iface0        True to drop packets arriving in iface0.
     * \param _iface1        True to drop packets arriving in iface1.
     */
    void drop_received(bool _iface0, bool _iface1);

   protected:
    /**
     * \brief Called for each received packet.
     *        Will forward received packet to destination interface.
     * \param _iface         Interface index that received the packet.
     * \param _filter        [Not used] Filter index that matched the packet.
     * \param _packet        Packet data.
     * \param _size          Packet size.
     * \return Always return true.
     */
    virtual bool received_packet(uint32_t _iface, uint32_t _filter, void *_packet,
                                 size_t _size) throw();

    bool should_drop[2]; /**< Flags to indicate if packets arriving in interfaces should be dropped.
                          */
    int32_t iface_dst[2]; /**< Destination interface for each receiving interface. */
};

/*************************************************************************************************/

} /* namespace L2T */

#endif /* L2T_TUNNEL_H */
