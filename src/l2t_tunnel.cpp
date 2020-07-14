/*************************************************************************************************/
/**
 * \file
 * \brief Tunnel packet between interfaces.
 */
/*************************************************************************************************/

#include "l2t_tunnel.h"
#include "l2t_scoped_lock.h"

extern "C" {
#include <cstring>
}

namespace L2T {

/*************************************************************************************************/

Tunnel::Tunnel(const std::string &_iface0, const std::string &_iface1) throw(L2T::Exception)
    : Sniffer(1000)
{
    std::vector<std::string> ifaces;
    ifaces.push_back(_iface0);

    ::memset(this->should_drop, 0, sizeof(this->should_drop));

    if (_iface0 != _iface1) {
        this->iface_dst[0] = 1;
        this->iface_dst[1] = 0;
        ifaces.push_back(_iface1);
    } else {
        this->iface_dst[0] = 0;
    }

    this->add_interfaces(ifaces);
    this->add_filter();
    this->start();
};

/*************************************************************************************************/

void Tunnel::set_filter(Filter *_filter)
{
    /* We can't use Sniffer methods for adding/removing filter as we want to have
     * the filters locked during all procedure.
     * Besides, as now we have only one filter, the procedure for removing can be a lot simpler. */
    ScopedLock lock(&this->filter_mutex);

    /* Remove old filter */
    delete this->filter_list.back();
    this->filter_list.pop_back();

    /* Add new one! */
    Filter *new_filter = _filter == NULL ? new Filter() : new Filter(*_filter);
    this->filter_list.push_back(new_filter);
}

/*************************************************************************************************/

void Tunnel::drop_received(bool _iface0, bool _iface1)
{
    this->should_drop[0] = _iface0;
    this->should_drop[1] = _iface1;
}

/*************************************************************************************************/

bool Tunnel::received_packet(uint32_t _iface, uint32_t _filter, void *_packet, size_t _size) throw()
{
    if (!this->should_drop[_iface]) {
        this->iface_list[this->iface_dst[_iface]]->send(_packet, _size);
    }
    return true;
}

/*************************************************************************************************/

} /* namespace L2T */
