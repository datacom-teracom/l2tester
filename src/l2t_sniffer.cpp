/*************************************************************************************************/
/**
 * \file
 * \brief Implement class to monitor interface for incoming packets.
 */
/*************************************************************************************************/

#include "l2t_sniffer.h"
#include "l2t_logger.h"
#include "l2t_scoped_lock.h"

#include <set>
#include <map>
#include <algorithm>

#include <cstdio>
#include <cstdlib>

extern "C" {
#include <time.h>
#include <unistd.h>  // For usleep
#include <pthread.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <string.h>
#include <errno.h>
#include <linux/version.h>
}

using namespace L2T;

/**************************************************************************************************
 ** L2T::Filter **
 **************************************************************************************************/

Filter::Filter() : match_all(true), inversed(false), mask(NULL), data(NULL), length(0), byte(0)
{
    L2T_INFO << "Creating Filter.";
}

/*************************************************************************************************/

Filter::Filter(const Filter &_other)
    : match_all(_other.match_all),
      inversed(_other.inversed),
      mask(NULL),
      data(NULL),
      length(_other.length),
      byte(_other.byte)
{
    L2T_INFO << "Creating Filter by copy.";

    if (_other.mask != NULL) {
        this->mask = new uint32_t[this->length];
        ::memcpy(this->mask, _other.mask, this->length * sizeof(uint32_t));
    }
    if (_other.data != NULL) {
        this->data = new uint32_t[this->length];
        ::memcpy(this->data, _other.data, this->length * sizeof(uint32_t));
    }
}

/*************************************************************************************************/

Filter::~Filter()
{
    L2T_INFO << "Deleting Filter.";

    if (mask != NULL) {
        delete[] mask;
    }
    if (data != NULL) {
        delete[] data;
    }
}

/*************************************************************************************************/

bool Filter::match(void *_packet, size_t _size)
{
    bool ret = true;

    if (this->byte + sizeof(uint32_t) * this->length >= _size) {
        /* Packet is too small, can't match. */
        ret = false;
    } else if (!this->match_all) {
        /* If this is not "match all" filter, try to match packet. */
        uint32_t *packet = (uint32_t *)((uint8_t *)_packet + this->byte);
        for (uint8_t i = 0; i < this->length; i++) {
            if ((this->mask[i] & packet[i]) != this->data[i]) {
                ret = false;
                break;
            }
        }
    }
    return ret != this->inversed;
}

/*************************************************************************************************/

void Filter::inverse()
{
    this->inversed = !this->inversed;
}

/*************************************************************************************************/

void Filter::match32bits(uint32_t _data, uint32_t _mask, uint16_t _byte) throw(L2T::Exception)
{
    uint32_t newLength;
    uint16_t newByte;

    /* Accepts only 32bit word addresses */
    if (_byte % 4 != 0) {
        L2T_ERROR << "Received byte " << _byte << " is not multiple of 4.";
        throw Exception(L2T_ERROR_INVALID_CONFIG, "'_byte' argument is not multiple of 4.");
    }

    /* First of all, make a backup of the original data */
    uint32_t bkpMask[length];
    uint32_t bkpData[length];
    memcpy(bkpMask, mask, length * sizeof(uint32_t));
    memcpy(bkpData, data, length * sizeof(uint32_t));

    delete[] mask;
    delete[] data;

    /* Now recalculate the new length and byte */
    int currentLastByte = byte + length * 4 - 1;

    // If it's the first data to be matched, the length is 1 and the starting byte is the received
    if (length == 0) {
        newLength = 1;
        newByte = _byte;
    }
    // If the received starting byte is less than the current one, recalculate length
    else if (_byte < byte) {
        newLength = (currentLastByte - _byte + 1) / 4;
        newByte = _byte;
    }
    // If the new starting byte is beyond the current last byte, recalculate length
    else if (_byte > currentLastByte) {
        int newLastByte = _byte + 3;
        newLength = (newLastByte - byte + 1) / 4;
        newByte = byte;
    }
    // If the new starting byte already exists, the new length and byte are the same
    else {
        newLength = length;
        newByte = byte;
    }

    /* Allocate memory */
    mask = (uint32_t*) malloc(newLength * sizeof(uint32_t));
    data = (uint32_t*) malloc(newLength * sizeof(uint32_t));
    memset(mask, 0, newLength * sizeof(uint32_t));
    memset(data, 0, newLength * sizeof(uint32_t));

    /* Place the already existing data */
    int index = (byte - newByte) / 4;
    memcpy(mask + index, bkpMask, length * sizeof(uint32_t));
    memcpy(data + index, bkpData, length * sizeof(uint32_t));

    /* Place the new data */
    index = (_byte - newByte) / 4;
    data[index] = _data;
    mask[index] = _mask;

    length = newLength;
    byte = newByte;

    match_all = false;

    L2T_DEBUG << "Mask:   " << *mask << std::endl;
    L2T_DEBUG << "Data:   " << *data << std::endl;
    L2T_DEBUG << "Byte:   " << byte << std::endl;
    L2T_DEBUG << "Length: " << length << std::endl;
}

/**************************************************************************************************
 ** L2T::EthernetFilter **
 **************************************************************************************************/

EthernetFilter::EthernetFilter()
    : Filter(),
      dst_mac(),
      src_mac(),
      outer_tpid(-1),
      outer_vlan(-1),
      outer_prio(-1),
      inner_tpid(-1),
      inner_vlan(-1),
      inner_prio(-1)
{
    L2T_INFO << "Creating new EthernetFilter.";
}

/*************************************************************************************************/

static void mac_from_string(const std::string &_input,
                            uint8_t (*_output)[ETH_ALEN]) throw(L2T::Exception)
{
    /* Verify supplied format is "XX:XX:XX:XX:XX:XX" */
    static const size_t required_size = std::string("XX:XX:XX:XX:XX:XX").size();
    if (_input.size() == required_size) {
        char *mac_str = const_cast<char *>(_input.c_str());
        int pos = 0;
        while (mac_str != NULL && pos < ETH_ALEN) {
            (*_output)[pos] = strtol(mac_str, &mac_str, 16);
            if (pos < ETH_ALEN - 1 && mac_str && mac_str[0] != ':') {
                throw Exception(L2T_ERROR_INVALID_CONFIG, "Invalid MAC Address format.");
            }
            mac_str++;
            pos++;
        }
    } else {
        L2T_ERROR << "MAC Address string with invalid size " << _input.size() << " (expected "
                  << required_size << ").";
        throw Exception(L2T_ERROR_INVALID_CONFIG, "MAC Address string with invalid size.");
    }
}

/*************************************************************************************************/

void EthernetFilter::compile() throw(L2T::Exception)
{
    uint8_t idx_first = 0xFF, idx_last = 0x00;
    uint8_t temp_mask[ETH_HLEN + 2 * VLAN_HLEN];
    uint8_t temp_data[ETH_HLEN + 2 * VLAN_HLEN];
    uint8_t mask_mac[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

    /* If any field was valid, update internal mask and data. */
    bool has_valid_field = false;

    ::memset(&temp_mask, 0, sizeof(temp_mask));
    ::memset(&temp_data, 0, sizeof(temp_data));

    if (this->data != NULL) {
        delete[] this->data;
        this->data = NULL;
    }
    if (this->mask != NULL) {
        delete[] this->mask;
        this->mask = NULL;
    }

    L2T_DEBUG << "Compiling EthernetFilter:";

    compileDstMac(idx_first, idx_last, temp_mask, temp_data, mask_mac, has_valid_field);
    compileSrcMac(idx_first, idx_last, temp_mask, temp_data, mask_mac, has_valid_field);
    compileOuterTpid(idx_first, idx_last, temp_mask, temp_data, has_valid_field);
    compileOuterVlan(idx_first, idx_last, temp_mask, temp_data, has_valid_field);
    compileOuterPrio(idx_first, idx_last, temp_mask, temp_data, has_valid_field);
    compileInnerTpid(idx_first, idx_last, temp_mask, temp_data, has_valid_field);
    compileInnerVlan(idx_first, idx_last, temp_mask, temp_data, has_valid_field);
    compileInnerPrio(idx_first, idx_last, temp_mask, temp_data, has_valid_field);

    if (has_valid_field) {
        this->match_all = false;
        this->byte = idx_first * sizeof(uint32_t);
        this->length = idx_last + 1 - idx_first;
        this->data = new uint32_t[this->length];
        this->mask = new uint32_t[this->length];
        uint32_t length_bytes = this->length * sizeof(uint32_t);

        ::memcpy(this->data, &temp_data[idx_first * sizeof(uint32_t)], length_bytes);
        ::memcpy(this->mask, &temp_mask[idx_first * sizeof(uint32_t)], length_bytes);
        L2T_DEBUG << "  => Byte   : " << this->byte;
        L2T_DEBUG << "  => Length : " << this->length;
        L2T_DEBUG << "  => Data   : " << ByteArray(this->data, length_bytes);
        L2T_DEBUG << "  => Mask   : " << ByteArray(this->mask, length_bytes);
    } else {
        this->match_all = true;
        L2T_DEBUG << "  => Match ALL filter.";
    }
}

void EthernetFilter::compileDstMac(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                                   uint8_t *temp_data, uint8_t *mask_mac,
                                   bool &has_valid_field) throw(L2T::Exception)
{
    if (this->dst_mac[0] != '\0') {
        uint8_t dst_mac_bytes[ETH_ALEN];
        L2T_DEBUG << "  * dest mac  : " << std::string(this->dst_mac);
        mac_from_string(this->dst_mac, &dst_mac_bytes);
        ::memcpy(temp_mask, mask_mac, ETH_ALEN);
        ::memcpy(temp_data, dst_mac_bytes, ETH_ALEN);
        idx_first = std::min<uint8_t>(idx_first, 0);
        idx_last = std::max<uint8_t>(idx_last, 1);
        has_valid_field = true;
    }
}

void EthernetFilter::compileSrcMac(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                                   uint8_t *temp_data, uint8_t *mask_mac,
                                   bool &has_valid_field) throw(L2T::Exception)
{
    if (this->src_mac[0] != '\0') {
        uint8_t src_mac_bytes[ETH_ALEN];
        L2T_DEBUG << "  * source mac : " << std::string(this->src_mac);
        mac_from_string(this->src_mac, &src_mac_bytes);
        ::memcpy(temp_mask + ETH_ALEN, mask_mac, ETH_ALEN);
        ::memcpy(temp_data + ETH_ALEN, src_mac_bytes, ETH_ALEN);
        idx_first = std::min<uint8_t>(idx_first, 1);
        idx_last = std::max<uint8_t>(idx_last, 2);
        has_valid_field = true;
    }
}

void EthernetFilter::compileOuterTpid(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                                      uint8_t *temp_data,
                                      bool &has_valid_field) throw(L2T::Exception)
{
    if (this->outer_tpid >= 0) {
        L2T_DEBUG << "  * outer tpid : 0x" << std::hex << std::setfill('0') << std::setw(4)
                  << this->outer_tpid;
        (*(uint16_t *)&(temp_mask[2 * ETH_ALEN])) |= 0xFFFF;
        (*(uint16_t *)&(temp_data[2 * ETH_ALEN])) |= htons(this->outer_tpid);

        idx_first = std::min<uint8_t>(idx_first, 3);
        idx_last = std::max<uint8_t>(idx_last, 3);
        has_valid_field = true;
    }
}

void EthernetFilter::compileOuterVlan(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                                      uint8_t *temp_data,
                                      bool &has_valid_field) throw(L2T::Exception)
{
    if (this->outer_vlan >= 0) {
        L2T_DEBUG << "  * outer vlan : " << this->outer_vlan;
        temp_mask[ETH_HLEN] |= 0x0F;
        temp_mask[ETH_HLEN + 1] |= 0xFF;
        temp_data[ETH_HLEN] |= ((this->outer_vlan >> 8) & 0x0F);
        temp_data[ETH_HLEN + 1] |= (this->outer_vlan & 0xFF);

        idx_first = std::min<uint8_t>(idx_first, 3);
        idx_last = std::max<uint8_t>(idx_last, 3);
        has_valid_field = true;
    }
}

void EthernetFilter::compileOuterPrio(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                                      uint8_t *temp_data,
                                      bool &has_valid_field) throw(L2T::Exception)
{
    if (this->outer_prio >= 0) {
        L2T_DEBUG << "  * outer prio : " << (int)this->outer_prio;
        temp_mask[ETH_HLEN] |= 0xE0;
        temp_data[ETH_HLEN] |= ((this->outer_prio << 5) & 0xE0);

        idx_first = std::min<uint8_t>(idx_first, 3);
        idx_last = std::max<uint8_t>(idx_last, 3);
        has_valid_field = true;
    }
}

void EthernetFilter::compileInnerTpid(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                                      uint8_t *temp_data,
                                      bool &has_valid_field) throw(L2T::Exception)
{
    if (this->inner_tpid >= 0) {
        L2T_DEBUG << "  * inner tpid : 0x" << std::hex << std::setfill('0') << std::setw(4)
                  << this->inner_tpid;
        (*(uint16_t *)&(temp_mask[2 * ETH_ALEN + VLAN_HLEN])) |= 0xFFFF;
        (*(uint16_t *)&(temp_data[2 * ETH_ALEN + VLAN_HLEN])) |= htons(this->inner_tpid);

        idx_first = std::min<uint8_t>(idx_first, 4);
        idx_last = std::max<uint8_t>(idx_last, 4);
        has_valid_field = true;
    }
}

void EthernetFilter::compileInnerVlan(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                                      uint8_t *temp_data,
                                      bool &has_valid_field) throw(L2T::Exception)
{
    if (this->inner_vlan >= 0) {
        L2T_DEBUG << "  * inner vlan : " << this->inner_vlan;
        temp_mask[ETH_HLEN + VLAN_HLEN] |= 0x0F;
        temp_mask[ETH_HLEN + VLAN_HLEN + 1] |= 0xFF;
        temp_data[ETH_HLEN + VLAN_HLEN] |= ((this->inner_vlan >> 16) & 0x0F);
        temp_data[ETH_HLEN + VLAN_HLEN + 1] |= (this->inner_vlan & 0xFF);

        idx_first = std::min<uint8_t>(idx_first, 4);
        idx_last = std::max<uint8_t>(idx_last, 4);
        has_valid_field = true;
    }
}

void EthernetFilter::compileInnerPrio(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                                      uint8_t *temp_data,
                                      bool &has_valid_field) throw(L2T::Exception)
{
    if (this->inner_prio >= 0) {
        L2T_DEBUG << "  * inner prio : " << (int)this->inner_prio;
        temp_mask[ETH_HLEN + VLAN_HLEN] |= 0xE0;
        temp_data[ETH_HLEN + VLAN_HLEN] |= ((this->inner_prio << 5) & 0xE0);

        idx_first = std::min<uint8_t>(idx_first, 4);
        idx_last = std::max<uint8_t>(idx_last, 4);
        has_valid_field = true;
    }
}

/**************************************************************************************************
 ** L2T::Sniffer **
 **************************************************************************************************/

Sniffer::Sniffer(uint32_t _timeout_ms) throw(L2T::Exception)
    : receive_thread(this, &Sniffer::receive_loop),
      receive_stop(true),
      iface_list(),
      iface_map(),
      sockfd_list(),
      filter_list(),
      is_configuring(false),
      timeout_ms(_timeout_ms),
      max_fd(0)
{
    L2T_INFO << "Creating new Sniffer.";

    ::pthread_mutex_init(&this->iface_mutex, NULL);
    ::pthread_mutex_init(&this->filter_mutex, NULL);

    FD_ZERO(&originalset);
    FD_ZERO(&readset);
}

/*************************************************************************************************/

Sniffer::~Sniffer()
{
    L2T_DEBUG << "Deleting Sniffer.";

    /* Finish thread before destroying this Sniffer. */
    this->stop();

    /* Remove all associated Interface objects. */
    while (!this->iface_list.empty()) {
        delete this->iface_list.back();
        this->iface_list.pop_back();
    }

    /* Remove all associated Filter objects. */
    while (!this->filter_list.empty()) {
        delete this->filter_list.back();
        this->filter_list.pop_back();
    }

    this->iface_map.clear();
}

/*************************************************************************************************/

void Sniffer::add_interfaces(std::vector<std::string> _interfaces) throw(L2T::Exception)
{
    if (_interfaces.empty()) {
        throw Exception(L2T_ERROR_INVALID_CONFIG, "Must specify at least one interface.");
    }

    this->is_configuring = true;
    ScopedLock lock(&this->iface_mutex);

    /* Create interfaces */
    for (uint32_t i = 0; i < _interfaces.size(); i++) {
        std::string iface_name = _interfaces[i];
        if (this->iface_map[iface_name] == NULL) {
            Interface *iface = new Interface(iface_name);
            this->iface_list.push_back(iface);
            this->iface_map[iface_name] = iface;
            this->sockfd_list.push_back(iface->get_socket_fd());
            FD_SET(iface->get_socket_fd(), &originalset);
        } else {
            L2T_WARNING << "Interface " << iface_name << " is already monitored.";
        }
    }

    this->max_fd = *std::max_element(this->sockfd_list.begin(), this->sockfd_list.end());
    ::memcpy(&readset, &originalset, sizeof(fd_set));
    this->is_configuring = false;
}

/*************************************************************************************************/

void Sniffer::remove_interfaces(std::vector<std::string> _interfaces) throw(L2T::Exception)
{
    if (_interfaces.empty()) {
        L2T_WARNING << "No interfaces specified to be removed.";
        throw Exception(L2T_ERROR_INVALID_CONFIG, "Must specify at least one interface.");
    }

    this->is_configuring = true;
    ScopedLock lock(&this->iface_mutex);

    /* Remove interfaces */
    for (uint32_t i = 0; i < _interfaces.size(); i++) {
        std::string iface_name = _interfaces[i];
        InterfaceMap::iterator it = this->iface_map.find(iface_name);
        if (it != this->iface_map.end()) {
            /* Found interface, remove it! */
            Interface *iface = it->second;
            this->iface_map.erase(it);

            std::vector<Interface *>::iterator pointer
                = std::find(this->iface_list.begin(), this->iface_list.end(), iface);
            this->iface_list.erase(pointer);

            std::vector<int>::iterator socket = std::find(
                this->sockfd_list.begin(), this->sockfd_list.end(), iface->get_socket_fd());
            this->sockfd_list.erase(socket);

            FD_CLR(iface->get_socket_fd(), &originalset);

            delete iface;
        } else {
            L2T_WARNING << "Interface " << iface_name << " is not monitored.";
        }
    }

    this->max_fd = *std::max_element(this->sockfd_list.begin(), this->sockfd_list.end());
    ::memcpy(&readset, &originalset, sizeof(fd_set));
    this->is_configuring = false;
}

/*************************************************************************************************/

Filter *Sniffer::add_filter(Filter *_filter) throw(L2T::Exception)
{
    this->is_configuring = true;
    ScopedLock lock(&this->filter_mutex);

    /* Make a copy of the filter to avoid ownership problems with SWIG.
     * The parameter was probably allocated by SWIG so it can be deallocated any time by it. */
    Filter *new_filter = _filter == NULL ? new Filter() : new Filter(*_filter);

    this->filter_list.push_back(new_filter);

    this->is_configuring = false;
    return new_filter;
}

/*************************************************************************************************/

void Sniffer::remove_filter(Filter *_filter) throw(L2T::Exception)
{
    if (_filter == NULL) {
        L2T_ERROR << "Invalid Filter passed to remove_filter.";
        throw Exception(L2T_ERROR_INVALID_CONFIG, "NULL Filter pointer.");
    }

    this->is_configuring = true;
    ScopedLock lock(&this->filter_mutex);
    std::vector<Filter *>::iterator it
        = std::find(this->filter_list.begin(), this->filter_list.end(), _filter);
    if (it != this->filter_list.end()) {
        /* Found desired Filter! Delete it! */
        L2T::Filter *filter = *it;
        this->filter_list.erase(it);
        delete filter;
    } else {
        L2T_WARNING << "Filter is not associated with this Sniffer.";
    }
    this->is_configuring = false;
}

/*************************************************************************************************/

void Sniffer::start() throw(L2T::Exception)
{
    if (this->receive_thread.is_running()) {
        L2T_ERROR << "Already running. Stop it first.";
        throw Exception(L2T_ERROR_INVALID_OPERATION, "Sniffer already started.");
    }

    ScopedLock lock(&this->iface_mutex);
    /* Flush all interfaces */
    for (uint32_t i = 0; i < this->iface_list.size(); i++) {
        this->iface_list[i]->flush();
    }

    this->receive_stop = false;
    this->receive_thread.start();
}

/*************************************************************************************************/

void Sniffer::stop() throw(L2T::Exception)
{
    if (!this->receive_stop) {
        this->receive_stop = true;
        this->receive_thread.join();
    }
}

/*************************************************************************************************/

bool Sniffer::received_packet(uint32_t _iface, uint32_t _filter, void *_packet,
                              size_t _size) throw()
{
    L2T_DEBUG << "Received packet (interface " << this->iface_list[_iface]->get_name()
              << ", filter " << _filter << ", size " << _size << "):";
    L2T_DEBUG << ByteArray(_packet, _size);
    return true;
}

void Sniffer::metadataHandler(struct msghdr *msg, signed int *packet_size)
{
    struct cmsghdr *cmsg;

    for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        struct tpacket_auxdata *aux;
        unsigned int len;
        struct vlan_tag *tag;

        if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct tpacket_auxdata))
            || cmsg->cmsg_level != SOL_PACKET || cmsg->cmsg_type != PACKET_AUXDATA)
            continue;

        aux = (struct tpacket_auxdata *)CMSG_DATA(cmsg);
        if (aux->tp_vlan_tci == 0)
            continue;

        // Smaller between buffers size (msg->msg_iov->iov_len) and packet size
        len = *packet_size > (signed int)msg->msg_iov->iov_len ? msg->msg_iov->iov_len
                                                               : *packet_size;

        if (len < 2 * ETH_ALEN)
            break;

        // Moves the frame opening a gap after MACs to VLAN tag
        memmove((uint8_t *)msg->msg_iov->iov_base + VLAN_HLEN + 2 * ETH_ALEN,
                (uint8_t *)msg->msg_iov->iov_base + 2 * ETH_ALEN,
                msg->msg_iov->iov_len - 2 * ETH_ALEN - VLAN_HLEN);

        tag = (struct vlan_tag *)((uint8_t *)msg->msg_iov->iov_base + 2 * ETH_ALEN);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
        tag->vlan_tpid = htons(aux->tp_padding);
#else
        tag->vlan_tpid = htons(aux->tp_vlan_tpid);
#endif
        tag->vlan_tci = htons(aux->tp_vlan_tci);

        *packet_size += VLAN_HLEN;

        // If a VLAN was added and EtherType was 0x8100, the packet comes with no EtherType.
        // This lines fix it.
        if (((uint8_t *)msg->msg_iov->iov_base)[12] == 0x00
            && ((uint8_t *)msg->msg_iov->iov_base)[13] == 0x00) {
            ((uint8_t *)msg->msg_iov->iov_base)[12] = 0x81;
            ((uint8_t *)msg->msg_iov->iov_base)[13] = 0x00;
        }
    }
}

/*************************************************************************************************/

void Sniffer::receive_loop() throw()
{
    L2T_DEBUG << "Starting receive loop.";

    struct timeval timeout;

    while (!this->receive_stop) {

        timeout.tv_sec = this->timeout_ms / 1000;
        timeout.tv_usec = (this->timeout_ms % 1000) * 1000;

        /* User can change configuration only between each receive loop.
         * Sleep a while to allow the configuring thread to obtain the lock. */
        if (this->is_configuring) {
            usleep(1000);
        }

        ScopedLock lock(&this->iface_mutex);
        int sel = ::select(this->max_fd + 1, &this->readset, NULL, NULL, &timeout);

        if (sel == -1) { /* Error in select function */

            /* The fd_set were left in undefined state. Readjusts it! */
            ::memcpy(&this->readset, &this->originalset, sizeof(fd_set));
            L2T_ERROR << "Failed select (max_fd " << max_fd << ") with error " << Errno(errno);
            continue;

        } else if (sel == 0) { /* select timedout */

            /* Reset bit for next call! */
            ::memcpy(&this->readset, &this->originalset, sizeof(fd_set));
            continue;

        } else {

            int num_sockets = this->sockfd_list.size();

            for (int sock = 0; sock < num_sockets; sock++) {
                if (FD_ISSET(this->sockfd_list[sock], &this->readset)) {
                    signed int packet_size;
                    struct iovec iov;
                    struct msghdr msg;
                    union {
                        struct cmsghdr cmsg;
                        char buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
                    } cmsg_buf;

                    /* Struct used to verify received address. */
                    struct ::sockaddr_ll address;
                    socklen_t address_len = sizeof(address);

                    uint8_t buffer[1600];

                    msg.msg_name = &address;
                    msg.msg_namelen = address_len;
                    msg.msg_iov = &iov;
                    msg.msg_iovlen = 1;
                    msg.msg_control = &cmsg_buf;
                    msg.msg_controllen = sizeof(cmsg_buf);
                    msg.msg_flags = 0;

                    iov.iov_len = sizeof(buffer);
                    iov.iov_base = (void *)buffer;

                    /* Packet to receive in interface */
                    packet_size = ::recvmsg(this->sockfd_list[sock], &msg, MSG_TRUNC);

                    if (packet_size < 0) {
                        L2T_ERROR << "Failed recvmsg with error " << Errno(errno);
                        continue;
                    }

                    metadataHandler(&msg, &packet_size);

                    if (address.sll_pkttype == PACKET_OUTGOING) {
                        continue;
                    }

                    /* Process incoming packet. */
                    if (processIncomingPacket(sock, buffer, packet_size) < 0) {
                        return;
                    }

                } else {
                    FD_SET(this->sockfd_list[sock], &this->readset);
                }
            }
        }
    }

    L2T_DEBUG << "Receive loop finished.";
}

int Sniffer::processIncomingPacket(int sock, uint8_t *buffer, int packet_size)
{
    ScopedLock lock(&this->filter_mutex);
    int num_filters = this->filter_list.size();
    for (int filter = 0; filter < num_filters; filter++) {
        if (this->filter_list[filter]->match(buffer, packet_size)) {
            if (!this->received_packet(sock, filter, (void *)buffer, packet_size)) {
                L2T_ERROR << "Failed to process packet. Aborting receive loop.";
                return -1;
            }
        }
    }
    return 0;
}

/*************************************************************************************************/
