/*************************************************************************************************/
/**
 * \file
 * \brief Implement class to send and check frames using multiples interfaces.
 */
/*************************************************************************************************/

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>

#include "l2t_logger.h"
#include "l2t_timer.h"
#include "l2t_send_and_check.h"

namespace L2T {

/**************************************************************************************************
 ** L2T::SendAndCheck **
 **************************************************************************************************/

SendAndCheck::SendAndCheck(const FrameMapping &_send_frames, const FrameMapping &_expected_frames,
                           uint32_t _timeout_ms, Filter *_filter,
                           uint32_t _interval_ms) throw(L2T::Exception)
    : Sniffer(500) /* Add an extra 500 ms to receiving timeout. */
      ,
      receive_interval_ms(_timeout_ms),
      interval_ms(_interval_ms),
      send_frames(_send_frames),
      received_frames(),
      missed_frames(
          _expected_frames) /* If we receive nothing, all expected frames are missed ones. */
      ,
      unexpected_frames()
{
    std::vector<std::string> ifaces;
    FrameMapping::const_iterator expected = _expected_frames.begin();
    while (expected != _expected_frames.end()) {
        ifaces.push_back(expected->first);
        ++expected;
    }
    this->add_interfaces(ifaces);
    this->add_filter(_filter);
}

/*************************************************************************************************/

void SendAndCheck::run() throw(L2T::Exception)
{
    /* Reestablish initial values so the same test can be executed multiples times.
     * Received frames are put back into missed ones. Unexpected are cleared. */
    FrameMapping::iterator received = this->received_frames.begin();
    while (received != this->received_frames.end()) {
        std::copy(received->second.begin(), received->second.end(),
                  this->missed_frames[received->first].end());
        this->received_frames.erase(received++);
    }
    this->unexpected_frames.clear();

    /* Start sniffing thread. */
    this->Sniffer::start();

    /* Sleep some time after each sent packet to avoid CPU overload.
     * Some packets were not correctly received otherwise. */
    Timer timer;

    /* Send frames */
    FrameMapping::iterator send_iterator = this->send_frames.begin();
    while (send_iterator != this->send_frames.end()) {
        const std::vector<std::string> &frame_list = send_iterator->second;
        if (!frame_list.empty()) {
            Interface iface(send_iterator->first);
            uint32_t num_frames = frame_list.size();
            for (uint32_t frame_id = 0; frame_id < num_frames; frame_id++) {
                const std::string &frame = frame_list[frame_id];
                iface.send((void *)frame.c_str(), frame.size());
                timer.sleep_ms(this->interval_ms);
            }
        }
        ++send_iterator;
    }

    /* Monitor frame reception for specified amount of time. */
    Timer().sleep_ms(this->receive_interval_ms);

    /* Stop sniffing thread. */
    this->Sniffer::stop();

    /* Remove empty vectors from missed frames. */
    FrameMapping::iterator missed_iterator = this->missed_frames.begin();
    while (missed_iterator != this->missed_frames.end()) {
        if (missed_iterator->second.empty()) {
            this->missed_frames.erase(missed_iterator++);
        } else {
            ++missed_iterator;
        }
    }
}

/*************************************************************************************************/

bool SendAndCheck::received_packet(uint32_t _iface, uint32_t _filter, void *_packet,
                                   size_t _size) throw()
{
    std::string frame((const char *)_packet, _size);
    std::string if_name(this->iface_list[_iface]->get_name());

    std::vector<std::string> &missed = this->missed_frames[if_name];
    std::vector<std::string>::iterator found = std::find(missed.begin(), missed.end(), frame);

    if (found != missed.end()) {
        missed.erase(found);
        this->received_frames[if_name].push_back(frame);
    } else {
        this->unexpected_frames[if_name].push_back(frame);
    }
    return true;
}

/*************************************************************************************************/

} /* namespace L2T */
