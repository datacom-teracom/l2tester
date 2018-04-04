/*************************************************************************************************/
/**
 * \file
 * \brief Define class to send and check frames using multiples interfaces.
 */
/*************************************************************************************************/

#ifndef L2T_SEND_AND_CHECK_H
#define L2T_SEND_AND_CHECK_H

#include "l2t_sniffer.h"
#include "l2t_sender.h"

#include <map>
#include <vector>

extern "C" {
#include <stdint.h>
}

typedef std::map<std::string, std::vector<std::string> > FrameMapping;

namespace L2T {

/*************************************************************************************************/

/**
 * \brief Class intended to do tests using frame-by-frame analysis with full frame match.
 *        It can be specified what frames should be sent, and from which interfaces.
 *        It's also possible to select interfaces that should be monitored, and what frames should
 * be expected.
 *        To monitor an interface that should not receive a frame, pass to it an empty list.
 */
class SendAndCheck : protected Sniffer {
   public:
    /**
     * \brief Create a new SendAndCheck test.
     * \param _send_frames         Mapping of [interface -> frame list] describing which frames
     *                             and from which interfaces they should be sent.
     * \param _expected_frames     Mapping of [interface -> frame list] describing frames expected
     *                             to be received during test execution.
     * \param _timeout_ms          For how long receiving interfaces should be monitored.
     *                             Default: 1000 ms.
     * \param _filter              Filter to be applied in incoming packets.
     *                             Default : Receive all packets.
     * \param _interval_ms         Interval in milliseconds between each sent packet. Default: 1 ms.
     *                             If analyzed packets are too long or too many it may be necessary
     * to
     *                             use increase this interval.
     */
    SendAndCheck(const FrameMapping& _send_frames, const FrameMapping& _expected_frames,
                 uint32_t _timeout_ms = 1000, Filter* _filter = NULL,
                 uint32_t _interval_ms = 1) throw(L2T::Exception);

    /**
     * \brief Effectively send packets and check received ones.
     */
    void run() throw(L2T::Exception);

    /**
     * \brief Obtain frames received during test execution.
     * \return Return FrameMapping with received frames.
     */
    const FrameMapping& get_received_frames()
    {
        return this->received_frames;
    }

    /**
     * \brief Obtain frames that were expected but not received during test execution.
     *        NOTE: Before running the test, all expected frames are considered missed.
     * \return Return FrameMapping with missed frames.
     */
    const FrameMapping& get_missed_frames()
    {
        return this->missed_frames;
    }

    /**
     * \brief Obtain frames that were not expected but were received during test execution.
     * \return Return FrameMapping with unexpected frames.
     */
    const FrameMapping& get_unexpected_frames()
    {
        return this->unexpected_frames;
    }

   protected:
    /**
     * \brief [Sniffer] Called for each received packet.
     * \param _iface         Interface index that received the packet.
     * \param _filter        Filter index that matched the packet.
     * \param _packet        Packet data.
     * \param _size          Packet size.
     * \return Return true if packet processing was successful, false otherwise.
     *         False will cause receive_loop to finish.
     */
    bool received_packet(uint32_t _iface, uint32_t _filter, void* _packet, size_t _size) throw();

   private:
    uint32_t receive_interval_ms; /**< For how long should we monitor sniffed interfaces. */
    uint32_t interval_ms;         /**< Interval between each sent packet. */

    FrameMapping send_frames;       /**< Frames that will be sent during test execution. */
    FrameMapping received_frames;   /**< Frames that were expected and received. */
    FrameMapping missed_frames;     /**< Frames that were expected but NOT received. */
    FrameMapping unexpected_frames; /**< Frames that were NOT expected but received. */
};

/*************************************************************************************************/

} /* namespace L2T */

#endif /* L2T_TEST_DATA_LOSS_H */
