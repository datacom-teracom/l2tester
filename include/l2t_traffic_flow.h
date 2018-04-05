/*************************************************************************************************/
/**
 * \file
 * \brief Define tools for monitoring a data path using a specific traffic flow.
 *        It provide ways for sending a periodic and sequential traffic and ways
 *        of measuring this traffic interruption or loops.
 */
/*************************************************************************************************/

#ifndef L2T_TRAFFIC_FLOW_H
#define L2T_TRAFFIC_FLOW_H

#include "l2t_sniffer.h"
#include "l2t_sender.h"
#include "l2t_thread.h"
#include "l2t_iterable.h"
#include "l2t_timer.h"

#include <vector>

extern "C" {
#include <stdint.h>
}

namespace L2T {
namespace TrafficFlow {

/*************************************************************************************************/

/**
 * \brief Represent a single event for traffic monitoring.
 */
struct Event {
    /**
     * \brief Enumerate possible types of Events.
     */
    enum Type {
        TEST_STARTED,  /**< Start of the test. */
        TEST_FINISHED, /**< End of the test. */

        TRAFFIC_STARTED, /**< Traffic flow started. Received a valid sent packet. */
        TRAFFIC_STOPPED, /**< Missed any packet. */

        LOOP_STARTED, /**< Started to receive duplicate packets or received packet in source
                         interface. */
        LOOP_STOPPED, /**< Traffic flow stabilized. */

        ERROR_DETECTED, /**< Wrong packet received. Test is aborted and ends without TEST_FINISHED
                           event. */
    };

    /**
     * \brief Create new Event.
     * \param _timestamp_ms  Time in ms since test started.
     * \param _type          Type of the event.
     */
    Event(uint64_t _timestamp_ms, Type _type) : timestamp_ms(_timestamp_ms), type(_type)
    {
    }

    /**
     * \brief Convert an event type into char string.
     * \param _type          Type to be converted.
     * \return String with type name.
     */
    static const std::string type_to_str(Type _type);

    uint64_t timestamp_ms; /**< Timestamp in ms since Monitor started. */
    Type type;             /**< Type of this event. */
};

/*************************************************************************************************/

/**
 * \brief Traffic Flow statistics.
 */
struct Statistics {
    uint64_t traffic_interruption_ms;        /**< Total interruption time in milliseconds. */
    uint32_t traffic_interruption_intervals; /**< Number of traffic interruptions. */

    uint64_t loop_detected_ms;        /**< Total loop time in milliseconds. */
    uint32_t loop_detected_intervals; /**< Number of loop intervals. */

    uint64_t sent_packets;     /**< Number of sent packets. */
    uint64_t received_packets; /**< Number of valid received packets. */
    uint64_t dropped_packets;  /**< Number of dropped packets by loop detection. */

    bool error_detected; /**< True if an error was detected during test execution. */
};

/*************************************************************************************************/

/**
 * \brief Monitor a Traffic Flow for particular events.
 *        A traffic is defined by a source and destination interface with associated packet and
 *action.
 *        Each time a packet is sent, the specified action is applied. They must create unique
 *packets
 *        that are sent from source and checked in destination interface. While sent packets are
 *received,
 *        we consider that traffic is up. This state is bounded a TRAFFIC_STARTED and
 *TRAFFIC_STOPPED events.
 *        We verify traffic interruption using two approaches:
 *        1) We only keep the last [max_delayed_packets] sent packets. If we do not receive any
 *packets during
 *           [max_delayed_packets] * [packet_interval_ms], we assume traffic was interrupted and an
 *event
 *           TRAFFIC_STOPPED with the timestamp of the last received packet is generated.
 *        2) Inside the timeout interval, we receive an unexpected packet. Suppose we are waiting
 *for the 26th
 *           packet but the incoming packet didn't match its ID. We try to match the 27th, the 28th,
 *and so on
 *           until we reach all sent packets. If we match a newer packet, two events are generated:
 *TRAFFIC_STOPPED
 *           with the received ID before this one, and one TRAFFIC_STARTED with the newer matched
 *ID.
 *           If no packet matches, this can mean two things:
 *           2.a) We verify if the packet is an old one (25th, 24th, ...) . If that is the case, we
 *received
 *                a duplicated packet and we are in loop condition.
 *           2.b) It's not an old packet (at least is not in the [max_delayed_packet] window. In
 *this case
 *                and ERROR_DETECTED event is generated and the test is aborted.
 *
 *        If we receive a packet in the source interface or a duplicate packet in the destination
 *interface,
 *        we consider a loop was detected. This state is bounded by the LOOP_STARTED and
 *LOOP_STOPPED events.
 *        During a loop event we stop sending frames so the traffic state is unknown. For the sake
 *of statistics,
 *        loop periods are always counted as "no traffic".
 *
 *        As we are no longer sending frames, we consider the loop has ended once we do not receive
 *frames for
 *        at least 50 ms (empirically determined to avoid false loop ends). After that we resume
 *packet sending
 *        and checking.
 *
 *        Remarks:
 *        1) This tests are only valid as long as we assume packet order is maintained. If that is
 *not the
 *        case, spurious events will be generated.
 *        2) The filter parameter should be used to isolate the generated traffic flow from other
 *traffics.
 *           If unexpected packets are received the test will be aborted.
 */
class Monitor : protected Sniffer, protected Sender {
   public:
    /**
     * \brief Create a new Monitor for specific traffic flow.
     * \param _src                 The source interface. Ex: "eth0"
     * \param _dst                 The destination interface. Ex: "eth1"
     * \param _packet              Packet data to be sent.
     * \param _size                Size of the packet.
     * \param _packet_interval_ms  Interval between each packet. Default : 10ms.
     * \param _action              Action to be performed in packets so they can be uniquely
     * identified.
     *                             Default : Increment four bytes after the ethertype.
     * \param _filter              Filter to be applied in incoming packets.
     *                             Default : Receive all packets.
     */
    Monitor(const std::string& _src, const std::string& _dst, void* _packet, size_t _size,
            uint32_t _packet_interval_ms = 10, Action* _action = NULL,
            Filter* _filter = NULL) throw(L2T::Exception);

    /**
     * \brief Stop test if running and free packet memory.
     */
    virtual ~Monitor();

    /**
     * \brief Run Monitor in blocking mode based on number of packets or timeout.
     * \param _num_packets   Number of packets to be sent during execution. Pass 0 to ignore.
     * \param _timeout       Maximum time of execution in milliseconds. Pass 0 to ignore.
     */
    void run(uint64_t _num_packets = 0, uint32_t _timeout_ms = 0) throw(L2T::Exception);

    /**
     * \brief Start all threads to send and check packets.
     */
    void start() throw(L2T::Exception);

    /**
     * \brief Stop all threads and wait then to be finished.
     */
    void stop() throw(L2T::Exception);

    /**
     * \brief Iterate through stored events.
     * \param _start         ID of event to start iteration.
     *                          0 : to read next unread event.
     *                          1 : start from oldest stored event.
     *                         -1 : start from next incoming event.
     * \param _block         If True, block until there's a new event available.
     * \param _timeout_ms    Timeout in milliseconds if blocking operation. Zero to wait forever.
     * \return Return a pointer to next event. NULL if last one and not blocking or blocking and
     * timed out.
     */
    const Event* iterate_event(int _start = 0, bool _block = true, uint32_t _timeout_ms = 0);

    /**
     * \brief Get test statistics.
     * \param _stats         Pointer to struct that should be used.
     */
    void get_statistics(Statistics* _stats);

    /**
     * \brief Monitor internal timers.
     */
    void timers_loop();

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
    virtual bool received_packet(uint32_t _iface, uint32_t _filter, void* _packet,
                                 size_t _size) throw();

    /**
     * \brief [Sender] Called before each packet is sent.
     * \return Return true if packet should be sent, false otherwise.
     */
    virtual bool should_send_packet() throw();

   private:
    /**
     * \brief Handle pre-test execution and register TEST_STARTED event.
     */
    void test_started_event();

    /**
     * \brief Handle post-test execution and register TEST_FINISHED event.
     */
    void test_finished_event();

    /**
     * \brief Handle traffic detection. Update associated timer.
     *        If traffic is not in progress, register TRAFFIC_STARTED event.
     */
    void traffic_detected_event();

    /**
     * \brief Handle and register TRAFFIC_STOPPED event.
     */
    void traffic_stopped_event();

    /**
     * \brief Handle loop detection. Update associated timer.
     *        If a loop is not in progress, register LOOP_STARTED event.
     */
    void loop_detected_event();

    /**
     * \brief Handle and register LOOP_STOPPED event.
     */
    void loop_stopped_event();

    /**
     * \brief Verify received flow for errors
     * \param _packet  Packet data.
     * \param _size    Packet size.
     * \return true if ok, false otherwise
     */
    bool verify_received_packet(void* _packet, size_t _size) throw();

    static const int max_delayed_packets = 16; /**< Maximum delay in number of packets. */

    uint64_t packet_seq_tx; /**< Sequence number of last sent packet. */
    uint64_t packet_seq_rx; /**< Sequence number of last received packet. */

    uint64_t packet_id_list[max_delayed_packets]; /**< Unique identifier of last sent packets. */
    uint32_t packet_interval_ms;                  /**< Interval in ms between each sent packet. */

    pthread_mutex_t packet_mutex; /**< Used to lock packet related variables. */

    bool traffic_started_enabled; /**< Boolean to indicate if traffic is current up and running. */
    Timer traffic_started_timer;  /**< Timer to verify traffic is still running. */

    bool loop_detected_enabled;
    Timer loop_detected_timer; /**< Timer to verify loop is still going on. */
    Timer loop_started_timer;  /**< Register loop starting time. */

    Thread<Monitor> timers_thread; /**< Thread for checking timers. */
    bool timers_stop;              /**< Flag to indicate timers thread to stop. */

    Iterable<Event> event_list; /**< List of traffic events. */
    Statistics statistics;      /**< Internal statistics. */
};

/*************************************************************************************************/

} /* namespace TrafficFlow */
} /* namespace L2T */

#endif /* L2T_TEST_DATA_LOSS_H */
