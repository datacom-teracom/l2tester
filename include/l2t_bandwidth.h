/*************************************************************************************************/
/**
 * \file
 * \brief Define tools for bandwidth tests.
 *        Configuring bandwidth tests by parameters would be complex and ineffective.
 *        Instead, this file provide core tools to implement elaborated bandwidth tests using
 *        one of the scripting languages.
 */
/*************************************************************************************************/

#ifndef L2T_BANDWIDTH_H
#define L2T_BANDWIDTH_H

#include "l2t_interface.h"
#include "l2t_thread.h"
#include "l2t_iterable.h"
#include "l2t_sniffer.h"

#include <vector>

namespace L2T {
namespace Bandwidth {

/*************************************************************************************************/

/**
 * \brief Represent a single measure of instantaneous bandwidth.
 */
struct Measure {
    /**
     * \brief Construct new Measure.
     * \param _timestamp_ms                Time in ms since test started.
     * \param _bits_per_sec                Bandwidth in bits per second.
     * \param _packets_per_sec             Bandwidth in packets per second.
     * \param _counter_bytes               Total of bytes.
     * \param _counter_packets             Total of packets.
     * \param _cumulative_counter_bytes    Number of bytes since Sniffer started.
     * \param _cumulative_counter_packets  Number of packets since Sniffer started.
     */
    Measure(uint64_t _timestamp_ms, uint32_t _bits_per_sec, uint32_t _packets_per_sec,
            uint64_t _counter_bytes, uint64_t _counter_packets, uint64_t _cumulative_counter_bytes,
            uint64_t _cumulative_counter_packets)
        : timestamp_ms(_timestamp_ms),
          bits_per_sec(_bits_per_sec),
          packets_per_sec(_packets_per_sec),
          counter_bytes(_counter_bytes),
          counter_packets(_counter_packets),
          cumulative_counter_bytes(_cumulative_counter_bytes),
          cumulative_counter_packets(_cumulative_counter_packets)
    {
    }

    uint64_t timestamp_ms;               /**< Timestamp in ms since Sniffer started. */
    uint32_t bits_per_sec;               /**< Bandwidth in bps (bits per second). */
    uint32_t packets_per_sec;            /**< Bandwidth in pps (packets per second). */
    uint64_t counter_bytes;              /**< Number of bytes for current analysis. */
    uint64_t counter_packets;            /**< Number of packets for current analysis. */
    uint64_t cumulative_counter_bytes;   /**< Number of bytes since Sniffer started. */
    uint64_t cumulative_counter_packets; /**< Number of packets since Sniffer started. */
};

/*************************************************************************************************/

/**
 * \brief Class representing a stream of monitored packets.
 */
class Stream {
   public:
    friend class Monitor;

    /**
     * \brief Construct new Stream.
     * \param _filter             Filter that define this Stream. No filter means 'all packets'.
     */
    explicit Stream(L2T::Filter *_filter = NULL);

    /**
     * \brief Destroy Stream. All stored Measures are also deleted.
     */
    ~Stream();

    /**
     * \brief Get the last measure for this stream.
     * \return Return a pointer to last measure.
     */
    const Measure *last_reading();

    /**
     * \brief Iterate through stored readings.
     * \param _start         ID of reading to start iteration.
     *                          0 : to read next unread reading.
     *                          1 : start from oldest stored reading.
     *                         -1 : start from next incoming reading.
     * \param _block         If True, block until there's a new reading available.
     * \param _timeout_ms    Timeout in milliseconds if blocking operation. Zero to wait forever
     * (default).
     * \return Return a pointer to next measure. NULL if last one and not blocking or blocking and
     * timed out.
     */
    const Measure *iterate_reading(int _start = 0, bool _block = true, uint32_t _timeout_ms = 0);

   private:
    /**
     * \brief Process packet. If it matches this stream, bytes and packets counters are incremented.
     * \param _packet        Packet to be processed.
     *                       The first 2 bytes are the socket file descriptor of the received
     * interface.
     * \param _size          Size of the packet, without the 2 extra bytes.
     */
    void count_packet(void *_packet, int _size);

    /**
     * \brief Calculate instantaneous bandwidth and reset internal counters.
     * \param _timestamp_ms  Timestamp in ms since last measurement.
     */
    void measure_bandwidth(const uint64_t &_timestamp_ms);

    /**
     * \brief Clear packets and byte counters, remove all Measures.
     * \param _timestamp_ms  Current timestamp in ms based on CLOCK_MONOTONIC.
     */
    void reset(const uint64_t &_timestamp_ms);

    Filter *filter; /**< Filter associated with this Stream. */

    uint64_t counter_bytes;              /**< Number of bytes for current analysis. */
    uint64_t counter_packets;            /**< Number of packets for current analysis. */
    uint64_t cumulative_counter_bytes;   /**< Number of bytes since Sniffer started. */
    uint64_t cumulative_counter_packets; /**< Number of packets since Sniffer started. */
    pthread_mutex_t counter_mutex;       /**< Used to lock counters access. */

    uint64_t timestamp_ms;          /**< Timestamp in ms of last measurement. */
    Iterable<Measure> measure_list; /**< List of instantaneous bandwidth measures. */
};

/*************************************************************************************************/

/**
 * \brief Monitor multiples interfaces and measure incoming bandwidth.
 */
class Monitor : protected L2T::Sniffer {
   public:
    /**
     * \brief Construct new Monitor for bandwidth measurement.
     * \param _interfaces             List of interfaces to be monitored.
     * \param _measure_interval_ms    Interval in ms between each measurement.
     */
    Monitor(std::vector<std::string> _interfaces,
            uint32_t _measure_interval_ms = 500) throw(L2T::Exception);

    /**
     * \brief Destroy Sniffer freeing all allocated memory.
     */
    ~Monitor();

    /**
     * \brief Add new Stream to the Monitor.
     * \param _filter          Pointer to filter that will be used to create the Stream.
     *                         If NULL, the stream will consider all received packets.
     * \return Reference to created Stream.
     */
    Stream *new_stream(L2T::Filter *_filter = NULL);

    /**
     * \brief Remove the Stream from internal list and delete it.
     * \param _stream          Pointer to the stream that should be deleted.
     */
    void delete_stream(Stream *_stream);

    /**
     * \brief Start receive and measure threads.
     */
    void start() throw(L2T::Exception);

    /**
     * \brief Stop all threads.
     */
    void stop() throw(L2T::Exception);

    /**
     * \brief At each measure_interval verify streams counters to determine instantaneous bandwidth.
     */
    void measure_loop() throw();

   private:
    /**
     * \brief Called for each received packet.
     * \param _iface         Interface index that received the packet.
     * \param _filter        Filter index that matched the packet.
     * \param _packet        Packet data.
     * \param _size          Packet size.
     * \return Return true if packet process was successful, false otherwise.
     */
    virtual bool received_packet(uint32_t _iface, uint32_t _filter, void *_packet,
                                 size_t _size) throw();

    std::vector<Stream *> stream_list; /**< Vector of monitored streams. */
    pthread_mutex_t stream_mutex;      /**< Mutex to protected stream list. */

    Thread<Monitor> measure_thread; /**< Thread for measuring instantaneous bandwidth. */
    bool measure_stop;              /**< Flag to stop measuring process. */
    uint32_t measure_interval_ms;   /**< Interval in ms between each measurement. */
    uint64_t timestamp_ms;          /**< Timestamp in ms since measurement started. */
};

/*************************************************************************************************/

} /* namespace Bandwidth */
} /* namespace L2T */

#endif /* L2T_BANDWIDTH_H */
