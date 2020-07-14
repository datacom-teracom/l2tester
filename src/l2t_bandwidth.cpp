/*************************************************************************************************/
/**
 * \file
 * \brief Implement tools for bandwidth tests.
 */
/*************************************************************************************************/

#include "l2t_bandwidth.h"
#include "l2t_logger.h"
#include "l2t_timer.h"

#include <cstring>
#include <cstdlib>
#include <algorithm>

namespace L2T {
namespace Bandwidth {

/**************************************************************************************************
 ** L2T::Bandwidth::Stream **
 **************************************************************************************************/

Stream::Stream(L2T::Filter *_filter)
    : filter(_filter),
      counter_bytes(0ULL),
      counter_packets(0ULL),
      cumulative_counter_bytes(0ULL),
      cumulative_counter_packets(0ULL),
      timestamp_ms(0ULL),
      measure_list()
{
    L2T_INFO << "Creating new Stream";
    ::pthread_mutex_init(&this->counter_mutex, NULL);
}

/*************************************************************************************************/

Stream::~Stream()
{
    L2T_DEBUG << "Deleting Stream.";
}

/*************************************************************************************************/

const Measure *Stream::last_reading()
{
    return this->measure_list.back();
}

/*************************************************************************************************/

const Measure *Stream::iterate_reading(int _start, bool _block, uint32_t _timeout_ms)
{
    return this->measure_list.iterate(_start, _block, _timeout_ms);
}

/*************************************************************************************************/

void Stream::count_packet(void *_packet, int _size)
{
    ::pthread_mutex_lock(&this->counter_mutex);
    this->counter_packets++;
    this->counter_bytes += _size;
    this->cumulative_counter_packets++;
    this->cumulative_counter_bytes += _size;
    ::pthread_mutex_unlock(&this->counter_mutex);
}

/*************************************************************************************************/

void Stream::measure_bandwidth(const uint64_t &_timestamp_ms)
{
    /* Read counters and reset then! */
    ::pthread_mutex_lock(&this->counter_mutex);
    uint64_t copy_counter_bytes = this->counter_bytes;
    uint64_t copy_counter_packets = this->counter_packets;
    uint64_t copy_cumulative_counter_bytes = this->cumulative_counter_bytes;
    uint64_t copy_cumulative_counter_packets = this->cumulative_counter_packets;
    uint32_t interval_ms = _timestamp_ms - this->timestamp_ms;
    this->counter_bytes = 0;
    this->counter_packets = 0;
    this->timestamp_ms = _timestamp_ms;
    ::pthread_mutex_unlock(&this->counter_mutex);

    /* Do not account measures for intervals smaller than 10ms. */
    if (interval_ms < 10) {
        return;
    }

    /* Calculate actual bandwidth. */
    uint64_t total_bits = (copy_counter_bytes + copy_counter_packets * 4LL) * 8LL;
    uint32_t bits_per_sec = (total_bits * 1000LL) / interval_ms;
    uint64_t packets_per_sec = (copy_counter_packets * 1000) / interval_ms;

    /* Update measure list. */
    this->measure_list.push_back(new Measure(
        _timestamp_ms, bits_per_sec, packets_per_sec, copy_counter_bytes, copy_counter_packets,
        copy_cumulative_counter_bytes, copy_cumulative_counter_packets));
}

/*************************************************************************************************/

void Stream::reset(const uint64_t &_timestamp_ms)
{
    ::pthread_mutex_lock(&this->counter_mutex);
    this->counter_bytes = 0;
    this->counter_packets = 0;
    this->cumulative_counter_bytes = 0;
    this->cumulative_counter_packets = 0;
    this->timestamp_ms = _timestamp_ms;
    ::pthread_mutex_unlock(&this->counter_mutex);

    this->measure_list.clear();
}

/**************************************************************************************************
 ** L2T::Bandwidth::Receiver **
 **************************************************************************************************/

Monitor::Monitor(std::vector<std::string> _interfaces,
                 uint32_t _measure_interval_ms) throw(L2T::Exception)
    : L2T::Sniffer(_measure_interval_ms + 2000),
      measure_thread(this, &Monitor::measure_loop),
      measure_stop(true),
      measure_interval_ms(_measure_interval_ms),
      timestamp_ms(0ULL)
{
    L2T_INFO << "Creating new Bandwidth::Monitor.";

    if (_interfaces.empty()) {
        throw Exception(L2T_ERROR_INVALID_CONFIG, "Must specify at least one interface.");
    }

    this->add_interfaces(_interfaces);
    ::pthread_mutex_init(&this->stream_mutex, NULL);
}

/*************************************************************************************************/

Monitor::~Monitor()
{
    L2T_DEBUG << "Deleting Bandwidth::Monitor.";

    /* Stop sniffer before deleting it! */
    this->stop();

    while (!this->stream_list.empty()) {
        delete this->stream_list.back();
        this->stream_list.pop_back();
    }
}

/*************************************************************************************************/

Stream *Monitor::new_stream(L2T::Filter *_filter)
{
    L2T_DEBUG << "Add new Stream to Bandwidth::Monitor.";

    ScopedLock lock(&this->stream_mutex);

    /* Add filter and associate with a new Stream. */
    L2T::Filter *filter = this->add_filter(_filter);
    Stream *new_stream = new Stream(filter);
    new_stream->reset(this->timestamp_ms);

    this->stream_list.push_back(new_stream);

    return new_stream;
}

/*************************************************************************************************/

void Monitor::delete_stream(Stream *_stream)
{
    if (_stream == NULL) {
        L2T_ERROR << "Invalid Stream passed to delete_stream.";
        throw Exception(L2T_ERROR_INVALID_CONFIG, "NULL Stream pointer.");
    }

    ScopedLock lock(&this->stream_mutex);

    std::vector<Stream *>::iterator it;
    it = std::find(this->stream_list.begin(), this->stream_list.end(), _stream);

    if (it != this->stream_list.end()) {
        this->remove_filter((*it)->filter);
        Stream *stream = *it;
        this->stream_list.erase(it);
        delete stream;
    } else {
        L2T_WARNING << "Couldn't find Stream to delete.";
    }
}

/*************************************************************************************************/

void Monitor::start() throw(L2T::Exception)
{
    /* Start internal Sniffer. */
    this->Sniffer::start();

    if (this->measure_thread.is_running()) {
        L2T_ERROR << "Bandwidth::Monitor is already running. Stop it first.";
        throw Exception(L2T_ERROR_INVALID_OPERATION, "Bandwidth::Monitor already started.");
    }

    this->measure_stop = false;
    this->measure_thread.start();
}

/*************************************************************************************************/

void Monitor::stop() throw(L2T::Exception)
{
    if (!this->measure_stop) {
        this->measure_stop = true;
        this->measure_thread.join();
    }
    this->Sniffer::stop();
}

/*************************************************************************************************/

void Monitor::measure_loop() throw()
{
    L2T_DEBUG << "Starting measure loop.";

    Timer waker;

    try {
        ScopedLock lock(&this->stream_mutex);
        /* Reset all streams information before starting over! */
        for (uint32_t stream = 0; stream < this->stream_list.size(); stream++) {
            this->stream_list[stream]->reset(0ULL);
        }
        this->timestamp_ms = 0ULL;
    }
    catch (...) {
        L2T_ERROR << "Measure Loop initialization failed.";
        return;
    }

    while (!this->measure_stop) {
        this->timestamp_ms = waker.elapsed_ms(true);

        ::pthread_mutex_lock(&this->stream_mutex);
        int num_streams = this->stream_list.size();
        for (int id = 0; id < num_streams; id++) {
            this->stream_list[id]->measure_bandwidth(this->timestamp_ms);
        }
        ::pthread_mutex_unlock(&this->stream_mutex);

        /* Wait for next measurement event */
        waker.sleep_ms(this->measure_interval_ms);
    }

    L2T_DEBUG << "Measure loop finished.";
}

/*************************************************************************************************/

bool Monitor::received_packet(uint32_t _iface, uint32_t _filter, void *_packet,
                              size_t _size) throw()
{
    ::pthread_mutex_lock(&this->stream_mutex);
    this->stream_list[_filter]->count_packet(_packet, _size);
    ::pthread_mutex_unlock(&this->stream_mutex);
    return true;
}

/*************************************************************************************************/

} /* namespace Bandwidth */
} /* namespace L2T */
