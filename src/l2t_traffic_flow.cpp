/*************************************************************************************************/
/**
 * \file
 * \brief Implement tools for monitoring a data path using a specific traffic flow.
 */
/*************************************************************************************************/

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <algorithm>

extern "C" {
#include <time.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <endian.h>
#include <errno.h>
}

#include "l2t_logger.h"
#include "l2t_traffic_flow.h"

namespace L2T {
namespace TrafficFlow {

/**************************************************************************************************
 ** L2T::TrafficFlow::Event **
 **************************************************************************************************/

const std::string Event::type_to_str(Type _type)
{
    switch (_type) {
        case Event::TEST_STARTED:
            return std::string("TEST STARTED");
        case Event::TEST_FINISHED:
            return std::string("TEST FINISHED");
        case Event::TRAFFIC_STARTED:
            return std::string("TRAFFIC STARTED");
        case Event::TRAFFIC_STOPPED:
            return std::string("TRAFFIC STOPPED");
        case Event::LOOP_STARTED:
            return std::string("LOOP STARTED");
        case Event::LOOP_STOPPED:
            return std::string("LOOP STOPPED");
        case Event::ERROR_DETECTED:
            return std::string("ERROR DETECTED");
        default:
            return std::string("UNKNOWN Event::Type");
    }
}

/**************************************************************************************************
 ** L2T::TrafficFlow::Monitor **
 **************************************************************************************************/

Monitor::Monitor(const std::string &_src, const std::string &_dst, void *_packet, size_t _size,
                 uint32_t _packet_interval_ms, Action *_action,
                 Filter *_filter) throw(L2T::Exception)
    : Sniffer((this->max_delayed_packets + 2) * _packet_interval_ms),
      Sender(_src, _packet, _size),
      packet_seq_tx(0),
      packet_seq_rx(0),
      packet_interval_ms(_packet_interval_ms),
      traffic_started_enabled(false),
      traffic_started_timer(),
      loop_detected_enabled(false),
      loop_detected_timer(),
      loop_started_timer(),
      timers_thread(this, &Monitor::timers_loop),
      timers_stop(true),
      event_list()
{
    if (_action != NULL && _action->range_first != _action->range_last &&
        static_cast<int64_t>(_action->range_last - _action->range_first) <
            this->max_delayed_packets) {
        throw Exception(L2T_ERROR_INVALID_CONFIG, "Action with range too small.");
    }

    if (!_action) { /* Use default action. */
        Action *default_action = new Action();
        this->set_action(default_action);
        delete default_action; /* Action was copied internally. */
    } else {                   /* Use user defined action. */
        this->set_action(_action);
    }

    this->add_filter(_filter);

    std::vector<std::string> ifaces;
    ifaces.push_back(_src);
    ifaces.push_back(_dst);

    this->add_interfaces(ifaces);
    this->manual_bandwidth(1, _packet_interval_ms * 1000000LL);

    ::memset(&this->packet_id_list, 0, sizeof(packet_id_list));
    ::pthread_mutex_init(&this->packet_mutex, NULL);
}

/*************************************************************************************************/

Monitor::~Monitor()
{
    this->stop();
}

/*************************************************************************************************/

void Monitor::run(uint64_t _num_packets, uint32_t _timeout_ms) throw(L2T::Exception)
{
    this->test_started_event();
    Sniffer::start();
    Sender::run(_num_packets, _timeout_ms);
    Sniffer::stop();
    this->test_finished_event();
}

/*************************************************************************************************/

void Monitor::start() throw(L2T::Exception)
{
    this->test_started_event();

    Sniffer::start();
    Sender::start();
}

/*************************************************************************************************/

void Monitor::stop() throw(L2T::Exception)
{
    Sender::stop();
    Sniffer::stop();

    this->test_finished_event();
}

/*************************************************************************************************/

const Event *Monitor::iterate_event(int _start, bool _block, uint32_t _timeout_ms)
{
    return this->event_list.iterate(_start, _block, _timeout_ms);
}

/*************************************************************************************************/

void Monitor::get_statistics(Statistics *_stats)
{
    if (_stats == NULL) {
        L2T_ERROR << "Invalid Statistics passed to get_statistics.";
        throw Exception(L2T_ERROR_INVALID_CONFIG, "NULL Statistics pointer.");
    }

    ::memcpy(_stats, &this->statistics, sizeof(Statistics));
}

/*************************************************************************************************/

bool Monitor::received_packet(uint32_t _iface, uint32_t _filter, void *_packet,
                              size_t _size) throw()
{
    if (_iface == 0 || this->loop_detected_enabled) {
        this->loop_detected_event();
        return true;
    }

    ScopedLock lock(&this->packet_mutex);
    try {
        return verify_received_packet(_packet, _size);
    }
    catch (L2T::Exception &e) {
        /* This won't happen in normal operation. This exception will only be raised if a foreign
         * packet
         * arrives in the middle of the test. If this might occur, please use an adequate filter to
         * isolate testing traffic from other flows. */
        L2T_ERROR << e.what() << " Proper filters where configured?";
        this->event_list.push_back(
            new Event(this->packet_seq_rx * this->packet_interval_ms, Event::ERROR_DETECTED));
        this->statistics.error_detected = true;

        /* Stop sender thread. */
        this->send_stop = true;
        this->send_thread.join();

        /* Request receive thread to be stopped. */
        this->receive_stop = true;

        /* This is the only exit that may return false, forcing the receive_loop
         * thread to finish. */
        this->test_finished_event();
        return false;
    }

    return true;
}

/*************************************************************************************************/

bool Monitor::should_send_packet() throw()
{
    ScopedLock lock(&this->packet_mutex);

    /* Stop sending packets during loop. */
    if (!this->loop_detected_enabled) {
        this->packet_id_list[this->packet_seq_tx % 16] = this->action->last_id();
        this->packet_seq_tx++;
        this->statistics.sent_packets++;
        return true;
    } else {
        this->packet_seq_tx++;
        return false;
    }
}

/*************************************************************************************************/

void Monitor::test_started_event()
{
    /* Clean up previous states. */
    this->event_list.clear();
    this->event_list.push_back(new Event(0, Event::TEST_STARTED));
    this->traffic_started_enabled = false;
    this->traffic_started_timer.update();
    this->loop_detected_enabled = false;
    this->loop_detected_timer.update();
    this->loop_started_timer.update();

    ::memset(&this->statistics, 0, sizeof(Statistics));

    this->timers_stop = false;
    this->timers_thread.start();
}

/*************************************************************************************************/

void Monitor::test_finished_event()
{
    if (!this->timers_stop) {
        /* When finished, if we left in disrupted state, update statistics. */
        if (this->packet_seq_rx < this->packet_seq_tx || this->statistics.error_detected) {
            this->statistics.traffic_interruption_intervals++;
            this->statistics.traffic_interruption_ms += this->traffic_started_timer.elapsed_ms();
        }
        if (this->loop_detected_enabled) {
            this->statistics.loop_detected_intervals++;
            this->statistics.loop_detected_ms += this->loop_started_timer.elapsed_ms();
        }
        this->event_list.push_back(
            new Event(this->packet_seq_tx * this->packet_interval_ms, Event::TEST_FINISHED));
        this->timers_stop = true;
        this->timers_thread.join();
    }
}

/*************************************************************************************************/

void Monitor::traffic_detected_event()
{
    if (!this->traffic_started_enabled) {
        /* Update traffic interruption statistics.
         * Ignore if RX sequence is zero (we didn't lost any packets). */
        if (this->packet_seq_rx > 0) {
            this->statistics.traffic_interruption_intervals++;
            this->statistics.traffic_interruption_ms += this->traffic_started_timer.elapsed_ms();
        }

        this->event_list.push_back(
            new Event(this->packet_seq_rx * this->packet_interval_ms, Event::TRAFFIC_STARTED));
        this->traffic_started_enabled = true;
    }

    this->traffic_started_timer.update();
    this->statistics.received_packets++;
    this->packet_seq_rx++;
}

/*************************************************************************************************/

void Monitor::traffic_stopped_event()
{
    this->event_list.push_back(
        new Event(this->packet_seq_rx * this->packet_interval_ms, Event::TRAFFIC_STOPPED));
    this->traffic_started_enabled = false;
}

/*************************************************************************************************/

void Monitor::loop_detected_event()
{
    if (!this->loop_detected_enabled) {
        this->loop_started_timer.update();
        this->event_list.push_back(
            new Event(this->packet_seq_tx * this->packet_interval_ms, Event::LOOP_STARTED));
    }
    this->loop_detected_timer.update();
    this->loop_detected_enabled = true;
    this->statistics.dropped_packets++;
}

/*************************************************************************************************/

void Monitor::loop_stopped_event()
{
    /* Update loop statistics. */
    this->statistics.loop_detected_intervals++;
    this->statistics.loop_detected_ms += this->loop_started_timer.elapsed_ms();

    this->event_list.push_back(
        new Event(this->packet_seq_tx * this->packet_interval_ms, Event::LOOP_STOPPED));
    this->loop_detected_enabled = false;
    this->packet_seq_rx = this->packet_seq_tx;
}

/*************************************************************************************************/

void Monitor::timers_loop()
{
    Timer waker;

    while (!this->timers_stop) {

        /* Only check timers each packet_interval_ms */
        waker.sleep_ms(this->packet_interval_ms);

        /* Treat loop timer.
         * The interval to consider a loop has ended does not depend on the packet interval, as
         * during
         * the loop condition we stop sending frames. Instead, we use a fixed amount of time during
         * which we can't receive any packets for this flow. This interval will limit the smaller
         * loop
         * interval we can measure.
         * Empirically, we determined 50 ms are enough to avoid synchronization issues between this
         * and
         * receiving thread, which could led to false loop ends.
         */
        if (this->loop_detected_enabled && this->loop_detected_timer.elapsed_ms() > 50) {
            this->loop_stopped_event();
        }

        /* Treat traffic timer. */
        if (this->traffic_started_enabled &&
            this->traffic_started_timer.elapsed_ms() >
                this->packet_interval_ms * this->max_delayed_packets) {
            this->traffic_stopped_event();
        }
    }
}

/*************************************************************************************************/

bool Monitor::verify_received_packet(void *_packet, size_t _size) throw()
{
    uint64_t received = this->action->extract_id(_packet, _size);

    if (this->traffic_started_enabled) {
        /* Received packet matches the expected one! */
        if (this->packet_id_list[this->packet_seq_rx % this->max_delayed_packets] == received) {
            /* Will only update internal timer and counters */
            this->traffic_detected_event();
            return true;
        }
        /* Traffic interrupted. Update event list. */
        else {
            this->traffic_stopped_event();
        }
    }

    /* As we only keep track of the last [max_delayed_packets], update RX sequence if needed. */
    if (static_cast<int64_t>(this->packet_seq_rx) <
        static_cast<int64_t>(this->packet_seq_tx - this->max_delayed_packets)) {
        this->packet_seq_rx = this->packet_seq_tx - this->max_delayed_packets;
    }

    /* Search newer sent packets. We may have missed some packets. */
    while ((this->packet_seq_rx <= this->packet_seq_tx) &&
           (this->packet_id_list[this->packet_seq_rx % this->max_delayed_packets] != received)) {
        this->packet_seq_rx++;
    }

    /* Received a packet that wasn't expected. */
    if (this->packet_seq_rx > this->packet_seq_tx) {
        /* Search if packet was already consumed. If this is the case, we are in loop. */
        for (int i = 0; i < this->max_delayed_packets; i++) {
            if (this->packet_id_list[i] == received) {
                this->loop_detected_event();
                return true;
            }
        }
        throw Exception(L2T_ERROR_NOT_FOUND, "Received a packet that was not sent.");
    }
    /* Found packet in sent list! */
    else {
        this->traffic_detected_event();
    }

    return true;
}

/*************************************************************************************************/

} /* namespace TrafficFlow */
} /* namespace L2T */
