/*************************************************************************************************/
/**
 * \file
 * \brief Implement class for periodically sending packets.
 */
/*************************************************************************************************/

#include <cstdlib>
#include <cstring>

#include "l2t_sender.h"
#include "l2t_logger.h"
#include "l2t_scoped_lock.h"
#include "l2t_timer.h"

namespace L2T {

/**************************************************************************************************
 ** L2T::Action **
 **************************************************************************************************/

Action::Action()
    : byte(ETH_HLEN)  // .
      ,
      mask(0xFFFFFFFF00000000ULL)  // | Action: Increment four bytes after the ethertype.
      ,
      type(ACTION_INCREMENT)  // '
      ,
      seed(0),
      range_first(0),
      range_last(0),
      copied(false),
      custom_range(0x0ULL),
      packet_data(NULL),
      packet_pointer(NULL),
      step(0x0ULL),
      current(0x0ULL),
      inverse_mask_be(0x0ULL),
      current_be(0x0ULL),
      chained_unconditional(NULL),
      chained_periodically(NULL),
      chained_period(0),
      apply_counter(0),
      gen()
{
    L2T_INFO << "Creating default Action.";
}

/*************************************************************************************************/

Action::Action(const Action& _other)
    : byte(_other.byte),
      mask(_other.mask),
      type(_other.type),
      seed(_other.seed),
      range_first(_other.range_first),
      range_last(_other.range_last),
      copied(true),
      custom_range(_other.custom_range),
      packet_data(_other.packet_data),
      packet_pointer(_other.packet_pointer),
      step(_other.step),
      current(_other.current),
      inverse_mask_be(_other.inverse_mask_be),
      current_be(_other.current_be),
      chained_unconditional(NULL),
      chained_periodically(NULL),
      chained_period(_other.chained_period),
      apply_counter(_other.apply_counter),
      gen()
{
    L2T_INFO << "Creating Action by copy.";

    /* Recursively copy chained actions. */
    if (_other.chained_periodically) {
        this->chained_periodically = new Action(*_other.chained_periodically);
    }
    if (_other.chained_unconditional) {
        this->chained_unconditional = new Action(*_other.chained_unconditional);
    }
}

/*************************************************************************************************/

Action::~Action()
{
    L2T_DEBUG << "Deleting Action.";

    /* Only delete chained actions if this instance was created by copy. */
    if (this->copied) {
        /* Recursively delete chained actions. */
        if (this->chained_unconditional) {
            delete this->chained_unconditional;
        }
        if (this->chained_periodically) {
            delete this->chained_periodically;
        }
    }
}

/*************************************************************************************************/

void Action::chain_action(Action* _another, ChainMode _mode, uint32_t _period) throw(L2T::Exception)
{
    switch (_mode) {
        case ACTION_CHAIN_UNCONDITIONAL: {
            this->chained_unconditional = _another;
            break;
        }
        case ACTION_CHAIN_PERIODICALLY: {
            this->chained_periodically = _another;
            this->chained_period = _period;
            break;
        }
        case ACTION_CHAIN_WHEN_FINISHED: {
            this->chained_periodically = _another;
            this->chained_period = 0; /* Will be determined during Action compilation. */
            break;
        }
    }
}

/*************************************************************************************************/

void Action::apply()
{
    if (this->packet_data == NULL) {
        return;
    }

    /* Updated current ID. */
    switch (this->type) {
        case Action::ACTION_INCREMENT: {
            this->current = this->mask & (this->current + this->step);
            if (this->custom_range && (this->current > this->range_last * this->step
                                       || this->current < this->range_first * this->step)) {
                this->current = this->range_first * this->step;
            }
            break;
        }
        case Action::ACTION_DECREMENT: {
            this->current = this->mask & (this->current - this->step);
            if (this->custom_range && (this->current > this->range_last * this->step
                                       || this->current < this->range_first * this->step)) {
                this->current = this->range_last * this->step;
            }
            break;
        }
        case Action::ACTION_RANDOMIZE: {
            std::uniform_int_distribution<unsigned long long> dis;
            this->current = dis(this->gen);
            this->current &= this->mask;
            if (this->custom_range) {
                this->current = (this->current % ((this->custom_range) * this->step))
                                + this->range_first * this->step;
            }
            break;
        }
        case Action::ACTION_IPV4_CHECKSUM: {
            uint64_t checksum = 0;
            uint16_t* data = (uint16_t*)this->packet_pointer;
            /* Add bytes from IPv4 header in groups of 16 bits (represented by the letters A through
             *I)
             * except the 16 bits from the checksum itself.
             *
             * 0     4     8           16      19             31
             * | Ver | IHL |    TOS    |    Total Length      |
             * |           A           |          B           |
             * ------------------------------------------------
             * |     Identification    | Flags | Frag. Offset |
             * |           C           |          D           |
             * ------------------------------------------------
             * |    TTL    |  Protocol |   Header Checksum    |
             * |           E           |     <NOT ADDED>      |
             * ------------------------------------------------
             * |                  Source IP                   |
             * |           F           |           G          |
             * ------------------------------------------------
             * |                Destination IP                |
             * |           H           |           I          |
             */
            for (uint32_t pos = this->byte / 2 - 5; pos < this->byte / 2; pos++) {
                /* Add 16 bits A -> E */
                checksum += data[pos];
            }
            for (uint32_t pos = this->byte / 2 + 1; pos < this->byte / 2 + 5; pos++) {
                /* Add 16 bits F -> I */
                checksum += data[pos];
            }
            /* Add the upper 16 bits (considered as carry) to the lower 16 bits and inverse result.
             * Change to bit-endian and shift 48 bits to create valid [current]. It replace old
             * checksum
             * update_packet method is called. */
            this->current
                = (uint64_t)(htobe16(~((((checksum & 0xFFFF0000) >> 16) + checksum) & 0xFFFF)))
                  << 48;
            break;
        }
    }

    this->update_packet();

    /* First execute conditional chained Action. */
    if (this->chained_periodically && !(this->apply_counter % this->chained_period)) {
        this->chained_periodically->apply();
    }

    /* Execute unconditional chained Action. */
    if (this->chained_unconditional) {
        this->chained_unconditional->apply();
    }

    /* Increment apply counter! */
    this->apply_counter++;
}

/*************************************************************************************************/

static std::ostream& operator<<(std::ostream& _out, const Action::Type& _type)
{
    switch (_type) {
        case Action::ACTION_RANDOMIZE:
            _out << "RANDOMIZE";
            break;
        case Action::ACTION_INCREMENT:
            _out << "INCREMENT";
            break;
        case Action::ACTION_DECREMENT:
            _out << "DECREMENT";
            break;
        case Action::ACTION_IPV4_CHECKSUM:
            _out << "IPv4 CHECKSUM";
            break;
        default:
            _out << "<Invalid Action::Type>";
            break;
    }
    return _out;
}

/*************************************************************************************************/

void Action::compile(void* _packet, size_t _size,
                     const std::string& _indentation) throw(L2T::Exception)
{
    L2T_DEBUG << _indentation << "Compiling Action:";

    /* Validate parameters */
    validate(_packet, _size);

    this->current = 0;

    uint64_t max_range = getActionMaskMaxRange();

    L2T_DEBUG << _indentation << "  => Type   : " << this->type;
    L2T_DEBUG << _indentation << "  => Byte   : " << this->byte;
    L2T_DEBUG << _indentation << "  => Mask   : 0x" << std::hex << std::setfill('0')
              << std::setw(16) << this->mask;
    L2T_DEBUG << _indentation << "  => Step   : 0x" << std::hex << std::setfill('0')
              << std::setw(16) << this->step;
    if (this->type == ACTION_RANDOMIZE) {
        L2T_DEBUG << _indentation << "  => Seed   : " << this->seed;
    }

    if (this->custom_range) {
        if (this->range_last > max_range) {
            throw Exception(L2T_ERROR_INVALID_CONFIG,
                            "Defined range doesn't fit in supplied mask.");
        }
        /* For increment, let current be last. When first applied, current will become first. */
        if (this->type == ACTION_INCREMENT) {
            this->current = this->range_last * this->step;
        }
        /* For decrement, same logic but inverted. */
        else if (this->type == ACTION_DECREMENT) {
            this->current = this->range_first * this->step;
        }
        L2T_DEBUG << _indentation << "  => Range  : " << this->range_first << " - "
                  << this->range_last;
    } else {
        L2T_DEBUG << _indentation << "  => Range  : 0 - " << max_range;
    }

    this->packet_pointer = _packet;
    this->packet_data = (uint64_t*)((uint8_t*)_packet + this->byte);
    this->inverse_mask_be = htobe64(~this->mask);

    /* Compile chained actions. */
    if (this->chained_periodically) {
        if (!this->chained_period) {
            /* Was created using ACTION_CHAIN_WHEN_FINISHED. */
            this->chained_period = this->custom_range > 0 ? this->custom_range : max_range;
        }
        L2T_DEBUG << _indentation << "  * Chained Periodically (period " << this->chained_period
                  << ")";
        this->chained_periodically->compile(_packet, _size, _indentation + "  ");
    }
    if (this->chained_unconditional) {
        L2T_DEBUG << _indentation << "  * Chained Unconditional";
        this->chained_unconditional->compile(_packet, _size, _indentation + "  ");
    }

    this->apply_counter = 0;
    this->update_packet();
    this->gen.seed(this->seed);
}

void Action::validate(void* _packet, size_t _size) throw(L2T::Exception)
{
    if (this->type == ACTION_IPV4_CHECKSUM) {
        if (this->byte < ETH_HLEN + 10 /* IPv4 minimum header length */) {
            throw Exception(L2T_ERROR_INVALID_CONFIG, "Invalid position for IPv4 header checksum.");
        }
        this->mask = 0xFFFF000000000000ULL;
    }

    if (this->mask == 0LL) {
        throw Exception(L2T_ERROR_INVALID_CONFIG, "Cannot use empty action mask.");
    }

    if (_packet == NULL) {
        throw Exception(L2T_ERROR_INVALID_CONFIG, "NULL packet.");
    }

    if (this->byte + sizeof(uint64_t) >= _size) {
        throw Exception(L2T_ERROR_INVALID_CONFIG, "Action byte must be within packet size.");
    }

    if (this->range_first != this->range_last) {
        if (this->range_first > this->range_last) {
            throw Exception(L2T_ERROR_INVALID_CONFIG,
                            "When using ranges, first value must be smaller than last.");
        }
        this->custom_range = this->range_last - this->range_first + 1;
    }
}

uint64_t Action::getActionMaskMaxRange() throw(L2T::Exception)
{
    bool mask_ended = false;
    uint8_t bit, first_non_zeroed_bit, mask_last_bit = 64;

    /* Find least significant bit that is not zero! */
    for (bit = 0; bit < sizeof(uint64_t) * 8; bit++) {
        if (this->mask & (1ULL << bit)) {
            break;
        }
    }

    /* The step is the first non-zeroed bit. */
    first_non_zeroed_bit = bit;
    this->step = 1ULL << first_non_zeroed_bit;
    bit++;

    /* If action is DECREMENT or INCREMENT, the action mask can't have holes. */
    if (this->type == Action::ACTION_DECREMENT || this->type == Action::ACTION_INCREMENT) {
        /* Find end of mask. After that, all remaining bits must be zeros. */
        for (; bit < sizeof(uint64_t) * 8; bit++) {
            if (!(this->mask & (1ULL << bit))) {
                if (!mask_ended) {
                    mask_last_bit = bit;
                }
                mask_ended = true;
            } else if (mask_ended) {
                throw Exception(L2T_ERROR_INVALID_CONFIG,
                                "For actions increment or decrement, mask cannot have holes.");
            }
        }
    }

    /* Calculate maximum range allowed by mask definition. */
    uint64_t max_range = 0xFFFFFFFFFFFFFFFFULL;
    if (mask_last_bit - first_non_zeroed_bit < 64) {
        max_range = (1ULL << (mask_last_bit - first_non_zeroed_bit)) - 1;
    }

    return max_range;
}

/**************************************************************************************************
 ** L2T::Sender **
 **************************************************************************************************/

Sender::Sender(const std::string& _interface, void* _packet, size_t _size) throw(L2T::Exception)
    : iface_name(_interface),
      packet_data(NULL),
      packet_size(_size),
      bandwidth(0),
      burst(0),
      sending_interval_ns(0x0ULL),
      action(NULL),
      send_stop(true),
      packets_sent(0x0ULL),
      send_max_packets(0x0ULL),
      send_timeout_ms(0x0ULL),
      send_thread(this, &Sender::send_loop)
{
    L2T_INFO << "Creating Sender for interface " << _interface << ", with packet size of " << _size
             << ".";

    if (this->packet_size < ETH_ZLEN || _packet == NULL) {
        throw Exception(L2T_ERROR_INVALID_CONFIG, "Invalid or too small packet.");
    }

    ::pthread_mutex_init(&this->bandwidth_mutex, NULL);
    ::pthread_mutex_init(&this->action_mutex, NULL);

    this->packet_data = ::malloc(this->packet_size);
    ::memcpy(this->packet_data, _packet, this->packet_size);
}

/*************************************************************************************************/

Sender::~Sender()
{
    L2T_DEBUG << "Deleting Sender.";

    /* Finish thread before destroying this TxStream. */
    this->stop();

    if (this->packet_data) {
        ::free(this->packet_data);
        this->packet_data = NULL;
    }

    /* Remove associated Action if it exists. */
    if (this->action) {
        delete this->action;
        this->action = NULL;
    }
}

/*************************************************************************************************/

void Sender::auto_bandwidth(uint32_t _bandwidth) throw(L2T::Exception)
{
    L2T_DEBUG << "Configure TxStream for auto bandwidth " << _bandwidth << " bps.";

    if (_bandwidth < 1) {
        throw Exception(L2T_ERROR_INVALID_CONFIG, "Target bandwidth must be greater than zero.");
    }

    ScopedLock lock(&this->bandwidth_mutex);

    this->burst = 0;
    this->sending_interval_ns = 0;

    /* Try to find interval of at least 1ms. */
    while (this->sending_interval_ns < 1000) {
        this->burst++;
        L2T_DEBUG << " - Trying with burst of " << this->burst << " packets.";
        long double packets_per_sec = (_bandwidth / 8.0L) / (this->packet_size + 4.0L);
        this->sending_interval_ns
            = (unsigned long long)(1000000000.0L * (long double)this->burst / packets_per_sec);
        L2T_DEBUG << " - Got interval " << this->sending_interval_ns << ".";
    }
    this->bandwidth = _bandwidth;

    if (this->bandwidth > 100000000LL) {
        L2T_WARNING << "Specified bandwidth is greater than 100 Mbps. Are you sure?";
    }
}

/*************************************************************************************************/

void Sender::manual_bandwidth(uint32_t _burst, uint64_t _interval_ns) throw(L2T::Exception)
{
    L2T_DEBUG << "Configure Sender : burst " << _burst << ", interval " << _interval_ns << " ns";

    if (_interval_ns < 100) {
        throw Exception(L2T_ERROR_INVALID_CONFIG, "Interval must be greater than 100 ns.");
    }
    if (_burst < 0) {
        throw Exception(L2T_ERROR_INVALID_CONFIG, "Burst must be greater than zero.");
    }

    ScopedLock lock(&this->bandwidth_mutex);
    this->burst = _burst;
    this->sending_interval_ns = _interval_ns;
    this->bandwidth = (1000000000.0L / _interval_ns) * _burst * (this->packet_size + 4) * 8;

    L2T_DEBUG << " - Got bandwidth " << this->bandwidth << " bps.";

    if (this->bandwidth > 100000000LL) {
        L2T_WARNING << "Specified bandwidth is greater than 100 Mbps. Are you sure?";
    }
}

/*************************************************************************************************/

void Sender::set_action(Action* _action) throw(L2T::Exception)
{
    ScopedLock lock(&this->action_mutex);

    if (_action == NULL) {
        /* Remove action from Sender. */
        delete this->action;
        this->action = NULL;
    } else {

        /* Make a copy of the action to avoid ownership problems with SWIG.
         * The parameter was probably allocated by SWIG so it can be deallocated any time by it. */

        Action* new_action = _action == NULL ? new Action : new Action(*_action);

        try {
            new_action->compile(this->packet_data, this->packet_size);
            this->action = new_action;
        }
        catch (...) {
            delete new_action;
            throw;
        }
    }
}

/*************************************************************************************************/

void Sender::run(uint64_t _num_packets, uint32_t _timeout_ms) throw(L2T::Exception)
{
    this->check_running_conditions();

    this->send_max_packets = _num_packets;
    this->send_timeout_ms = _timeout_ms;
    this->send_stop = false;

    this->send_loop();

    this->send_max_packets = 0;
    this->send_timeout_ms = 0;
    this->send_stop = true;
}

/*************************************************************************************************/

void Sender::start() throw(L2T::Exception)
{
    this->check_running_conditions();

    this->send_stop = false;
    this->send_thread.start();
}

/*************************************************************************************************/

void Sender::stop() throw(L2T::Exception)
{
    /* Only stop thread if it's currently running. */
    if (!this->send_stop) {
        this->send_stop = true;
        this->send_thread.join();
    }
}

/*************************************************************************************************/

void Sender::send_loop() throw()
{
    L2T_DEBUG << "Starting sending loop.";

    Timer waker;
    Interface interface(this->iface_name);
    this->packets_sent = 0x0ULL;

    while (!this->send_stop && (!this->send_max_packets || this->packets_sent < this->send_max_packets)
           && (!this->send_timeout_ms || waker.elapsed_ms(true) < this->send_timeout_ms)) {
        uint64_t interval_ns;
        uint32_t burst;

        {
            ScopedLock lock(&this->bandwidth_mutex);
            interval_ns = this->sending_interval_ns;
            burst = this->burst;
        }

        /* Send packet. */
        try {
            for (uint32_t n = 0; n < burst; n++) {
                { /* Apply action if defined. */
                    ScopedLock lock(&this->action_mutex);
                    if (this->action) {
                        this->action->apply();
                    }
                }
                if (this->should_send_packet()) {
                    this->packets_sent++;
                    interface.send(this->packet_data, this->packet_size);
                }
            }
        }
        catch (Exception& e) {
            L2T_ERROR << "Error sending packet.";
        }

        /* Wait before sending more packets. */
        waker.sleep_ns(interval_ns);
    }

    L2T_DEBUG << "Sending loop finished.";
}

/*************************************************************************************************/

void Sender::check_running_conditions() throw(L2T::Exception)
{
    if (this->bandwidth == 0) {
        throw Exception(L2T_ERROR_INVALID_OPERATION, "Configure Sender before starting it.");
    }
    if (this->send_thread.is_running()) {
        L2T_ERROR << "Sender is already running. Stop it first.";
        throw Exception(L2T_ERROR_INVALID_OPERATION, "Sender already started.");
    }
}

/*************************************************************************************************/

} /* namespace L2T */
