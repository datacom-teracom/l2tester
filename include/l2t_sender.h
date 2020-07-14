/*************************************************************************************************/
/**
 * \file
 * \brief Define class for periodically sending packets.
 */
/*************************************************************************************************/

#ifndef L2T_SENDER_H
#define L2T_SENDER_H

#include "l2t_interface.h"
#include "l2t_thread.h"

#include <vector>
#include <cstdlib>
#include <random>

extern "C" {
#include <stdint.h>
}

namespace L2T {

/*************************************************************************************************/

/**
 * \brief This class defines an action to be applied over a packet.
 *        The action will be applied in a specific position [byte], based in the desired rule [type]
 *        but masked using a 64bit [mask].
 *        Besides the [mask] parameter, it's also possible to limit the result of the action using
 *        a user defined range. To do so, configure the parameters [range_first] and [range_last].
 *        Note that these extremes will be valid results.
 *
 *        Once all parameters are defined, the action can be associated with a packet using the
 *        compile method. This will validate the action and save a reference to the packet memory.
 *        After that, every time the apply method is called, the action will be performed updating
 *        the associated packet. The action can no longer be applied once the packet memory is
 *        released (there's no mechanism to prevent that).
 *
 *        There's an special action to re-calculate the IPv4 header checksum. This may be useful
 *        if another action modify any field in the IPv4 header. The target byte must point to
 *        the byte where the checksum starts (byte 24 for untagged IPv4 packets).
 *
 *        It's also possible to create complex actions chaining other actions to this one.
 *        Each action can be chained directly with at most another two actions. One using
 *unconditional
 *        mode and another using periodical mode.
 *
 *        For the first mode, every time this action apply is called, the apply for the
 *unconditionally
 *        bounded action is also called. In the second, the apply of the chained action is called
 *every
 *        [period] applies of this actions. For INCREMENT or DECREMENT actions, there's a special
 *mode
 *        called 'when finished' that chain the other action in periodical mode using the total
 *number
 *        of possible IDs of this action as period.
 *
 *        This is a recursive process: if the chained actions are also chained to other actions,
 *        they will be also called and the process stop when an action is not chained.
 *        In this process, always the "conditional" branch is executed first (if the condition was
 *met).
 */
class Action {
   public:
    /**
     * \brief Action to perform to modify packet.
     */
    enum Type {
        ACTION_INCREMENT,
        ACTION_DECREMENT,
        ACTION_RANDOMIZE,
        ACTION_IPV4_CHECKSUM,
    };

    enum ChainMode {
        ACTION_CHAIN_UNCONDITIONAL, /* Always execute chained action after this one. */
        ACTION_CHAIN_PERIODICALLY,  /* Execute chained action after a specified number of applies of
                                       the current action. */
        ACTION_CHAIN_WHEN_FINISHED, /* Execute chained action only when all possible IDs of current
                                       action were applied.
                                       Only valid if action type is INCREMENT or DECREMENT.
                                       NOTE: This is a special case of CHAIN_PERIODICALLY, where the
                                       'period' is automatically
                                       calculated. */
    };

    /**
     * \brief Create new action using default values.
     */
    Action();

    /**
     * \brief Create new action using default values or coping values from another action.
     * \param _other         Reference to another Action to be copied from.
     */
    Action(const Action &_other);

    /**
     * \brief Destroy action and recursively delete chained actions copies.
     */
    ~Action();

    /**
     * \brief Chain another action to this one in order to compose complex actions.
     * \param _another       Extra action that should be chained.
     * \param _mode          When chained action will be executed.
     * \param _period        How many applies of current actions should be done before chained
     * action is executed.
     *                       Only used if mode is ACTION_CHAIN_PERIODICALLY.
     */
    void chain_action(Action *_another, ChainMode _mode = ACTION_CHAIN_UNCONDITIONAL,
                      uint32_t _period = 0) throw(L2T::Exception);

    /**
     * \brief Apply this action over the associated packet.
     * \param _packet        Packet data.
     * \param _size          Packet size.
     */
    void apply();

    /**
     * \brief Validate action and associate with specified packet.
     *        Chained actions are also compiled for the same packet.
     *        This will only save a reference to the packet, so the packet cannot be
     *        deleted or have its size changed afterwards.
     * \param _packet        Packet data.
     * \param _size          Packet size.
     * \param _indentation   String used to indent chained actions logs.
     */
    void compile(void *_packet, size_t _size,
                 const std::string &_indentation = "") throw(L2T::Exception);

    /**
     * \brief Extract action result from foreign packet assuming this action would be applied to it.
     * \param _packet        Packet data.
     * \param _size          Packet size.
     * \return Result as if this action was executed over this packet.
     */
    inline uint64_t extract_id(void *_packet, size_t _size) throw(L2T::Exception)
    {
        if (this->byte + sizeof(uint64_t) >= _size) {
            throw Exception(L2T_ERROR_INVALID_OPERATION,
                            "Packet too small to have action extracted.");
        }
        return *((uint64_t *)((uint8_t *)_packet + this->byte)) & htobe64(this->mask);
    }

    /**
     * \brief Result of last action application.
     */
    inline uint64_t last_id()
    {
        return current_be;
    }

    uint32_t byte; /**< Starting byte for which action will be performed. */
    uint64_t mask; /**< Extension of action as a mask of 8 bytes. */
    Type type;     /**< Type of action to be performed. */

    uint32_t seed; /**< Seed for random numbers. Default: 0 */

    uint64_t range_first; /**< First valid value for range action. */
    uint64_t range_last;  /**< Last valid value for range action. */

   protected:
    /**
     * \brief Update packet data with new packet ID.
     */
    inline void update_packet()
    {
        this->current_be = htobe64(this->current);
        *this->packet_data &= this->inverse_mask_be;
        *this->packet_data |= this->current_be;
    }

    bool copied;           /**< True if this instance was created by copy. */
    uint64_t custom_range; /**< Value of user defined range. */

    uint64_t *packet_data; /**< Pointer to memory region that must be modified. */
    void *packet_pointer;  /**< Pointer to complete packet. */

    uint64_t step;    /**< Step for actions increment or decrement. Depends on mask. */
    uint64_t current; /**< Result of last action. */

    uint64_t inverse_mask_be; /**< Inverse Mask in Big-Endian format. */
    uint64_t current_be;      /**< Result of last action in Big-Endian format. */

    Action *chained_unconditional; /**< Unconditionally chained action. */
    Action *chained_periodically;  /**< Periodically chained action. */
    uint32_t chained_period;       /**< Number of applies before chaining next action. */

    uint32_t apply_counter; /**< Internal counter to determine how many applies were done. */

    std::mt19937_64 gen; /**< Random generator. */

   private:
    /**
     * \brief Validates action parameters
     * \param _packet Packet data.
     * \param _size Packet size.
     */
    void validate(void *_packet, size_t _size) throw(L2T::Exception);

    /**
     * \brief Get the max range for action mask
     * \return max range
     */
    uint64_t getActionMaskMaxRange() throw(L2T::Exception);
};

/*************************************************************************************************/

/**
 * \brief Define a periodical packet sender.
 */
class Sender {
   public:
    /**
     * \brief Construct new Sender.
     *        The packet data is cached inside this object.
     * \param _interface     Name of the sending interface.
     * \param _packet        Packet data to be sent.
     * \param _size          Size of the packet.
     */
    Sender(const std::string &_interface, void *_packet, size_t _size) throw(L2T::Exception);

    /**
     * \brief Destroy Sender and free packet memory and internal actions.
     */
    virtual ~Sender();

    /**
     * \brief Configure this stream to send target bandwidth.
     *        The internal interval and burst size are calculated based on the desired bandwidth and
     * frame size.
     * \param _bandwidth     Target bandwidth of this stream in bps (>0).
     */
    void auto_bandwidth(uint32_t _bandwidth) throw(L2T::Exception);

    /**
     * \brief Specify burst size and interval directly instead of target bandwidth.
     * \param _burst         Number of frames sent per interval (>0).
     * \param _interval_ns   Interval in nanoseconds between each burst (>100).
     */
    void manual_bandwidth(uint32_t _burst, uint64_t _interval_ns) throw(L2T::Exception);

    /**
     * \brief Set Action to this Sender.
     *        It will be applied to current packet before it is sent.
     *        Action is copied to this Sender, so modifications (including chaining another Action)
     *        won't be taken into account. You must set it again in order to re-copy and consider
     *        new modifications.
     * \param _action        Action to be applied. Pass NULL to remove action.
     */
    void set_action(Action *_action = NULL) throw(L2T::Exception);

    /**
     * \brief Return current configured bandwidth.
     * \return Current bandwidth in bits per second.
     */
    inline const uint32_t get_bandwidth()
    {
        return this->bandwidth;
    }

    /**
     * \brief Run Sender in blocking mode based on number of packets or timeout.
     * \param _num_packets   Number of packets to be sent during execution. Pass 0 to ignore.
     * \param _timeout       Maximum time of execution in milliseconds. Pass 0 to ignore.
     */
    void run(uint64_t _num_packets = 0, uint32_t _timeout_ms = 0) throw(L2T::Exception);

    /**
     * \brief Start sending bandwidth.
     */
    void start() throw(L2T::Exception);

    /**
     * \brief Stop sending bandwidth.
     */
    void stop() throw(L2T::Exception);

    /**
     * \brief Send frames periodically based on burst and interval.
     */
    void send_loop() throw();

    /**
     * \brief Get the total of sent packets since last start()
     */
    uint64_t sent_packets()
    {
        return packets_sent;
    }

   protected:
    /**
     * \brief Called before each packet is sent.
     * \return Return true if packet should be sent, false otherwise.
     */
    virtual bool should_send_packet() throw()
    {
        return true;
    }

    /**
     * \brief Helper function to verify everything is prepared before starting sending loop.
     */
    void check_running_conditions() throw(L2T::Exception);

    std::string iface_name; /**< Name of the sending interface. */
    void *packet_data;      /**< Packet data. */
    size_t packet_size;     /**< Packet size. */

    uint32_t bandwidth;              /**< Actual bandwidth, measured in bits per second. */
    uint32_t burst;                  /**< Number of packets sent per interval. */
    uint64_t sending_interval_ns;    /**< Interval between each burst in nanoseconds. */
    pthread_mutex_t bandwidth_mutex; /**< Can't change bandwidth while this stream is being used. */

    Action *action; /**< Optional Action to be applied to the packet each time it's sent. */
    pthread_mutex_t action_mutex; /**< Can't change bandwidth while this stream is being used. */

    bool send_stop;             /**< Flag used to end sending thread. */
    uint64_t packets_sent;      /**< Total of sent packets. */
    uint64_t send_max_packets;  /**< Maximum number of packets to be sent during execution. */
    uint32_t send_timeout_ms;   /**< Maximum time of sending execution. */
    Thread<Sender> send_thread; /**< Thread responsible for sending the packets periodically. */
};

/*************************************************************************************************/

} /* namespace L2T */

#endif /* L2T_SENDER_H */
