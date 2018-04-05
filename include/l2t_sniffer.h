/*************************************************************************************************/
/**
 * \file
 * \brief Define class to monitor interface for incoming packets.
 */
/*************************************************************************************************/

#ifndef L2T_SNIFFER_H
#define L2T_SNIFFER_H

#include "l2t_interface.h"
#include "l2t_thread.h"

#include <vector>
#include <set>

extern "C" {
#include <stdint.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
}

namespace L2T {

/*************************************************************************************************/

/**
 * \brief Define a Packet Filter to receive only matching packets.
 */
class Filter {
   public:
    /**
     * \brief Construct new empty Filter.
     */
    Filter();

    /**
     * \brief Construct new Filter based on the other.
     * \param _other         Reference to another Filter to be copied from.
     */
    Filter(const Filter &_other);

    /**
     * \brief Destroy filter releasing resources.
     */
    virtual ~Filter();

    /**
     * \brief Verify if this filter match the specified packet.
     * \param _packet        Packet data.
     * \param _size          Packet size.
     * \return True if packet matches this filter, false otherwise.
     */
    bool match(void *_packet, size_t _size);

    /**
     * \brief Inverse filter results.
     */
    void inverse();

    /**
     * \brief Append a 32 bits match to the existing match
     * \param _data  The data to be appended
     * \param _mask  The mask related to data where bits '0' mean 'ignore'
     * \param _byte  The starting byte of match. It must be multiple of 4. Be careful to do not do
     *               undesired overwrites
     */
    void match32bits(uint32_t _data, uint32_t _mask, uint16_t _byte) throw(L2T::Exception);

   protected:
    bool match_all; /**< If this filter match any packet, match function return promptly. */
    bool inversed;  /**< If true, matching result will be reversed. */

    uint32_t *mask;  /**< Mask of this filter. */
    uint32_t *data;  /**< Content of the filter to be matched. */
    uint32_t length; /**< Length of filter in multiple of 4 bytes. */
    uint16_t byte;   /**< Starting byte for filter matching. */
};

/*************************************************************************************************/

/**
 * \brief Ease creation of filter based on Ethernet header.
 */
class EthernetFilter : public Filter {
   public:
    /**
     * \brief Create new EthernetFilter.
     */
    EthernetFilter();

    /**
     * \brief Compile fields information into filter mask and data.
     *        Be careful: this method will overwrite previously compiled matches, including the ones
     *        created with match32bits().
     */
    void compile() throw(L2T::Exception);

    std::string dst_mac; /**< Destination MAC Address. String in format "10:00:01:02:03:04". */
    std::string src_mac; /**< Source MAC Address. String in format "10:00:01:02:03:04". */

    int32_t outer_tpid; /**< Outer TPID or Ethertype for untagged frames. */
    int16_t outer_vlan; /**< Outer Vlan (Service VLAN) */
    int8_t outer_prio;  /**< Outer 802.1p priority */

    int32_t inner_tpid; /**< Inner TPID or Ethertype for tagged frames. */
    int16_t inner_vlan; /**< Inner Vlan (Costumer VLAN) */
    int8_t inner_prio;  /**< Outer 802.1p priority */

   private:
    static const uint8_t VLAN_HLEN = 4;

    /**
     * \brief Compile Destination MAC
     * \param idx_first First index
     * \param idx_last Last index
     * \param temp_mask temporary mask
     * \param temp_data temporary data
     * \param mask_mac Mask of MAC Address
     * \param has_valid_field bool indicating if field is present
     */
    void compileDstMac(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                       uint8_t *temp_data, uint8_t *mask_mac,
                       bool &has_valid_field) throw(L2T::Exception);

    /**
     * \brief Compile Source MAC
     * \param idx_first First index
     * \param idx_last Last index
     * \param temp_mask temporary mask
     * \param temp_data temporary data
     * \param mask_mac Mask of MAC Address
     * \param has_valid_field bool indicating if field is present
     */
    void compileSrcMac(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                       uint8_t *temp_data, uint8_t *mask_mac,
                       bool &has_valid_field) throw(L2T::Exception);

    /**
     * \brief Compile OuterTpid
     * \param idx_first First index
     * \param idx_last Last index
     * \param temp_mask temporary mask
     * \param temp_data temporary data
     * \param has_valid_field bool indicating if field is present
     */
    void compileOuterTpid(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                          uint8_t *temp_data, bool &has_valid_field) throw(L2T::Exception);

    /**
     * \brief Compile OuterVlan
     * \param idx_first First index
     * \param idx_last Last index
     * \param temp_mask temporary mask
     * \param temp_data temporary data
     * \param has_valid_field bool indicating if field is present
     */
    void compileOuterVlan(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                          uint8_t *temp_data, bool &has_valid_field) throw(L2T::Exception);

    /**
     * \brief Compile OuterPrio
     * \param idx_first First index
     * \param idx_last Last index
     * \param temp_mask temporary mask
     * \param temp_data temporary data
     * \param has_valid_field bool indicating if field is present
     */
    void compileOuterPrio(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                          uint8_t *temp_data, bool &has_valid_field) throw(L2T::Exception);

    /**
     * \brief Compile InnerTpid
     * \param idx_first First index
     * \param idx_last Last index
     * \param temp_mask temporary mask
     * \param temp_data temporary data
     * \param has_valid_field bool indicating if field is present
     */
    void compileInnerTpid(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                          uint8_t *temp_data, bool &has_valid_field) throw(L2T::Exception);

    /**
     * \brief Compile InnerVlan
     * \param idx_first First index
     * \param idx_last Last index
     * \param temp_mask temporary mask
     * \param temp_data temporary data
     * \param has_valid_field bool indicating if field is present
     */
    void compileInnerVlan(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                          uint8_t *temp_data, bool &has_valid_field) throw(L2T::Exception);

    /**
     * \brief Compile InnerPrio
     * \param idx_first First index
     * \param idx_last Last index
     * \param temp_mask temporary mask
     * \param temp_data temporary data
     * \param has_valid_field bool indicating if field is present
     */
    void compileInnerPrio(uint8_t &idx_first, uint8_t &idx_last, uint8_t *temp_mask,
                          uint8_t *temp_data, bool &has_valid_field) throw(L2T::Exception);
};

/*************************************************************************************************/

/**
 * \brief Sniff multiples interfaces to receive incoming packets.
 *        After the Sniffer is created, it should monitor at least one interface
 *        and have at least one associated filter to properly work.
 *        If multiples filters are associated, the function received_packet is called
 *        one time for each Filter the packet matches.
 */
class Sniffer {
   public:
    /**
     * \brief Create a new Sniffer to monitor interfaces.
     * \param _timeout_ms    Timeout in milliseconds for select operation.
     *                       Determine the frequency for thread termination checks.
     */
    explicit Sniffer(uint32_t _timeout_ms) throw(L2T::Exception);

    /**
     * \brief Destroy Sniffer freeing all allocated memory.
     */
    virtual ~Sniffer();

    /**
     * \brief Add interfaces to be monitored.
     * \param _interfaces    List of interfaces to be monitored.
     */
    void add_interfaces(std::vector<std::string> _interfaces) throw(L2T::Exception);

    /**
     * \brief Remove interfaces from monitored list.
     * \param _interfaces    List of interfaces to be removed.
     */
    void remove_interfaces(std::vector<std::string> _interfaces) throw(L2T::Exception);

    /**
     * \brief Add new filter to this Sniffer.
     * \param _filter        Filter to be added. NULL to create a match all filter.
     * \return Filter pointer that should be used later for filter removal.
     */
    Filter *add_filter(Filter *_filter = NULL) throw(L2T::Exception);

    /**
     * \brief Remove filter from this Sniffer.
     * \param _filter        Filter to be removed.
     */
    void remove_filter(Filter *_filter) throw(L2T::Exception);

    /**
     * \brief Start receive thread.
     */
    void start() throw(L2T::Exception);

    /**
     * \brief Stop receive thread.
     */
    void stop() throw(L2T::Exception);

    /**
     * \brief Wait for any incoming data.
     */
    void receive_loop() throw();

   protected:
    /**
     * \brief Called for each received packet.
     * \param _iface         Interface index that received the packet.
     * \param _filter        Filter index that matched the packet.
     * \param _packet        Packet data.
     * \param _size          Packet size.
     * \return Return true if packet process was successful, false otherwise.
     *         False will cause receive_loop to finish.
     */
    virtual bool received_packet(uint32_t _iface, uint32_t _filter, void *_packet,
                                 size_t _size) throw();

    Thread<Sniffer> receive_thread; /**< Thread for receiving frames. */
    bool receive_stop;              /**< Flag to stop receiving process. */

    std::vector<Interface *> iface_list; /**< List of sniffed interfaces. */
    InterfaceMap iface_map;              /**< Map of sniffed interfaces. */
    pthread_mutex_t iface_mutex;         /**< Used to lock interface changes during receive loop. */

    std::vector<int> sockfd_list; /**< Socket file descriptor associated with interfaces. */

    std::vector<Filter *> filter_list; /**< List of filters associated with this Sniffer. */
    pthread_mutex_t filter_mutex;      /**< Used to lock filter changes during receive loop. */

    bool is_configuring; /**< Flag used to indicate receive loop that a interface or filter change
                            is in progress.
                              This is only needed because iface_mutex and filter_mutex are held
                            during most of receive loop execution. */

    uint32_t timeout_ms; /**< Timeout in milliseconds for select operation. */
    fd_set originalset;  /**< File descriptor set containing all monitored sockets. */
    fd_set readset;      /**< File descriptor set for select operation. */
    int max_fd;          /**< Maximum file descriptor number to be monitored. */

   private:
    static const uint8_t VLAN_HLEN = 4;

    /**
     * \brief Process packet metadata and adds the VLAN
     * \param msg          pointer to packets message
     * \param packet_size  pointer to size of packet in bytes
     */
    void metadataHandler(struct msghdr *msg, signed int *packet_size);

    /**
     * \brief Process the incoming packet with existing filters
     * \param sock         socket for receiving packet
     * \param buffer       pointer to the buffer with packet
     * \param packet_size  size of packet in bytes
     * \return negative value if error, 0 otherwise
     */
    int processIncomingPacket(int sock, uint8_t *buffer, int packet_size);

    struct vlan_tag {
        u_int16_t vlan_tpid; /* ETH_P_8021Q */
        u_int16_t vlan_tci;  /* VLAN TCI */
    };
};

/*************************************************************************************************/

} /* namespace L2T */

#endif /* L2T_SNIFFER_H */
