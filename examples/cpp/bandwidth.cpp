/*************************************************************************************************/
/**
 * \file
 * \brief Example in C++ for L2T::Bandwidth classes.
 */
/*************************************************************************************************/

#include <iostream>
#include <map>
#include <cstdlib>
#include <unistd.h>
#include <cstring>

#include "l2t_sender.h"
#include "l2t_bandwidth.h"
#include "l2t_logger.h"

/**************************************************************************************************
 ** Main **
 **************************************************************************************************/

int main(int argc, char* argv[])
{
    /* Verify if we have the 2 mandatory arguments */
    if (argc < 3) {
        std::cout << "  Usage: " << argv[0] << " <src> <dst>" << std::endl << "  Arguments"
                  << std::endl << "    src               : Source ethernet interface. Ex eth0"
                  << std::endl << "    dst               : Destination ethernet interface. Ex eth1"
                  << std::endl << std::endl;
        return -1;
    }

    std::vector<std::string> ifaces;
    ifaces.push_back(argv[2]);
    L2T::Bandwidth::Monitor* recv = new L2T::Bandwidth::Monitor(ifaces);

    L2T::EthernetFilter* f0 = new L2T::EthernetFilter();
    f0->outer_tpid = 0x8100;
    f0->outer_vlan = 10;
    f0->inner_tpid = 0x5010;
    f0->dst_mac = std::string("FF:FF:FF:FF:FF:FF");
    f0->compile();
    L2T::Bandwidth::Stream* rx0 = recv->new_stream(f0);

    L2T::EthernetFilter* f1 = new L2T::EthernetFilter();
    f1->outer_vlan = 20;
    f1->compile();
    L2T::Bandwidth::Stream* rx1 = recv->new_stream(f1);

    uint8_t frame0[100] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x10, 0x00, 0x01,
        0x02, 0x03, 0x04, 0x81, 0x00, 0x00, 0x0A, 0x50, 0x10,
    };

    L2T::Sender* tx0 = new L2T::Sender(argv[1], frame0, 100);
    uint32_t bandwidth = 500000;
    tx0->auto_bandwidth(bandwidth);
    tx0->start();

    uint8_t frame1[100] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x10, 0x00,
        0x01, 0x02, 0x03, 0x05, 0x81, 0x00, 0x00, 0x14,
    };

    L2T::Sender* tx1 = new L2T::Sender(argv[1], frame1, 100);
    tx1->auto_bandwidth(300000);
    tx1->start();

    recv->start();

    std::cout << "First round." << std::endl;

    for (int i = 0; i < 10; i++) {
        const L2T::Bandwidth::Measure* m = rx0->iterate_reading();
        std::cout << "RX0 : [" << m->timestamp_ms << "] " << m->bits_per_sec << " bps / "
                  << m->packets_per_sec << " pps / " << m->counter_bytes << " bytes / "
                  << m->counter_packets << " packets / " << m->cumulative_counter_bytes
                  << " cumulative bytes / " << m->cumulative_counter_packets
                  << " cumulative packets" << std::endl;
        m = rx1->iterate_reading();
        std::cout << "RX1 : [" << m->timestamp_ms << "] " << m->bits_per_sec << " bps / "
                  << m->packets_per_sec << " pps / " << m->counter_bytes << " bytes / "
                  << m->counter_packets << " packets / " << m->cumulative_counter_bytes
                  << " cumulative bytes / " << m->cumulative_counter_packets
                  << " cumulative packets" << std::endl;
        bandwidth = (int)(bandwidth * 1.2);
        tx0->auto_bandwidth(bandwidth);
    }

    /* Remove Stream during sniffing. */
    recv->delete_stream(rx0);
    std::cout << "Deleted Stream 0." << std::endl;

    for (int i = 0; i < 5; i++) {
        const L2T::Bandwidth::Measure* m = rx1->iterate_reading();
        std::cout << "RX1 : [" << m->timestamp_ms << "] " << m->bits_per_sec << " bps / "
                  << m->packets_per_sec << " pps / " << m->counter_bytes << " bytes / "
                  << m->counter_packets << " packets / " << m->cumulative_counter_bytes
                  << " cumulative bytes / " << m->cumulative_counter_packets
                  << " cumulative packets" << std::endl;
    }

    /* Recreate Stream while sniffing! */
    rx0 = recv->new_stream(f0);
    std::cout << "Recreated Stream 0." << std::endl;

    for (int i = 0; i < 10; i++) {
        const L2T::Bandwidth::Measure* m = rx0->iterate_reading();
        std::cout << "RX0 : [" << m->timestamp_ms << "] " << m->bits_per_sec << " bps / "
                  << m->packets_per_sec << " pps / " << m->counter_bytes << " bytes / "
                  << m->counter_packets << " packets / " << m->cumulative_counter_bytes
                  << " cumulative bytes / " << m->cumulative_counter_packets
                  << " cumulative packets" << std::endl;
        m = rx1->iterate_reading();
        std::cout << "RX1 : [" << m->timestamp_ms << "] " << m->bits_per_sec << " bps / "
                  << m->packets_per_sec << " pps / " << m->counter_bytes << " bytes / "
                  << m->counter_packets << " packets / " << m->cumulative_counter_bytes
                  << " cumulative bytes / " << m->cumulative_counter_packets
                  << " cumulative packets" << std::endl;
    }

    recv->stop();
    tx0->stop();
    tx1->stop();

    std::cout << "Second round." << std::endl;

    recv->start();
    tx0->start();
    tx1->start();

    for (int i = 0; i < 10; i++) {
        const L2T::Bandwidth::Measure* m = rx0->iterate_reading();
        std::cout << "[" << m->timestamp_ms << "] " << m->bits_per_sec << " bps / "
                  << m->packets_per_sec << " pps / " << m->counter_bytes << " bytes / "
                  << m->counter_packets << " packets / " << m->cumulative_counter_bytes
                  << " cumulative bytes / " << m->cumulative_counter_packets
                  << " cumulative packets" << std::endl;
        m = rx1->iterate_reading();
        std::cout << "[" << m->timestamp_ms << "] " << m->bits_per_sec << " bps / "
                  << m->packets_per_sec << " pps / " << m->counter_bytes << " bytes / "
                  << m->counter_packets << " packets / " << m->cumulative_counter_bytes
                  << " cumulative bytes / " << m->cumulative_counter_packets
                  << " cumulative packets" << std::endl;
        bandwidth = (int)(bandwidth * 0.8);
        tx0->auto_bandwidth(bandwidth);
    }

    recv->stop();
    tx0->stop();
    tx1->stop();

    delete recv;
    delete tx0;
    delete tx1;
    delete f0;
    delete f1;

    return 0;
}
