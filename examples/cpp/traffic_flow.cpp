/*************************************************************************************************/
/**
 * \file
 * \brief Example in C++ for L2T::TrafficFlow classes.
 */
/*************************************************************************************************/

#include <iostream>
#include <map>
#include <cstdlib>
#include <unistd.h>
#include <cstring>

#include "l2t_traffic_flow.h"
#include "l2t_sender.h"
#include "l2t_logger.h"

extern "C" {
#include <signal.h>
}

/**************************************************************************************************
 ** Main **
 **************************************************************************************************/

/* Static instance of TrafficFlow Monitor */
static bool L2T_TESTER_CtrlCPressed;

void signal_handler(int _signal)
{
    L2T_TESTER_CtrlCPressed = true;
}

int main(int argc, char* argv[])
{

    int invalid_options = 0;
    uint32_t packet_interval_ms = 10;
    int opt;
    optind = 1; /* Skip program name! */
    while ((opt = getopt(argc, argv, "i:d:")) != -1) {
        switch (opt) {
            case 'i':
                packet_interval_ms = atoi(optarg);
                break;
            case 'd':
                L2T::Logger::config_log_level(L2T::Logger::L2T_LOG_DEBUG);
            default:
                invalid_options = 1;
                break;
        }
    }

    /* Verify if we have the 2 mandatory arguments */
    if (optind > argc - 2 || invalid_options) {
        std::cout << "  Usage: " << argv[0] << " [opts] <src> <dst>" << std::endl << "  Arguments"
                  << std::endl << "    src               : Source ethernet interface. Ex eth0"
                  << std::endl << "    dst               : Destination ethernet interface. Ex eth1"
                  << std::endl << "  Options:" << std::endl
                  << "    -i <int>          : Configure packet interval in ms. Default: 10."
                  << std::endl << "    -d                : Enable debugs." << std::endl;
        return -1;
    }

    /* Create and start the monitor. */
    try {
        uint8_t packet[100] = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x50, 0x10,
        };

        L2T::Action* action = new L2T::Action();
        action->type = L2T::Action::ACTION_INCREMENT;
        action->mask = 0x0FFF000000000000ULL;
        action->byte = 14;
        action->range_first = 1;
        action->range_last = 4094;

        L2T::EthernetFilter* filter = new L2T::EthernetFilter();
        filter->src_mac = std::string("10:00:01:02:03:04");
        filter->compile();

        L2T::TrafficFlow::Monitor* monitor
            = new L2T::TrafficFlow::Monitor(argv[optind], argv[optind + 1], packet, sizeof(packet),
                                            packet_interval_ms, action, filter);

        struct sigaction sig_handler;
        sig_handler.sa_handler = signal_handler;
        sigemptyset(&sig_handler.sa_mask);
        sig_handler.sa_flags = 0;

        sigaction(SIGINT, &sig_handler, NULL);

        std::cout
            << "==============================================================================="
            << std::endl << "   Timestamp (ms) |       Delta (ms) | Event" << std::endl
            << "-------------------------------------------------------------------------------"
            << std::endl;
        uint64_t last_event_ms = 0;
        monitor->start();
        while (1) {
            const L2T::TrafficFlow::Event* event = monitor->iterate_event(0, true, 1000);
            if (event != NULL) {
                std::cout << " " << std::setw(16) << event->timestamp_ms << " | " << std::setw(16)
                          << event->timestamp_ms - last_event_ms << " | "
                          << L2T::TrafficFlow::Event::type_to_str(event->type) << std::endl;
                if (event->type == L2T::TrafficFlow::Event::TEST_FINISHED) {
                    break;
                }
                last_event_ms = event->timestamp_ms;
            } else {
                if (L2T_TESTER_CtrlCPressed) {
                    monitor->stop();
                }
            }
        }

        L2T::TrafficFlow::Statistics stats;
        monitor->get_statistics(&stats);

        std::cout
            << "==============================================================================="
            << std::endl << "  Traffic Interruption" << std::endl
            << "    Total     : " << stats.traffic_interruption_ms << " ms" << std::endl
            << "    Intervals : " << stats.traffic_interruption_intervals << std::endl
            << "  Loop Detection" << std::endl << "    Total     : " << stats.loop_detected_ms
            << " ms" << std::endl << "    Intervals : " << stats.loop_detected_intervals
            << std::endl << "  Packets" << std::endl << "    Sent      : " << stats.sent_packets
            << std::endl << "    Received  : " << stats.received_packets << std::endl
            << "    Dropped   : " << stats.dropped_packets << std::endl << "  "
            << (stats.error_detected ? "** MONITOR ABORTED **" : "") << std::endl
            << "==============================================================================="
            << std::endl;

        delete monitor;
        delete action;
        delete filter;
    }
    catch (L2T::Exception& e) {
        std::cout << e.what() << std::endl;
    }

    return 0;
}
