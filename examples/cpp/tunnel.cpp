/*************************************************************************************************/
/**
 * \file
 * \brief Example in C++ for L2T::Tunnel classes.
 */
/*************************************************************************************************/

#include <iostream>
#include "l2t_tunnel.h"

extern "C" {
#include <signal.h>
#include <pthread.h>
}

/**************************************************************************************************
 ** Main **
 **************************************************************************************************/

pthread_mutex_t L2TESTER_TUNNEL_mutex;
pthread_cond_t L2TESTER_TUNNEL_cond;

void signal_handler(int _signal)
{
    ::pthread_cond_signal(&L2TESTER_TUNNEL_cond);
}

int main(int argc, char* argv[])
{
    /* Verify if we have the 2 mandatory arguments */
    if (argc < 3) {
        std::cout << "  Usage: " << argv[0] << " <src> <dst>" << std::endl << "  Arguments"
                  << std::endl << "    src               : Source ethernet interface. Ex eth0"
                  << std::endl << "    dst               : Destination ethernet interface. Ex eth1"
                  << std::endl;
        return -1;
    }

    ::pthread_mutex_init(&L2TESTER_TUNNEL_mutex, NULL);
    ::pthread_cond_init(&L2TESTER_TUNNEL_cond, NULL);

    struct sigaction sig_handler;
    sig_handler.sa_handler = signal_handler;
    ::sigemptyset(&sig_handler.sa_mask);
    sig_handler.sa_flags = 0;
    ::sigaction(SIGINT, &sig_handler, NULL);

    try {
        pthread_mutex_lock(&L2TESTER_TUNNEL_mutex);
        L2T::Tunnel tunnel(argv[1], argv[2]);
        pthread_cond_wait(&L2TESTER_TUNNEL_cond, &L2TESTER_TUNNEL_mutex);
        pthread_mutex_unlock(&L2TESTER_TUNNEL_mutex);
    }
    catch (L2T::Exception& e) {
        std::cout << e.what() << std::endl;
    }

    return 0;
}
