/*************************************************************************************************/
/**
 * \file
 * \brief Define a helper classes to manipulate timers.
 */
/*************************************************************************************************/

#ifndef L2T_TIMER_H
#define L2T_TIMER_H

extern "C" {
#include <time.h>
#include <stdint.h>
#include <pthread.h>
}

namespace L2T {

/*************************************************************************************************/

/**
 * \brief Class to verify elapsed time and sleep with milliseconds precision.
 */
class Timer {
   public:
    /**
     * \brief Construct new Timer and update internal clock.
     */
    Timer();

    /**
     * \brief Sleep until current time is increased by an interval in milliseconds.
     * \param _interval_ms   Interval in milliseconds.
     */
    void sleep_ms(uint64_t _interval_ms);

    /**
     * \brief Sleep until current time is increased by an interval in nanoseconds.
     * \param _interval_ns   Interval in nanoseconds.
     */
    void sleep_ns(uint64_t _interval_ns);

    /**
     * \brief Update internal clock with current time.
     */
    void update();

    /**
     * \brief Elapsed time in milliseconds.
     * \param _creation      If true, return elapsed time since object creation.
     * \return Elapsed time.
     */
    uint64_t elapsed_ms(bool _creation = false);

   private:
    struct timespec created; /**< Creation time. */
    struct timespec current; /**< Last updated time. */
    pthread_mutex_t mutex;   /**< Used to lock access to current clock. */
};

/*************************************************************************************************/

} /* namespace L2T */

#endif /* L2T_TIMER_H */
