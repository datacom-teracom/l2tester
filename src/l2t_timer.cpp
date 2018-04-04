/*************************************************************************************************/
/**
 * \file
 * \brief Implement helper classes to manipulate timers.
 */
/*************************************************************************************************/

#include "l2t_timer.h"
#include "l2t_scoped_lock.h"

namespace L2T {

/*************************************************************************************************/

Timer::Timer()
{
    ::pthread_mutex_init(&this->mutex, NULL);
    ::clock_gettime(CLOCK_MONOTONIC, &this->created);
    this->update();
}

/*************************************************************************************************/

void Timer::sleep_ms(uint64_t _interval_ms)
{
    this->sleep_ns(_interval_ms * 1000000LL);
}

/*************************************************************************************************/

void Timer::sleep_ns(uint64_t _interval_ns)
{
    ScopedLock lock(&this->mutex);
    uint64_t nsec = this->current.tv_nsec + _interval_ns;

    this->current.tv_nsec = nsec % 1000000000;
    this->current.tv_sec += nsec / 1000000000;
    while (::clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &this->current, NULL))
        ;
}

/*************************************************************************************************/

void Timer::update()
{
    ScopedLock lock(&this->mutex);
    ::clock_gettime(CLOCK_MONOTONIC, &this->current);
}

/*************************************************************************************************/

uint64_t Timer::elapsed_ms(bool _creation)
{
    ScopedLock lock(&this->mutex);
    struct timespec now, *then;
    ::clock_gettime(CLOCK_MONOTONIC, &now);
    then = _creation ? &this->created : &this->current;
    return (now.tv_sec - then->tv_sec) * 1000 + (now.tv_nsec - then->tv_nsec) / 1000000;
}

/*************************************************************************************************/

} /* namespace L2T */
