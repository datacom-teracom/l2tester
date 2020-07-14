/*************************************************************************************************/
/**
 * \file
 * \brief Define a helper class to store iterable results.
 */
/*************************************************************************************************/

#ifndef L2T_ITERABLE_H
#define L2T_ITERABLE_H

#include "l2t_exception.h"
#include "l2t_logger.h"
#include "l2t_scoped_lock.h"

#include <vector>

extern "C" {
#include <pthread.h>
#include <stdint.h>
}

namespace L2T {

/*************************************************************************************************/

/**
 * \brief Helper class to store a thread-safe iterable vector of pointers.
 */
template <class T>
class Iterable : protected std::vector<T *> {
   public:
    /**
     * \brief Construct new Iterable list.
     */
    Iterable();

    /**
     * \brief Destroy Iterable deallocating all resources.
     */
    ~Iterable();

    /**
     * \brief Add a new result.
     * \param _pointer        Pointer to be stored.
     */
    void push_back(T *_pointer);

    /**
     * \brief Get last added entry.
     * \return Last added entry or NULL if empty.
     */
    const T *back();

    /**
     * \brief Remove all entries deallocating all resources.
     */
    void clear();

    /**
     * \brief Iterate through stored values with persistent read position.
     * \param _start         Index to start iteration.
     *                          0 : to read next unread value.
     *                          1 : start from last stored value.
     *                         -1 : start from next pushed value.
     * \param _block         If True, block until the desired value is available.
     * \param _timeout_ms    Timeout in milliseconds if blocking operation. Zero to wait forever.
     * \return Return a copy of desired value. NULL if last one and not blocking or blocking and
     * timed out.
     */
    const T *iterate(int _start = 0, bool _block = true, uint32_t _timeout_ms = 0);

   protected:
    uint32_t read_pos;        /**< Current reading position. */
    pthread_cond_t read_cond; /**< Condition used to wait for new event. */
    pthread_mutex_t mutex;    /**< Used to lock list access. */
};

/**************************************************************************************************
 ** L2T::Iterable **
 **************************************************************************************************/

template <class T>
Iterable<T>::Iterable() : std::vector<T *>(), read_pos(0), read_cond(), mutex()
{
    ::pthread_mutex_init(&this->mutex, NULL);
    ::pthread_cond_init(&this->read_cond, NULL);
}

/*************************************************************************************************/

template <class T>
Iterable<T>::~Iterable()
{
    this->clear();
}

/*************************************************************************************************/

template <class T>
void Iterable<T>::push_back(T *_pointer)
{
    ScopedLock lock(&this->mutex);

    this->std::vector<T *>::push_back(_pointer);
    ::pthread_cond_signal(&this->read_cond);
}

/*************************************************************************************************/

template <class T>
const T *Iterable<T>::back()
{
    ScopedLock lock(&this->mutex);

    if (this->std::vector<T *>::empty()) {
        return NULL;
    } else {
        return this->std::vector<T *>::back();
    }
}

/*************************************************************************************************/

template <class T>
void Iterable<T>::clear()
{
    ScopedLock lock(&this->mutex);

    while (!this->std::vector<T *>::empty()) {
        delete this->std::vector<T *>::back();
        this->std::vector<T *>::pop_back();
    }
    this->read_pos = 0;
}

/*************************************************************************************************/

template <class T>
const T *Iterable<T>::iterate(int _start, bool _block, uint32_t _timeout_ms)
{
    ScopedLock lock(&this->mutex);

    if (_start == 1) {
        this->read_pos = 0;
    } else if (_start == -1) {
        this->read_pos = this->std::vector<T *>::size();
    }

    if (_block) {
        struct timespec wait_until;
        int rc = 0;

        if (_timeout_ms > 0) {
            clock_gettime(CLOCK_REALTIME, &wait_until);
            uint64_t nsec = wait_until.tv_nsec + _timeout_ms * 1000000LL;
            wait_until.tv_nsec = nsec % 1000000000LL;
            wait_until.tv_sec += nsec / 1000000000LL;
        }

        while (this->read_pos >= this->std::vector<T *>::size() && rc == 0) {
            if (_timeout_ms > 0) {
                rc = pthread_cond_timedwait(&this->read_cond, &this->mutex, &wait_until);
            } else {
                rc = pthread_cond_wait(&this->read_cond, &this->mutex);
            }
        }

        if (rc == 0) {
            return this->std::vector<T *>::operator[](this->read_pos++);
        } else {
            return NULL;
        }
    } else if (this->read_pos < this->std::vector<T *>::size()) {
        return this->std::vector<T *>::operator[](this->read_pos++);
    } else {
        return NULL;
    }
}

/*************************************************************************************************/

} /* namespace L2T */

#endif /* L2T_ITERABLE_H */
