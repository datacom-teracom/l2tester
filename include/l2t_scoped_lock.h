/*************************************************************************************************/
/**
 * \file
 * \brief Define a helper classes to manipulate mutex locks.
 */
/*************************************************************************************************/

#ifndef L2T_SCOPED_LOCK_H
#define L2T_SCOPED_LOCK_H

extern "C" {
#include <pthread.h>
}

namespace L2T {

/*************************************************************************************************/

/**
 * \brief Used to keep a mutex locked within a specific scope.
 */
class ScopedLock {
   public:
    /**
     * \brief Construct ScopedLock. Lock associated mutex.
     * \param _mutex         Associated mutex to be locked.
     */
    explicit ScopedLock(pthread_mutex_t* _mutex) : mutex(_mutex)
    {
        ::pthread_mutex_lock(this->mutex);
    }

    /**
     * \brief Destroy Scoped Lock and unlock mutex.
     */
    ~ScopedLock()
    {
        ::pthread_mutex_unlock(this->mutex);
    }

   private:
    pthread_mutex_t* mutex; /**< Mutex protected by this instance. */
};

/*************************************************************************************************/

} /* namespace L2T */

#endif /* L2T_SCOPED_LOCK_H */
