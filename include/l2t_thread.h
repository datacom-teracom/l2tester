/*************************************************************************************************/
/**
 * \file
 * \brief Define a helper class to launch methods as threads.
 */
/*************************************************************************************************/

#ifndef L2T_THREAD_H
#define L2T_THREAD_H

#include "l2t_exception.h"
#include "l2t_logger.h"

extern "C" {
#include <pthread.h>
}

namespace L2T {

/*************************************************************************************************/

/**
 * \brief Helper class to ease launch and control of member functions
 *        as independent threads.
 */
template <class T>
class Thread {
   public:
    /**
     * \brief Construct new Thread.
     * \param _object        Pointer to instance with method to be executed.
     * \param _loop          Pointer to method that will be executed as a thread.
     */
    Thread(T* _object, void (T::*_loop)()) : id(0), object(_object), loop(_loop), running(false)
    {
    }

    /**
     * \brief Start this thread. Can't restart a thread that hasn't finished yet.
     */
    void start() throw(L2T::Exception)
    {
        if (this->running) {
            throw Exception(L2T_ERROR_INVALID_OPERATION, "Thread is already running.");
        }
        if (int rc = ::pthread_create(&this->id, NULL, execute_loop, (void*)this) != 0) {
            L2T_ERROR << "Thread creation failed with error " << Errno(rc);
            throw Exception(L2T_ERROR_GENERIC, "Can't start thread loop.");
        }
    }

    /**
     * \brief Wait for thread completion.
     *        Won't raise error if thread is already completed or never started.
     */
    void join() throw(L2T::Exception)
    {
        if (!this->running) {
            return;
        }
        if (int rc = ::pthread_join(this->id, NULL) != 0) {
            L2T_ERROR << "Failed to join thread with error " << Errno(rc);
            throw Exception(L2T_ERROR_GENERIC, "Can't join thread.");
        }
    }

    /**
     * \brief Return running state of Thread.
     * \return True if thread is running, False otherwhise.
     */
    inline bool is_running()
    {
        return this->running;
    }

   protected:
    /**
     * \brief Actual function executed by pthread.
     * \param _arg           Reference to this object.
     * \return NULL
     */
    static void* execute_loop(void* _arg)
    {
        Thread<T>* thread = (Thread<T>*)_arg;
        thread->running = true;
        (thread->object->*thread->loop)();
        thread->running = false;
        pthread_exit(NULL);
    }

    pthread_t id;      /**< The thread ID. */
    T* object;         /**< Pointer to the object which has the method to be executed. */
    void (T::*loop)(); /**< Pointer to the method to be executed. */
    bool running;      /**< Used to verify if this thread is currently running. */
};

/*************************************************************************************************/

} /* namespace L2T */

#endif /* L2T_THREAD_H */
