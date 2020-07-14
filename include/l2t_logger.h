/*************************************************************************************************/
/**
 * \file
 * \brief Define logger for L2T module.
 */
/*************************************************************************************************/

#ifndef L2T_LOGGER_H
#define L2T_LOGGER_H

#define L2T_DEBUG \
    L2T::Logger(L2T::Logger::L2T_LOG_DEBUG, __FILE__, __PRETTY_FUNCTION__, __LINE__).self()
#define L2T_INFO \
    L2T::Logger(L2T::Logger::L2T_LOG_INFO, __FILE__, __PRETTY_FUNCTION__, __LINE__).self()
#define L2T_WARNING \
    L2T::Logger(L2T::Logger::L2T_LOG_WARNING, __FILE__, __PRETTY_FUNCTION__, __LINE__).self()
#define L2T_ERROR \
    L2T::Logger(L2T::Logger::L2T_LOG_ERROR, __FILE__, __PRETTY_FUNCTION__, __LINE__).self()
#define L2T_CRITICAL \
    L2T::Logger(L2T::Logger::L2T_LOG_CRITICAL, __FILE__, __PRETTY_FUNCTION__, __LINE__).self()

#include <iomanip>
#include <iostream>
#include <sstream>

extern "C" {
#include <syslog.h>
}

namespace L2T {

/*************************************************************************************************/

class Logger : public std::stringstream {
   public:
    /**
     * Enum of accepted message types
     */
    enum LogLevel {
        L2T_LOG_SILENT = LOG_DEBUG + 1,
        L2T_LOG_DEBUG = LOG_DEBUG,
        L2T_LOG_INFO = LOG_INFO,
        L2T_LOG_WARNING = LOG_WARNING,
        L2T_LOG_ERROR = LOG_ERR,
        L2T_LOG_CRITICAL = LOG_CRIT,

    };

    /**
     * \brief Construct new Logger. Will log at object destruction.
     * \param _level         Level of the message.
     * \param _file          File, often __FILE__
     * \param _function      Function, often __FUNCTION__
     * \param _line          Line of log, often __LINE__
     */
    Logger(const LogLevel &_level, const char *_file, const char *_function, int _line);

    /**
     * \brief Destroy StreamLog effectively logging the message.
     */
    virtual ~Logger();

    /**
     * \brief Return reference to itself. Necessary to work with an anonymous object.
     */
    Logger &self()
    {
        return *this;
    }

    /**
     * \brief Configure maximum log level that are displayed.
     * \param _level         Minimum log level to be output. Lower level messages are not printed.
     */
    static void config_log_level(const LogLevel &_level);

   protected:
    LogLevel level;       /**< Level of current message. */
    const char *file;     /**< File where message was generated. */
    const char *function; /**< Function where message was generated. */
    int line;             /**< Line where message was generated. */

    static LogLevel config_level; /**< Global configuration level. Only messages with level
                                       smaller or equal to this configuration will be displayed. */
};

/*************************************************************************************************/

/**
 * \brief Helper class to log 'errno' messages.
 */
struct Errno {
    /**
     * \brief Create new instance of Errno holding errno number.
     */
    explicit Errno(int _errno) : code(_errno)
    {
    }
    int code;
};

/*************************************************************************************************/

/**
 * \brief Helper class to log byte streams.
 */
struct ByteArray {
    ByteArray(void *_data, size_t _size) : data(_data), size(_size)
    {
    }

    void *data;
    size_t size;
};

/*************************************************************************************************/

std::ostream &operator<<(std::ostream &_out, const Errno &_errno);
std::ostream &operator<<(std::ostream &_out, const ByteArray &_bytes);

/*************************************************************************************************/

} /* namespace L2T */

#endif /* L2T_LOGGER_H */
