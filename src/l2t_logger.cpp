/*************************************************************************************************/
/**
 * \file
 * \brief  Implements logger for L2T module.
 */
/*************************************************************************************************/

#include <iostream>
#include <cstring>
#include "l2t_logger.h"

namespace L2T {

/**************************************************************************************************
 ** L2T::Logger **
 **************************************************************************************************/

Logger::LogLevel Logger::config_level = L2T_LOG_ERROR;

/*************************************************************************************************/

Logger::Logger(const LogLevel &_level, const char *_file, const char *_function, int _line)
    : level(_level), file(_file), function(_function), line(_line)
{
}

/*************************************************************************************************/

Logger::~Logger()
{
    if (this->level > Logger::config_level) {
        return;
    }

    std::string level_str = "";

    switch (this->level) {
        case L2T_LOG_DEBUG:
            level_str = "DEBUG";
            break;
        case L2T_LOG_INFO:
            level_str = "INFO";
            break;
        case L2T_LOG_WARNING:
            level_str = "WARNING";
            break;
        case L2T_LOG_ERROR:
            level_str = "ERROR";
            break;
        case L2T_LOG_CRITICAL:
            level_str = "CRITICAL";
            break;
        case L2T_LOG_SILENT:
        default:
            break;
    }

    std::string message = this->str();

    size_t pos = message.find("\n", 0);
    while (pos != std::string::npos) {
        message.replace(pos, 1, "\n    ");
        pos = message.find("\n", pos + 1);
    }
    std::cout << "[" << level_str << "] " << message << std::endl;
    std::cout << std::flush;
}

/*************************************************************************************************/

void Logger::config_log_level(const LogLevel &_level)
{
    Logger::config_level = _level;
}

/*************************************************************************************************/

std::ostream &operator<<(std::ostream &_out, const Errno &_errno)
{
    char error_msg[200];
    _out << _errno.code << ": " << strerror_r(_errno.code, error_msg, sizeof(error_msg));
    return _out;
}

/*************************************************************************************************/

std::ostream &operator<<(std::ostream &_out, const ByteArray &_bytes)
{
    _out << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < _bytes.size; i++)
        _out << std::setw(2) << (int)((unsigned char *)_bytes.data)[i] << " ";
    return _out;
}

/*************************************************************************************************/

} /* namespace L2T */
