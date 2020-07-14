/*************************************************************************************************/
/**
 * \file
 * \brief Define basic exception thrown by L2 tester objects.
 */
/*************************************************************************************************/

#ifndef L2T_EXCEPTION_H
#define L2T_EXCEPTION_H

#include <exception>
#include <string>

extern "C" {
#include "l2t_error.h"
}

namespace L2T {

/*************************************************************************************************/

/**
 * \brief Exception class for L2 Tester.
 */
class Exception : public std::exception {
   public:
    /**
     * \brief Construct new Exception.
     * \param _code          Error code defining the nature of the exception.
     * \param _detail        Detailed information about exception.
     */
    Exception(en_l2t_error_t _code, const std::string &_detail = "");

    /**
     * \brief Destroy Exception.
     */
    virtual ~Exception() throw()
    {
    }

    /**
     * \brief Return string describing the exception.
     * \return The exception explanation.
     */
    const char *what() const throw();

    /**
     * \brief Overloads comparison operator == to ease error checking.
     */
    bool operator==(const int &_code) const;

    /**
     * \brief Overloads comparison operator != to ease error checking.
     */
    bool operator!=(const int &_code) const;

   protected:
    int error_code;          /**< Internal error code. */
    std::string description; /**< String describing the exception. */
};

/*************************************************************************************************/

} /* namespace L2T */

#endif /* L2T_EXCEPTION_H */
