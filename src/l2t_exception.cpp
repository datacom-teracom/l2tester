/*************************************************************************************************/
/**
 * \file
 * \brief Implement basic exception thrown by L2 tester objects.
 */
/*************************************************************************************************/

#include "l2t_exception.h"

namespace L2T {

/*************************************************************************************************/

Exception::Exception(en_l2t_error_t _code, const std::string &_detail)
    : error_code(_code), description("")
{
    this->description.append(l2t_error_explanation_get(_code));
    this->description.append(" ");
    this->description.append(_detail);
}

/*************************************************************************************************/

const char *Exception::what() const throw()
{
    return this->description.c_str();
}

/*************************************************************************************************/

bool Exception::operator==(const int &_code) const
{
    return this->error_code == _code;
}

/*************************************************************************************************/

bool Exception::operator!=(const int &_code) const
{
    return this->error_code != _code;
}

/*************************************************************************************************/

} /* namespace L2T */
