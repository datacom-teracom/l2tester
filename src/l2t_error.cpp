/*************************************************************************************************/
/**
 * \file
 * \brief Implement error related functions.
 */
/*************************************************************************************************/

extern "C" {
#include "l2t_error.h"
}

const char *l2t_error_explanation_get(en_l2t_error_t _code)
{
    switch (_code) {
        case L2T_ERROR_GENERIC:
            return "Generic error.";
        case L2T_ERROR_INVALID_CONFIG:
            return "Invalid configuration.";
        case L2T_ERROR_INVALID_OPERATION:
            return "Invalid operation.";
        case L2T_ERROR_SOCKET:
            return "Error in socket operation. User has permissions?";
        case L2T_ERROR_TIMEOUT:
            return "Operation timed out.";
        case L2T_ERROR_NOT_FOUND:
            return "Not Found.";
        default:
            return "Unknown L2T error.";
    }
}

/*************************************************************************************************/
