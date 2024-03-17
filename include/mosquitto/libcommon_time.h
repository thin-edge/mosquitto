#ifndef LIBMOSQUITTO_COMMON_TIME_H
#define LIBMOSQUITTO_COMMON_TIME_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#  ifdef libmosquitto_common_EXPORTS
#    define libmosqcommon_EXPORT __declspec(dllexport)
#  else
#    ifndef LIBMOSQUITTO_STATIC
#      ifdef libmosquittocommon_EXPORTS
#        define libmosqcommon_EXPORT  __declspec(dllexport)
#      else
#        define libmosqcommon_EXPORT  __declspec(dllimport)
#      endif
#    else
#      define libmosqcommon_EXPORT
#    endif
#  endif
#else
#  define libmosqcommon_EXPORT
#endif

#include <time.h>

/* Function: mosquitto_time
 *
 * Returns an indication of the current time in seconds. The exact type of
 * value varies depending on the platform in use, but in most cases will be a
 * monotonically increasing value that does not relate to the real clock time.
 *
 * Returns:
 *    Indication of the current time, in seconds
 */
libmosqcommon_EXPORT time_t mosquitto_time(void);

/* Function: mosquitto_time_ns
 *
 * Returns the current clock time in seconds and nanoseconds. The resolution of
 * the nanosecond value varies depending on the platform in use.
 *
 * The value returned may be decrease as well as increase in response to system
 * clock changes.
 *
 * Parameters:
 *    s - the output pointer for the number of seconds
 *    ns - the output pointer for the number of nanoseconds
 */
libmosqcommon_EXPORT void mosquitto_time_ns(time_t *s, long *ns);

#ifdef __cplusplus
}
#endif

#endif
