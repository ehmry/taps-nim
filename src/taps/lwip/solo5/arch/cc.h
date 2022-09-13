#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include "printf.h"

#define LWIP_SOLO5
#include "solo5.h"

#define memcmp   __builtin_memcmp
#define memcpy   __builtin_memcpy
#define memmove  __builtin_memmove
#define memset   __builtin_memset
#define strlen   __builtin_strlen
#define strncmp  __builtin_strncmp

static void printf(const char *fmt, ...)
    __attribute__ ((format (printf, 1, 2)));

static void printf(const char *fmt, ...)
{
    char buffer[1024];
    va_list args;
    size_t size;

    va_start(args, fmt);
    size = vsnprintf(buffer, sizeof buffer, fmt, args);
    va_end(args);

    if (size >= sizeof buffer) {
        const char trunc[] = "(truncated)\n";
        solo5_console_write(buffer, sizeof buffer - 1);
        solo5_console_write(trunc, sizeof trunc - 1);
    }
    else {
        solo5_console_write(buffer, size);
    }
}

#define LWIP_PLATFORM_DIAG(x) do {printf x;} while(0)

#define LWIP_PLATFORM_ASSERT(x) do { nim_raise_assert(x, __FILE__, __LINE__); } while(0)

#define LWIP_NO_INTTYPES_H 1
#define LWIP_NO_LIMITS_H 1
#define LWIP_NO_CTYPE_H 1

/* flags compatible with out tiny printf */
#define  X8_F "02x"
#define U16_F "u"
#define S16_F "d"
#define X16_F "x"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define SZT_F "d"

extern uint32_t nim_rand(void);
#define LWIP_RAND() (nim_rand())

#endif /* LWIP_ARCH_CC_H */
