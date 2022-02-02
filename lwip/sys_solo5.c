#include "lwip/sys.h"

u32_t sys_now(void)
{
  return solo5_clock_monotonic() / 1000000ULL;
}
