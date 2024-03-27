#define API_LIB_DEBUG LWIP_DBG_OFF
#define ICMP_DEBUG LWIP_DBG_OFF
#define INET_DEBUG LWIP_DBG_OFF
#define IP6_DEBUG LWIP_DBG_OFF
#define IPV6_REASS_MAXAGE 60
#define IP_DEBUG LWIP_DBG_OFF
#define LWIP_ARP 0
#define LWIP_CALLBACK_API 1
#define LWIP_DBG_MIN_LEVEL LWIP_DBG_LEVEL_ALL
#define LWIP_DBG_TYPES_ON LWIP_DBG_ON
#define LWIP_DHCP 0
#define LWIP_DNS 0
#define LWIP_ETHERNET 1
#define LWIP_EVENT_API 0
#define LWIP_ICMP 0
#define LWIP_IGMP 0
#define LWIP_IPV6_DHCP6 0
#define LWIP_IPV6_SCOPES_DEBUG LWIP_DBG_ON
#define LWIP_MULTICAST_PING 1
#define LWIP_NETCONN 0
#define LWIP_NETIF_API 0
#define LWIP_NETIF_STATUS_CALLBACK 1
#define LWIP_PERF 0
#define LWIP_RAW 0
#define LWIP_SINGLE_NETIF 0
#define LWIP_SOCKET 0
#define LWIP_TCP 1
#define LWIP_TCPIP_CORE_LOCKING 0
#define LWIP_TCPIP_CORE_LOCKING_INPUT 0
#define LWIP_UDP 1
#define LWIP_UDPLITE 0
#define MEM_LIBC_MALLOC 1
#define NETIF_DEBUG LWIP_DBG_OFF
#define NO_SYS 1
#define SYS_DEBUG LWIP_DBG_OFF
#define SYS_LIGHTWEIGHT_PROT 0
#define TCP_DEBUG LWIP_DBG_OFF
#define TIMERS_DEBUG LWIP_DBG_OFF
#define UDP_DEBUG LWIP_DBG_OFF

#include<stddef.h>
void nim_clib_free(void *rmem);
void *nim_clib_malloc(size_t size);
void *nim_clib_calloc(size_t count, size_t size);

#define mem_clib_free nim_clib_free
#define mem_clib_malloc nim_clib_malloc
#define mem_clib_calloc nim_clib_calloc
