# SPDX-License-Identifier: MIT

when defined(solo5):
  import
    solo5 / devices

type
  Pbuf {.importc: "struct pbuf", header: "lwip/pbuf.h".} = ptr object
  
  TcpPcb {.importc: "struct tcp_pcb", header: "lwip/tcp.h".} = ptr object
  UdpPcb {.importc: "struct udp_pcb", header: "lwip/udp.h".} = ptr object
  LwipTransport = enum
    lwipTcp, lwipUdp
  ListenerPlatform = object
    case
    of lwipTcp:
      
    else:
        nil

  
  ConnectionPlatform = object
    case
    of lwipTcp:
      
    of lwipUdp:
      
  