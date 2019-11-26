# Nim Transport Services Interface

A library providing the Transport Services Interface (TAPS). TAPS is a modern
alternative to the 1983 Berkley Sockets API. The TAPS specification is language
agnostic and this implementation follows the recommendations of the [Abstract
Application Layer Interface to Transport Services](https://datatracker.ietf.org/doc/draft-ietf-taps-impl/).

Please note that the TAPS specifications are still under review within the IETF,
and this implementation will change accordingly, without warning.

For more information see [TAPS IETF working group](https://datatracker.ietf.org/wg/taps/about/),
or watch the [CCCamp19 talk](https://media.ccc.de/v/Camp2019-10298-taps_transport_services_api).

## Examples

 - [Simple UDP client](examples/minimal_example/minimalClient.nim)
 - [Simple UDP server](examples/minimal_example/minimalServer.nim)

 - [Simple TCP client](examples/echo_example/echoClient.nim)
 - [Simple TCP server](examples/echo_example/echoServer.nim)
