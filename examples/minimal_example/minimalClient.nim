# SPDX-License-Identifier: MIT

import
  std / options

import
  pkg / sys / ioqueue

import
  taps

proc main() =
  var ep = newRemoteEndpoint()
  ep.withHostname "localhost"
  ep.with Port(6666)
  var tp = newTransportProperties()
  tp.prohibit("reliability")
  tp.ignore("congestion-control")
  tp.ignore("preserve-order")
  var preconn = newPreconnection(remote = [ep], transport = some tp)
  let conn = preconn.initiate()
  conn.onReadydo :
    conn.send("Hello\n")
  conn.onSentdo (ctx: MessageContext):
    quit()
  ioqueue.run()

main()