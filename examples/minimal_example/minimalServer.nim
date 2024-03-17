# SPDX-License-Identifier: MIT

import
  std / asyncdispatch, std / options, taps

proc `$`(b: seq[byte]): string =
  cast[string](b)

proc main() =
  var lp = newLocalEndpoint()
  lp.withHostname "localhost"
  lp.with Port(6666)
  var tp = newTransportProperties()
  tp.prohibit("reliability")
  tp.ignore("congestion-control")
  tp.ignore("preserve-order")
  var
    preconn = newPreconnection(local = [lp], transport = some(tp))
    listener = preconn.listen()
  listener.onConnectionReceiveddo (conn: Connection):
    conn.onReadydo :
      echo "connection ready"
    conn.onReceiveddo (data: seq[byte]; ctx: MessageContext):
      echo data
      conn.receive()
    conn.receive()
  runForever()

main()