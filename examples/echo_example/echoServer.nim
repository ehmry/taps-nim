# SPDX-License-Identifier: MIT

import
  std / asyncdispatch, std / options, taps

proc connectionHandler(conn: Connection) =
  echo "Received new Connection."
  conn.onReceivedPartialdo (data: seq[byte]; ctx: MessageContext; eom: bool):
    echo "Received message ", data, "."
    conn.receive(min_incomplete_length = 1.some, max_length = 5.some)
    conn.send(data)
  conn.onReceiveddo (data: seq[byte]; ctx: MessageContext):
    echo "Received message ", data, "."
    conn.receive(min_incomplete_length = 1.some, max_length = 5.some)
    conn.send(data)
  conn.onSentdo (ctx: MessageContext):
    echo "Sent cb received, message ", ctx, " has been sent."
  conn.receive(min_incomplete_length = 1.some, max_length = 3.some)

type
  Reliability = enum
    reliable, notReliable, both
proc main(reliable: Reliability) =
  var lp = newLocalEndpoint()
  lp.with Port(1024)
  var tp = newTransportProperties()
  tp.ignore "congestion-control"
  tp.ignore "preserve-order"
  let preconn = newPreconnection(local = lp.some, transport = tp.some)
  var listener = preconn.listen()
  listener.onListenErrordo (err: ref Exception):
    echo "Listen Error occcured, ", err.msg, "."
    quit -1
  listener.onConnectionReceived(connectionHandler)
  runForever()

main(notReliable)