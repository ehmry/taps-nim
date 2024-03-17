# SPDX-License-Identifier: MIT

import
  std / options

import
  pkg / sys / ioqueue

import
  taps

proc `$`(b: seq[byte]): string =
  cast[string](b)

proc connectionHandler(conn: Connection) =
  echo "Received new Connection."
  conn.onReceivedPartialdo (data: seq[byte]; ctx: MessageContext; eom: bool):
    echo "Received message ", data, "."
    conn.receive(min_incomplete_length = 1, max_length = 5)
    conn.send(data)
  conn.onReceiveddo (data: seq[byte]; ctx: MessageContext):
    echo "Received message ", data, "."
    conn.receive(min_incomplete_length = 1, max_length = 5)
    conn.send(data)
  conn.onSentdo (ctx: MessageContext):
    echo "Sent cb received, message ", ctx, " has been sent."
  conn.onReceiveErrordo (ctx: MessageContext; reason: ref Exception):
    echo "connection error: ", reason.msg
  conn.receive(min_incomplete_length = 1, max_length = 3)

type
  Reliability = enum
    reliable, notReliable, both
proc main(reliable: Reliability) =
  var lp = newLocalEndpoint()
  lp.with Port(1024)
  var tp = newTransportProperties()
  tp.require "reliability"
  tp.ignore "congestion-control"
  tp.ignore "preserve-order"
  let preconn = newPreconnection(local = [lp], transport = tp.some)
  var listener = preconn.listen()
  listener.onListenErrordo (err: ref Exception):
    echo "Listen Error occcured, ", err.msg, "."
    quit -1
  listener.onConnectionReceived(connectionHandler)
  ioqueue.run()

main(notReliable)