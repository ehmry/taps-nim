# SPDX-License-Identifier: MIT

import
  std / options

import
  taps

import
  solo5, solo5_dispatcher

proc `$`(b: seq[byte]): string =
  cast[string](b)

proc connectionHandler(conn: Connection) =
  echo "Received new Connection."
  conn.onCloseddo :
    conn.close()
  conn.onReceivedPartialdo (data: seq[byte]; ctx: MessageContext; eom: bool):
    echo "Received partial message of ", data.len, " bytes"
    conn.send(data)
    conn.receive()
  conn.onSentdo (ctx: MessageContext):
    echo "Sent cb received, message ", ctx, " has been sent."
  conn.onReceiveErrordo (ctx: MessageContext; reason: ref Exception):
    echo "connection error: ", reason.msg
  conn.receive()

proc main() =
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
  run()

acquireDevices([("echoserver", netBasic)], netAcquireHook)
main()