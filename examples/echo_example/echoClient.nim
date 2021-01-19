# SPDX-License-Identifier: MIT

import
  std / asyncdispatch, std / options, taps

proc main() =
  var ep = newRemoteEndpoint()
  ep.withHostname "localhost"
  ep.with Port(1024)
  var lp = newLocalEndpoint()
  var tp = newTransportProperties()
  tp.require "reliability"
  tp.ignore "congestion-control"
  tp.ignore "preserve-order"
  var preconn = newPreconnection(remote = ep.some, local = lp.some,
                                 transport = tp.some)
  let conn = preconn.initiate()
  conn.onInitiateErrordo (err: ref Exception):
    echo "Initiate Error occcured, ", err.msg, "."
    quit -1
  conn.onReadydo :
    echo "Ready cb received."
    conn.onSentdo (ctx: MessageContext):
      echo "Sent cb received, message ", ctx, " has been sent."
      conn.receive(min_incomplete_length = 1.some)
    conn.onSendErrordo (ctx: MessageContext; err: ref Exception):
      echo "SendError cb received, ", err.msg, "."
    conn.onCloseddo :
      echo "Connection closed, stopping event loop."
      quit()
    conn.onReceivedPartialdo (data: string; ctx: MessageContext; eom: bool):
      echo "Received partial message ", data, "."
    conn.onReceiveddo (data: string; ctx: MessageContext):
      echo "Received message ", data, "."
    echo "Connection cbs set."
    conn.send "Hello\n"
    conn.send "There"
    conn.send "Friend"
    conn.send "How"
    conn.send "Are"
    conn.send "You\n"
    conn.send "Today?\n"
    conn.send "343536"
    echo "send called."
  echo "Called initiate, connection object created."
  while true:
    if asyncdispatch.hasPendingOperations():
      poll()
    else:
      waitFor sleepAsync(500)

main()