# SPDX-License-Identifier: MIT

import
  std / options

import
  pkg / sys / ioqueue

import
  taps

proc `$`(b: seq[byte]): string =
  cast[string](b)

proc main() =
  echo "echoClient starting"
  var ep = newRemoteEndpoint()
  ep.with parseIpAddress"::1"
  ep.with Port(1024)
  echo ep
  var lp = newLocalEndpoint()
  echo lp
  var tp = newTransportProperties()
  tp.require "reliability"
  tp.ignore "congestion-control"
  tp.ignore "preserve-order"
  var preconn = newPreconnection(remote = [ep], local = [lp],
                                 transport = tp.some)
  let conn = preconn.initiate()
  conn.onInitiateErrordo (err: ref Exception):
    echo "Initiate Error occcured, ", err.msg, "."
    quit -1
  conn.onReadydo :
    echo "Ready cb received."
    conn.onSentdo (ctx: MessageContext):
      echo "Sent cb received, message ", ctx, " has been sent."
      conn.receive(min_incomplete_length = 1)
    conn.onSendErrordo (ctx: MessageContext; err: ref Exception):
      echo "SendError cb received, ", err.msg, "."
    conn.onCloseddo :
      echo "Connection closed, stopping event loop."
      quit()
    conn.onReceivedPartialdo (data: seq[byte]; ctx: MessageContext; eom: bool):
      echo "Received partial message ", data, "."
    conn.onReceiveddo (data: seq[byte]; ctx: MessageContext):
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
  ioqueue.run()

main()