package main

// WebSocket read pump: split the blocking read off the caller's thread.
//
// The synchronous WebsocketReadMessage holds the calling OS thread inside a
// blocking recv for as long as the peer stays quiet.  With one connection per
// Python thread that costs a thread, a goroutine and a cgo call for every idle
// socket; with a hundred connections it costs a hundred threads.  It also
// makes backpressure impossible: nothing bounds how far the peer can run ahead
// of the reader except the kernel receive buffer.
//
// This file adds an opt-in pump per connection:
//
//   WebsocketStartReadPump(connID, capacity)
//     spawns one goroutine that reads messages into a bounded channel.  When the
//     channel is full the goroutine blocks on send, which stops reading from the
//     socket, which lets TCP backpressure reach the peer.  That is the whole
//     point: no unbounded buffering, no dropped messages, no thread per socket.
//
//   WebsocketPumpRead(connID, timeoutMs)
//     pops one message with a bounded wait.  Returns a message, a "would block"
//     status, or an error -- so the Python side can wait on a Future (async) or
//     poll with a deadline (sync) without holding a thread in recv.
//
// The pump is per connection and torn down by WebsocketClose, which closes the
// socket (making the blocked ReadMessage return) and then drains the channel.
// A close is idempotent, and a pump that outlives its handle frees its own
// resources rather than leaking them.

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bogdanfinn/websocket"
)

const (
	// pumpStatus values returned by WebsocketPumpRead.
	pumpMessage   = 0
	pumpWouldWait = 1
	pumpClosed    = 2
	pumpError     = 3

	// defaultPumpCapacity bounds how many messages may sit between the socket
	// and the consumer.  64 messages is enough to absorb a burst without letting
	// a fast peer outrun a slow consumer by more than that.
	defaultPumpCapacity = 64
)

// wsMessage is one message carried by a pump.
type wsMessage struct {
	messageType int
	data        []byte
}

// wsPump is the read side of one connection.
type wsPump struct {
	ch      chan wsMessage
	closed  chan struct{} // closed when the reader exits
	stop    chan struct{} // closed by Close to tell the reader to give up
	errMu   sync.Mutex
	err     error
	credits atomic.Int64 // messages handed to the consumer, for stats
	dropped atomic.Int64
}

var (
	wsPumps   sync.Map // connID -> *wsPump
	wsPumpSeq atomic.Uint64
)

// next pops one message with a bounded wait.  timeoutMs < 0 waits forever.
func (p *wsPump) next(timeoutMs int) (wsMessage, int, error) {
	var timeout <-chan time.Time
	if timeoutMs >= 0 {
		t := time.NewTimer(time.Duration(timeoutMs) * time.Millisecond)
		defer t.Stop()
		timeout = t.C
	}

	select {
	case m := <-p.ch:
		p.credits.Add(1)
		return m, pumpMessage, nil
	case <-p.closed:
		// The reader stopped.  Anything still buffered is drained first.
		select {
		case m := <-p.ch:
			p.credits.Add(1)
			return m, pumpMessage, nil
		default:
		}
		return wsMessage{}, pumpClosed, wsPumpError(p)
	case <-timeout:
		return wsMessage{}, pumpWouldWait, nil
	}
}

func getWsPump(connID uint64) (*wsPump, bool) {
	v, ok := wsPumps.Load(connID)
	if !ok {
		return nil, false
	}
	return v.(*wsPump), true
}

func setWsPumpError(p *wsPump, err error) {
	p.errMu.Lock()
	if p.err == nil {
		p.err = err
	}
	p.errMu.Unlock()
}

func wsPumpError(p *wsPump) error {
	p.errMu.Lock()
	defer p.errMu.Unlock()
	return p.err
}

// startWsReadPump spawns the reader for conn and returns its handle (the same
// connID the caller already holds).  capacity <= 0 uses defaultPumpCapacity.
//
// Returns an error when a pump already exists for this connection: two readers
// on one websocket would interleave frames and corrupt the stream.
func startWsReadPump(connID uint64, conn *websocket.Conn, capacity int) error {
	if capacity <= 0 {
		capacity = defaultPumpCapacity
	}
	p := &wsPump{
		ch:     make(chan wsMessage, capacity),
		closed: make(chan struct{}),
		stop:   make(chan struct{}),
	}
	if _, loaded := wsPumps.LoadOrStore(connID, p); loaded {
		return fmt.Errorf("websocket connection %d already has a read pump", connID)
	}

	go func() {
		defer close(p.closed)
		for {
			messageType, data, err := conn.ReadMessage()
			if err != nil {
				setWsPumpError(p, err)
				return
			}
			msg := wsMessage{messageType: messageType, data: data}
			select {
			case p.ch <- msg:
				// Handed over to the consumer.
			case <-p.stop:
				return
			}
		}
	}()
	return nil
}

// stopWsReadPump tears a pump down.  Closing *stop releases a reader blocked on
// send; closing the socket releases one blocked in recv (the caller does that
// separately, in WebsocketClose).  Safe to call more than once.
func stopWsReadPump(connID uint64) {
	v, ok := wsPumps.LoadAndDelete(connID)
	if !ok {
		return
	}
	p := v.(*wsPump)
	select {
	case <-p.stop:
	default:
		close(p.stop)
	}
}

// drainWsPump waits for the reader goroutine to exit, so a Close does not race
// with a concurrent ReadMessage on the same conn.
func drainWsPump(connID uint64, timeout time.Duration) {
	v, ok := wsPumps.Load(connID)
	if !ok {
		return
	}
	p := v.(*wsPump)
	select {
	case <-p.closed:
	case <-time.After(timeout):
	}
}

// capacity <= 0 selects the default (64 messages).
//

// pumpAwareClose tears the pump down before the socket is closed, so the reader
// cannot deliver a message after the handle is gone.  Closing *stop releases a
// reader blocked on send; the caller's conn.Close() releases one blocked in
// recv.
func pumpAwareClose(connID uint64) {
	stopWsReadPump(connID)
	drainWsPump(connID, 2*time.Second)
}

// releaseConnectionsForClient closes and forgets every connection created by
// the given client handle.  Called when the client handle is released.
func releaseConnectionsForClient(wsID uint64) {
	type pair struct{ connID, owner uint64 }
	var doomed []pair
	wsConnOwner.Range(func(k, v any) bool {
		if v.(uint64) == wsID {
			doomed = append(doomed, pair{connID: k.(uint64), owner: wsID})
		}
		return true
	})
	for _, p := range doomed {
		stopWsReadPump(p.connID)
		if v, ok := wsConnHandles.Load(p.connID); ok {
			if c, ok := v.(*websocket.Conn); ok {
				_ = c.Close()
			}
			wsConnHandles.Delete(p.connID)
		}
		wsConnOwner.Delete(p.connID)
	}
}
