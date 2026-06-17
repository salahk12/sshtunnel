package tunnel

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// sockOpts holds per-tunnel socket tuning applied to the local listener, the
// SSH transport socket, and accepted client connections.
type sockOpts struct {
	sndBuf  int // bytes, 0 = OS default
	rcvBuf  int // bytes, 0 = OS default
	mss     int // TCP_MAXSEG bytes, 0 = default
	noDelay bool
}

// control is a net.Dialer / net.ListenConfig Control hook: it runs on the raw
// fd before connect/bind, which is the correct point to set buffers and MSS.
func (o sockOpts) control(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		f := int(fd)
		if o.sndBuf > 0 {
			_ = unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_SNDBUF, o.sndBuf)
		}
		if o.rcvBuf > 0 {
			_ = unix.SetsockoptInt(f, unix.SOL_SOCKET, unix.SO_RCVBUF, o.rcvBuf)
		}
		if o.mss > 0 {
			_ = unix.SetsockoptInt(f, unix.IPPROTO_TCP, unix.TCP_MAXSEG, o.mss)
		}
		if o.noDelay {
			_ = unix.SetsockoptInt(f, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
		}
	})
}

// applyToConn sets the tunable options that make sense on an already-accepted
// TCP connection (the client<->panel leg).
func (o sockOpts) applyToConn(conn net.Conn) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	tc.SetNoDelay(o.noDelay)
	if o.sndBuf > 0 {
		_ = tc.SetWriteBuffer(o.sndBuf)
	}
	if o.rcvBuf > 0 {
		_ = tc.SetReadBuffer(o.rcvBuf)
	}
}
