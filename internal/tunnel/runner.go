package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"sshtunnel-panel/internal/config"
	"sshtunnel-panel/internal/sshx"
	"sshtunnel-panel/internal/store"
)

// Runner drives a single tunnel: a pool of SSH workers plus local listeners
// that forward accepted connections over the pool. It runs until ctx is done.
type Runner struct {
	cfg *config.Config
	t   *store.Tunnel

	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
	conns    atomic.Int64

	mu        sync.RWMutex
	workers   []*worker
	lastError atomic.Value // string
	startedAt time.Time

	bufBytes int
	sock     sockOpts
}

type worker struct {
	idx     int
	client  atomic.Pointer[ssh.Client]
	healthy atomic.Bool
}

// NewRunner builds a runner for tunnel id by loading it from the store.
func NewRunner(cfg *config.Config, id string) (*Runner, error) {
	s, err := store.Open(cfg.StorePath())
	if err != nil {
		return nil, err
	}
	t, err := s.Tunnel(id)
	if err != nil {
		return nil, err
	}
	if len(t.Forwards) == 0 {
		return nil, errors.New("tunnel has no forwards configured")
	}
	if t.Workers < 1 {
		t.Workers = 1
	}
	buf := t.BufferSize * 1024
	if buf <= 0 {
		buf = 32 * 1024
	}
	sock := sockOpts{
		sndBuf:  t.SocketBuffer * 1024,
		rcvBuf:  t.SocketBuffer * 1024,
		mss:     t.MSS,
		noDelay: !t.DisableNoDelay,
	}
	return &Runner{cfg: cfg, t: t, startedAt: time.Now(), bufBytes: buf, sock: sock}, nil
}

// Run blocks until ctx is cancelled, maintaining workers and listeners.
func (r *Runner) Run(ctx context.Context) error {
	r.lastError.Store("")

	// Spawn worker maintainers.
	r.workers = make([]*worker, r.t.Workers)
	for i := range r.workers {
		w := &worker{idx: i}
		r.workers[i] = w
		go r.maintainWorker(ctx, w)
	}

	// Start listeners.
	var lns []net.Listener
	for _, f := range r.t.Forwards {
		ln, err := r.startListener(ctx, f)
		if err != nil {
			for _, l := range lns {
				l.Close()
			}
			return err
		}
		lns = append(lns, ln)
	}

	// Periodic stat flush.
	go r.statLoop(ctx)

	<-ctx.Done()
	for _, l := range lns {
		l.Close()
	}
	r.mu.RLock()
	for _, w := range r.workers {
		if c := w.client.Load(); c != nil {
			c.Close()
		}
	}
	r.mu.RUnlock()
	r.flushStat()
	return nil
}

func (r *Runner) maintainWorker(ctx context.Context, w *worker) {
	backoff := time.Second
	for ctx.Err() == nil {
		client, err := r.dial()
		if err != nil {
			r.lastError.Store(fmt.Sprintf("worker %d: %v", w.idx, err))
			log.Printf("tunnel %s worker %d dial failed: %v", r.t.ID, w.idx, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		w.client.Store(client)
		w.healthy.Store(true)
		log.Printf("tunnel %s worker %d connected", r.t.ID, w.idx)
		r.lastError.Store("")

		r.keepalive(ctx, client) // blocks until the connection drops
		w.healthy.Store(false)
		w.client.Store(nil)
		client.Close()
		log.Printf("tunnel %s worker %d disconnected", r.t.ID, w.idx)
	}
}

// keepalive sends periodic global requests; returns when the connection fails.
func (r *Runner) keepalive(ctx context.Context, client *ssh.Client) {
	interval := time.Duration(r.t.ServerAliveInterval) * time.Second
	if interval <= 0 {
		interval = 30 * time.Second
	}
	maxMiss := r.t.ServerAliveCountMax
	if maxMiss <= 0 {
		maxMiss = 3
	}
	closed := make(chan struct{})
	go func() { client.Wait(); close(closed) }()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	misses := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-closed:
			return
		case <-ticker.C:
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				misses++
				if misses >= maxMiss {
					return
				}
			} else {
				misses = 0
			}
		}
	}
}

func (r *Runner) dial() (*ssh.Client, error) {
	cfg, err := sshx.BuildClientConfig(sshx.ClientConfigOptions{
		User:       r.t.Username,
		PrivatePEM: r.t.PrivateKey,
		Cipher:     r.t.Cipher,
		HostKey:    r.t.HostKey,
	})
	if err != nil {
		return nil, err
	}
	return sshx.DialWithControl(r.t.RemoteHost, r.t.RemotePort, cfg, r.sock.control)
}

// pickWorker returns a connected client using round-robin over healthy workers.
func (r *Runner) pickWorker(start int) *ssh.Client {
	n := len(r.workers)
	for i := 0; i < n; i++ {
		w := r.workers[(start+i)%n]
		if w.healthy.Load() {
			if c := w.client.Load(); c != nil {
				return c
			}
		}
	}
	return nil
}

func (r *Runner) startListener(ctx context.Context, f store.Forward) (net.Listener, error) {
	addr := fmt.Sprintf("%s:%d", f.ListenAddr, f.ListenPort)
	lc := net.ListenConfig{Control: r.sock.control}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	log.Printf("tunnel %s listening on %s -> %s:%d", r.t.ID, addr, f.RemoteAddr, f.RemotePort)
	go func() {
		var rr int
		for {
			conn, err := ln.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			rr++
			go r.handle(conn, f, rr)
		}
	}()
	return ln, nil
}

func (r *Runner) handle(local net.Conn, f store.Forward, rr int) {
	defer local.Close()
	r.sock.applyToConn(local)
	client := r.pickWorker(rr)
	if client == nil {
		r.lastError.Store("no healthy worker available for incoming connection")
		return
	}
	remote, err := client.Dial("tcp", fmt.Sprintf("%s:%d", f.RemoteAddr, f.RemotePort))
	if err != nil {
		r.lastError.Store(fmt.Sprintf("open channel: %v", err))
		return
	}
	defer remote.Close()

	r.conns.Add(1)
	defer r.conns.Add(-1)

	var wg sync.WaitGroup
	wg.Add(2)
	// local -> remote (upload to kharej)
	go func() {
		defer wg.Done()
		n, _ := io.CopyBuffer(remote, local, make([]byte, r.bufBytes))
		r.bytesOut.Add(uint64(n))
		if cw, ok := remote.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	// remote -> local (download into Iran)
	go func() {
		defer wg.Done()
		n, _ := io.CopyBuffer(local, remote, make([]byte, r.bufBytes))
		r.bytesIn.Add(uint64(n))
		if cw, ok := local.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	wg.Wait()
}

func (r *Runner) statLoop(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.flushStat()
		}
	}
}

func (r *Runner) flushStat() {
	connected := 0
	for _, w := range r.workers {
		if w.healthy.Load() {
			connected++
		}
	}
	le, _ := r.lastError.Load().(string)
	_ = WriteStat(r.cfg.RunDir(), &Stat{
		TunnelID:         r.t.ID,
		BytesIn:          r.bytesIn.Load(),
		BytesOut:         r.bytesOut.Load(),
		ActiveConns:      int(r.conns.Load()),
		ConnectedWorkers: connected,
		TotalWorkers:     len(r.workers),
		LastError:        le,
		StartedAt:        r.startedAt,
	})
}
