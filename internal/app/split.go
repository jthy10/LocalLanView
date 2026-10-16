package app

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// splitTLS lets an HTTPS port answer plain HTTP too. Phones try http://
// first when you type 192.168.1.50:8787, and Go's TLS server would answer
// that with "Client sent an HTTP request to an HTTPS server". Connections
// that start with a TLS handshake go to tlsLn, everything else to plainLn,
// where redirectHTTPS sends the browser to the https:// address.
func splitTLS(ln net.Listener) (tlsLn, plainLn net.Listener) {
	s := &split{inner: ln, done: make(chan struct{})}
	s.tls = &chanListener{s: s, conns: make(chan net.Conn)}
	s.plain = &chanListener{s: s, conns: make(chan net.Conn)}
	go s.run()
	return s.tls, s.plain
}

type split struct {
	inner      net.Listener
	tls, plain *chanListener
	done       chan struct{}
	once       sync.Once
}

func (s *split) close() error {
	var err error
	s.once.Do(func() {
		close(s.done)
		err = s.inner.Close()
	})
	return err
}

func (s *split) run() {
	for {
		c, err := s.inner.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				s.close()
				return
			}
			time.Sleep(50 * time.Millisecond) // e.g. out of file descriptors
			continue
		}
		go s.route(c)
	}
}

// tlsHandshake is the first byte of every TLS connection.
const tlsHandshake = 0x16

func (s *split) route(c net.Conn) {
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	b, err := br.Peek(1)
	if err != nil {
		c.Close()
		return
	}
	c.SetReadDeadline(time.Time{})
	dest := s.plain
	if b[0] == tlsHandshake {
		dest = s.tls
	}
	select {
	case dest.conns <- &peekedConn{Conn: c, r: br}:
	case <-s.done:
		c.Close()
	}
}

type chanListener struct {
	s     *split
	conns chan net.Conn
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.s.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error   { return l.s.close() }
func (l *chanListener) Addr() net.Addr { return l.s.inner.Addr() }

// peekedConn reads the bytes route looked at before the rest.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *peekedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// redirectHTTPS sends plain HTTP requests to the same address over HTTPS.
// It's temporary, so a browser doesn't remember it if the console goes
// back to plain HTTP on this machine.
var redirectHTTPS = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if r.Host == "" {
		http.Error(w, "this console only speaks HTTPS", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusFound)
})
