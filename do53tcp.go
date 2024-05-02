package resolv

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/miekg/dns"
)

type Do53TCP struct {
	Server   string
	IPv4Only bool
	IPv6Only bool
	Timeout  time.Duration
	KeepOpen bool

	client *dns.Client
	conn   *dns.Conn
}

func (t *Do53TCP) dial() error {
	var err error

	net := "tcp"
	if t.IPv4Only {
		net = "tcp4"
	}
	if t.IPv6Only {
		net = "tcp6"
	}

	t.client = &dns.Client{
		Net:     net,
		Timeout: t.Timeout,
	}

	t.conn, err = t.client.Dial(t.Server)
	if err != nil {
		return fmt.Errorf("failed to connect to DNS server %s: %w", t.Server, err)
	}
	return nil
}

func (t *Do53TCP) isConnected() bool {
	return t.conn != nil
}

func (t *Do53TCP) Exchange(req *dns.Msg) (*dns.Msg, error) {
	var err error
	var reused bool
	var retried bool
	var resp *dns.Msg

reconnect:
	if !t.isConnected() {
		err = t.dial()
		if err != nil {
			return nil, err
		}
	} else {
		reused = true
	}

	resp, _, err = t.client.ExchangeWithConn(req, t.conn)
	if !t.KeepOpen {
		t.Close()
	}

	if err == nil {
		return resp, nil
	}

	if !errors.Is(err, io.EOF) {
		return nil, err
	}

	// The server closed the connection on us rather than returning a response
	t.Close()

	// If we were reusing an already established connection, try once to
	// reconnect and resend the query.
	if reused && !retried {
		retried = true
		goto reconnect
	}

	return nil, err
}

func (t *Do53TCP) Close() error {
	if t.conn == nil {
		return nil // XXX: should we instead return an error?
	}
	err := t.conn.Close()
	t.conn = nil
	return err
}
