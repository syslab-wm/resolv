package resolv

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

type DoH struct {
	ServerURL string
	Timeout   time.Duration
	UseGET    bool
	KeepOpen  bool
	TLSConfig *tls.Config

	client *http.Client
}

func (t *DoH) resetHTTPClient() {
	t.client = &http.Client{
		Timeout: t.Timeout,
		Transport: &http.Transport{
			TLSClientConfig:   t.TLSConfig,
			MaxConnsPerHost:   1,
			MaxIdleConns:      1,
			DisableKeepAlives: !t.KeepOpen,
			ForceAttemptHTTP2: true,
		},
	}
}

func (t *DoH) newGETRequest(dnsQuery []byte) (*http.Request, error) {
	urlStr := fmt.Sprintf("%s?dns=%s", t.ServerURL, base64.URLEncoding.EncodeToString(dnsQuery))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	return req, nil
}

func (t *DoH) newPOSTRequest(dnsQuery []byte) (*http.Request, error) {
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, t.ServerURL, bytes.NewReader(dnsQuery))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	return req, nil
}

func (t *DoH) Exchange(req *dns.Msg) (*dns.Msg, error) {
	var httpReq *http.Request
	var err error

	if t.client == nil || !t.KeepOpen {
		t.resetHTTPClient()
	}

	// Per RFC 8484 (DNS Queries over HTTPS (DoH)), the query's ID SHOULD be 0.
	req.Id = 0
	msg, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS request %w", err)
	}

	if t.UseGET {
		httpReq, err = t.newGETRequest(msg)
	} else {
		httpReq, err = t.newPOSTRequest(msg)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := t.client.Do(httpReq)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return nil, fmt.Errorf("error making HTTPS request: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading HTTPS response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTPS response returned an error: %v", resp.StatusCode)
	}

	var reply dns.Msg
	err = reply.Unpack(body)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response message: %w", err)
	}

	return &reply, nil
}

func (t *DoH) Close() error {
	t.client.CloseIdleConnections()
	return nil
}
