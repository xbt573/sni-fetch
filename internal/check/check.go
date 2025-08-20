package check

import (
	"crypto/tls"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

type Result struct {
	Available bool

	HTTP2 bool

	TLSAvailable bool
	TLSVerified  bool
	TLSVersion   uint16
}

type Opts struct {
	HTTP2 bool

	Timeout time.Duration

	MinTLS uint16
	MaxTLS uint16
}

func Check(url string, opts Opts) (*Result, error) {
	if opts.Timeout == 0 {
		opts.Timeout = time.Second * 3
	}

	if opts.MinTLS == 0 {
		opts.MinTLS = tls.VersionTLS12
	}

	if opts.MaxTLS == 0 {
		opts.MaxTLS = tls.VersionTLS13
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: opts.MinTLS,
			MaxVersion: opts.MaxTLS,
		},
	}

	if opts.HTTP2 {
		if err := http2.ConfigureTransport(transport); err != nil {
			return nil, err
		}
	} else {
		transport.TLSNextProto = make(map[string]func(string, *tls.Conn) http.RoundTripper)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	res.Body.Close()

	result := &Result{}

	result.TLSVersion = res.TLS.Version

	if res.StatusCode == http.StatusOK {
		result.Available = true
	}

	if res.TLS != nil {
		result.TLSAvailable = true
	}

	if len(res.TLS.VerifiedChains) > 0 {
		result.TLSVerified = true
	}

	if res.ProtoMajor == 2 {
		result.HTTP2 = true
	}

	return result, nil
}
