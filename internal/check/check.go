package check

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"time"
	"unicode"

	"golang.org/x/net/http2"
	"golang.org/x/net/idna"
)

type Result struct {
	Available  bool
	Successful bool
	IPs        []string

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

// lookupHost is net.lookupHost with automatic IDNA conversion and timeout
func lookupHost(host string) (addrs []string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*3) // sensible default
	defer cancel()

	isascii := true

	for i := 0; i < len(host); i++ {
		if host[i] > unicode.MaxASCII {
			isascii = false
			break
		}
	}

	if !isascii {
		conv, err := idna.ToASCII(host)
		if err != nil {
			return nil, err
		}

		host = conv
	}

	return net.DefaultResolver.LookupHost(ctx, host)
}

func Check(uri string, opts Opts) (*Result, error) {
	if opts.Timeout == 0 {
		opts.Timeout = time.Second * 3
	}

	if opts.MinTLS == 0 {
		opts.MinTLS = tls.VersionTLS12
	}

	if opts.MaxTLS == 0 {
		opts.MaxTLS = tls.VersionTLS13
	}

	result := &Result{}

	parsed, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	ips, err := lookupHost(parsed.Hostname())
	if err != nil {
		return nil, err
	}

	result.IPs = ips

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

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}

	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	res.Body.Close()

	result.Available = true
	result.TLSVersion = res.TLS.Version

	if res.StatusCode == http.StatusOK {
		result.Successful = true
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
