package util

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
	"unicode"

	"golang.org/x/net/idna"
)

var strtotls = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

func StringToTLSVersion(x string) (res uint16, err error) {
	res, ok := strtotls[x]
	if !ok {
		err = fmt.Errorf("unknown tls version: %v", x)
	}

	return
}

// LookupHost is net.LookupHost with automatic IDNA conversion and timeout
func LookupHost(host string) (addrs []string, err error) {
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
