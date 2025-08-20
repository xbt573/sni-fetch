package util

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/xbt573/sni-fetch/internal/check"
)

var strtotls = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

var tlstostr = map[uint16]string{
	tls.VersionTLS10: "tls1.0",
	tls.VersionTLS11: "tls1.1",
	tls.VersionTLS12: "tls1.2",
	tls.VersionTLS13: "tls1.3",
}

func StringToTLSVersion(x string) (res uint16, err error) {
	res, ok := strtotls[x]
	if !ok {
		err = fmt.Errorf("unknown tls version: %v", x)
	}

	return
}

func TLSVersionName(x uint16) string {
	res, ok := tlstostr[x]
	if !ok {
		return "unknowntls"
	}

	return res
}

func Format(domain string, subnet *net.IPNet, result check.Result, ips bool) string {
	modifiers := []string{}

	if result.HTTP2 {
		modifiers = append(modifiers, "http2")
	}

	modifiers = append(modifiers, TLSVersionName(result.TLSVersion))

	if !result.Successful {
		modifiers = append(modifiers, "non-200")
	}

	if !result.TLSAvailable {
		modifiers = append(modifiers, "non-tls")
	} else {
		if !result.TLSVerified {
			modifiers = append(modifiers, "self-signed")
		}
	}

	isSubnet := false

	for _, str := range result.IPs {
		if subnet.Contains(net.ParseIP(str)) {
			isSubnet = true
			break
		}
	}

	if !isSubnet {
		modifiers = append(modifiers, "othersubnet")
	}

	if ips {
		modifiers = append(modifiers, strings.Join(result.IPs, " "))
	}

	if !result.Available {
		modifiers = []string{"failure"}
	}

	return fmt.Sprintf("%v: %v", domain, strings.Join(modifiers, " "))
}
