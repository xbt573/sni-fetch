package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/spf13/cobra"
	"github.com/xbt573/sni-fetch/internal/bgp"
	"github.com/xbt573/sni-fetch/internal/check"
	"golang.org/x/sync/semaphore"
)

var (
	http2                      bool
	minTlsString, maxTlsString string
	minTls, maxTls             uint16
	maxProcs                   int
	verbose                    bool
)

var tlsVersions = map[string]uint16{
	"1.0": tls.VersionTLS10,
	"1.1": tls.VersionTLS11,
	"1.2": tls.VersionTLS12,
	"1.3": tls.VersionTLS13,
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&http2, "http2", true, "Pass HTTP2 as acceptable")
	rootCmd.PersistentFlags().StringVar(&minTlsString, "mintls", "1.2", "Minimal TLS version to accept")
	rootCmd.PersistentFlags().StringVar(&maxTlsString, "maxtls", "1.3", "Maximum TLS version to accept")
	rootCmd.PersistentFlags().IntVar(&maxProcs, "threads", runtime.NumCPU(), "Default concurrent checks")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Log failed domains")

	if info, ok := debug.ReadBuildInfo(); ok {
		vcsRev := "unknown"
		vcsTime := "unknown"
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				vcsRev = s.Value
			case "vcs.time":
				vcsTime = s.Value
			}
		}
		rootCmd.Version = fmt.Sprintf("%s (%s, built at %s)", info.Main.Version, vcsRev, vcsTime)
	} else {
		rootCmd.Version = "unknown"
	}
}

var rootCmd = &cobra.Command{
	Use:  "sni-fetch",
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		version, ok := tlsVersions[minTlsString]
		if !ok {
			return fmt.Errorf("invalid TLS version: %v", minTlsString)
		}
		minTls = version

		version, ok = tlsVersions[maxTlsString]
		if !ok {
			return fmt.Errorf("invalid TLS version: %v", maxTlsString)
		}
		maxTls = version

		ip := net.ParseIP(args[0])
		if ip == nil {
			return fmt.Errorf("invalid IP address: %v", ip)
		}

		subnet, err := bgp.Subnet(ip)
		if err != nil {
			return err
		}

		domains, err := bgp.Domains(subnet)
		if err != nil {
			return err
		}

		sem := semaphore.NewWeighted(int64(maxProcs))
		wg := sync.WaitGroup{}

		for _, domain := range domains {
			wg.Add(1)

			go func() {
				sem.Acquire(context.TODO(), 1)

				defer wg.Done()
				defer sem.Release(1)

				res, err := check.Check("https://"+domain, check.Opts{
					HTTP2:  http2,
					MinTLS: minTls,
					MaxTLS: maxTls,
				})
				if err != nil {
					if verbose {
						fmt.Printf("%v: failure\n", domain)
					}
					return
				}

				str := domain + ": "

				if !res.Available {
					str += "not-200 "
				}

				if res.HTTP2 {
					str += "http2 "
				}

				if res.TLSAvailable {
					str += tls.VersionName(res.TLSVersion) + " "

					if !res.TLSVerified {
						str += "selfsigned "
					}
				} else {
					str += "notls "
				}

				fmt.Println(str)
			}()
		}

		wg.Wait()

		return nil
	},
}

func Execute() error {
	return rootCmd.Execute()
}
