package cmd

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/spf13/cobra"
	"github.com/xbt573/sni-fetch/internal/bgp"
	"github.com/xbt573/sni-fetch/internal/check"
	"github.com/xbt573/sni-fetch/internal/util"
	"golang.org/x/sync/semaphore"
)

var config Config

var (
	mintls, maxtls string
)

func init() {
	rootCmd.PersistentFlags().BoolVar(&config.HTTP2, "http2", true, "Pass HTTP2 as acceptable")
	rootCmd.PersistentFlags().StringVar(&mintls, "mintls", "1.2", "Minimal TLS version to accept")
	rootCmd.PersistentFlags().StringVar(&maxtls, "maxtls", "1.3", "Maximum TLS version to accept")
	rootCmd.PersistentFlags().IntVar(&config.Threads, "threads", runtime.NumCPU(), "Default concurrent checks")
	rootCmd.PersistentFlags().BoolVarP(&config.Failed, "failed", "f", false, "Log failed domains")
	rootCmd.PersistentFlags().BoolVarP(&config.Verbose, "verbose", "v", false, "Log additional information (domain IP)")

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
	Use: "sni-fetch",
	Args: func(cmd *cobra.Command, args []string) error {
		if err := cobra.MinimumNArgs(1)(cmd, args); err != nil {
			return err
		}

		mintls, err := util.StringToTLSVersion(mintls)
		if err != nil {
			return err
		}

		maxtls, err := util.StringToTLSVersion(maxtls)
		if err != nil {
			return err
		}

		config.MinTLS = mintls
		config.MaxTLS = maxtls

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		var subnet *net.IPNet

		if _, cidr, err := net.ParseCIDR(args[0]); err == nil {
			subnet = cidr
		} else if ip := net.ParseIP(args[0]); ip != nil {
			subnet, err = bgp.Subnet(ip)
			if err != nil {
				return err
			}
		} else {
			return fmt.Errorf("failed to parse argument: %v", args[0])
		}

		domains, err := bgp.Domains(subnet)
		if err != nil {
			return err
		}

		sem := semaphore.NewWeighted(int64(config.Threads))
		wg := sync.WaitGroup{}

		for _, domain := range domains {
			wg.Add(1)

			go func() {
				sem.Acquire(context.TODO(), 1)

				defer wg.Done()
				defer sem.Release(1)

				res, err := check.Check("https://"+domain, check.Opts{
					HTTP2:  config.HTTP2,
					MinTLS: config.MinTLS,
					MaxTLS: config.MaxTLS,
				})
				if err != nil {
					if config.Failed {
						fmt.Println(util.Format(domain, subnet, *res, config.Verbose))
					}
					return
				}

				fmt.Println(util.Format(domain, subnet, *res, config.Verbose))
			}()
		}

		wg.Wait()

		return nil
	},
}

func Execute() error {
	return rootCmd.Execute()
}
