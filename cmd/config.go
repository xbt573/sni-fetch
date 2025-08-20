package cmd

type Config struct {
	HTTP2          bool
	MinTLS, MaxTLS uint16

	Threads int

	Failed  bool
	Verbose bool
}
