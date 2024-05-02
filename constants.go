package resolv

import (
	"time"
)

const (
	MinUDPBufSize = 0
	MaxUDPBufSize = 65535

	MinMaxCNAMEs = 0
	MaxMaxCNAMEs = 10

	DefaultDoTPort      = "853"
	DefaultDoQPort      = "853"
	DefaultHTTPEndpoint = "/dns-query"
	DefaultTimeout      = 5 * time.Second
	DefaultUDPBufSize   = 4096 // in the EDNS0 opt record
)
