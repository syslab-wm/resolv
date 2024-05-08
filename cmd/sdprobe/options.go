package main

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/syslab-wm/adt/set"
	"github.com/syslab-wm/mu"
	"github.com/syslab-wm/netx"
	"github.com/syslab-wm/resolv"
)

const usage = `Usage: sdprobe [options] FILE

Probe a list of domains for services.

positional arguments:
  FILE 
    Input file.  Each line of the file is a domainname.

options:
  -help
    Display this usage statement and exit.
    
query options:
  -4
    Use IPv4 only

    Default: false

  -6
    Use IPv6 Only

    Default: false

  -bufsize B
    Set the UDP message buffer size advertised using EDNS0 to B bytes.  The
    maximum and minimum sizes of this buffer are 65535 and 0, respectively.
    Values other than 0 will cause an EDNS query to be sent.

  -https ENDPOINT
    Use DNS over HTTPS (DoH).  Th port number defaults to 443.  The HTTP POST
    request mode is used when sending the query.

    ENDPOINT is the HTTP endpoint in the query URI.  There is no standard value
    for ENDPOINT, though /dns-query is conventional.

    For example:
        ./resolv -server example.com -https /dnsquery foo.bar.example.com

    will use the URI https://example.com/dnsquery

  -https-get ENDPOINT
    Same as -https, except that the HTTP GET request mode is used when sending
    the query.

  -keepalive[=0|1]
    Send an EDNS Keepalive option.

    Default: 0

  -keepopen[=0|1]
    Keep the TCP socket open between queries, and reuse it rather than creating
    a new TCP socket for each lookup.

    Default: 0

  -ignore
    Ignore truncation in UDP responses instead of retrying with TCP.  By
    default, TCP retries are performed.

  -max-cnames N
    The maximum of number of CNAMEs to follow.

    Default: 0

  -num-workers N
    The number of worker goroutines (each goroutine issues a synchronous DNS
    query).

    Default: 1

  -nsid[=1|0]
    Include an EDNS name server ID request when sending a query.

    Default: 0

  -probe PROBE_NAME
    The probe to run.  Available probes are:

      * all
        All the probes

      * dnssd
        Probes for browsable DNS-SD records

      * ptr
        Probes non-browsable DNS-SD records (SRV and TXT records) by trying
        service names from a list.  See -service-names and -service-names-batch-size

      * srv
        Probes for SRV recrods by trying service names from a list
        See -service-names and -service-names-batch-size

      * napatr
        Probes for NAPTR records

    Multiple probes may be specified in a comma-delimited list (e.g., "dnssd,ptr")
    By default all probes are run.

  -server SERVER
    The nameserver to query.  For Do53 and DoH, SERVER is of the form
    HOST[:PORT], where HOST may be hostname or IP address.  If PORT is not
    provided, then port 53 is used for Do53,  port 853 for DoT, and port 443
    for DoH.

    The default is the first nameserver in /etc/resolv.conf.

  -service-names SERVICE_NAME_FILE
    The ptr and srv probes directly query for ~50 popular service names, such
    as _sip._udp and _ipps._tcp.  You can override this list by specifiy a file
    that has one service name per line.

  -service-names-batch-size B
    By default, the ptr and srv probes make queries for all service names
    (either the hardcoded ones, or the names specified in the -service-names
    file).  For exploratory analysis, it can be useful to have a large list,
    and to have each worker randomly draw B names from this list when probing
    each domain.  This option lets you set the number of names to draw.  By
    default, the ptr and srv probes use all names in the list when probing a
    domain.

  -subnet ADDR/PREFIX
    Send an EDNS Client Subnet options with the specified IP address or network
    prefix (e.g., 192.168.1.2/24).

  -tcp
    For Do53, use TCP.  The default is to use UDP.

  -timeout TIMEOUT
    The timeout for the DNS request (e.g. 500ms, 1.5s).

    Default: 5s

  -tls
    Use DNS over TLS (DoT).  When this option is in use, the port
    number defaults to 853.

  -tls-ca CA_FILE
    By default, certificat authority certificat are loaded from the system's
    default certificate store.  This option allows an alternative CA
    certificate to be used for TLS validation.  CA_FILE must be in the PM
    format.

  -tls-hostname HOSTNAME
    Use th provided HOSTNAME during remote server TLS certificate validation.
    Otherwise, theh DNS server name is used.


examples:
  $ ./sdprobe -server 1.1.1.1 -tcp tranco-1m.txt
`

type Options struct {
	// positional
	inputFile string
	// general query options
	four                  bool
	six                   bool
	adflag                bool
	bufsize               int
	cdflag                bool
	dnssec                bool
	https                 string
	httpsGET              string
	httpsURL              string // derived
	httpsUseGET           bool   // derived
	ignore                bool
	keepopen              bool
	maxCNAMEs             int
	probe                 string
	probeNames            *set.Set[string] //derived
	numWorkers            int
	nsid                  bool
	server                string
	serviceNames          string
	serviceNamesBatchSize int
	subnet                string
	subnetPrefix          netip.Prefix // derived
	tcp                   bool
	timeout               time.Duration
	tls                   bool
	tlsCA                 string
	tlsHostname           string
}

func printUsage() {
	fmt.Fprintf(os.Stdout, "%s", usage)
}

func parseOptions() *Options {
	opts := Options{}

	flag.Usage = printUsage
	// general options
	flag.BoolVar(&opts.four, "4", false, "")
	flag.BoolVar(&opts.six, "6", false, "")
	flag.IntVar(&opts.bufsize, "bufsize", 0, "")
	flag.StringVar(&opts.https, "https", "", "")
	flag.StringVar(&opts.httpsGET, "https-get", "", "")
	flag.BoolVar(&opts.ignore, "ignore", false, "")
	flag.BoolVar(&opts.keepopen, "keepopen", false, "")
	flag.IntVar(&opts.maxCNAMEs, "max-cnames", 0, "")
	flag.IntVar(&opts.numWorkers, "num-workers", 1, "")
	flag.BoolVar(&opts.nsid, "nsid", false, "")
	flag.StringVar(&opts.probe, "probe", "all", "")
	flag.StringVar(&opts.server, "server", "", "")
	flag.StringVar(&opts.serviceNames, "service-names", "", "")
	flag.IntVar(&opts.serviceNamesBatchSize, "service-names-batch-size", 0, "")
	flag.StringVar(&opts.subnet, "subnet", "", "")
	flag.BoolVar(&opts.tcp, "tcp", false, "")
	flag.DurationVar(&opts.timeout, "timeout", resolv.DefaultTimeout, "")
	flag.BoolVar(&opts.tls, "tls", false, "")
	flag.StringVar(&opts.tlsCA, "tls-ca", "", "")
	flag.StringVar(&opts.tlsHostname, "tls-hostname", "", "")

	flag.Parse()

	if flag.NArg() != 1 {
		mu.Fatalf("error: expected one positional argument but got %d", flag.NArg())
	}

	opts.inputFile = flag.Arg(0)

	if opts.four && opts.six {
		mu.Fatalf("error: can't specify both -4 and -6")
	}

	if opts.server == "" {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			mu.Fatalf("error: unable to retrieve default nameserver: %v", err)
		}
		opts.server = conf.Servers[0]
		if conf.Port != "" {
			opts.server = netx.TryJoinHostPort(opts.server, conf.Port)
		}
	}

	if opts.https != "" && opts.httpsGET != "" {
		mu.Fatalf("error: can't specify -https and -https-get together")
	}
	if opts.https != "" {
		opts.httpsURL = fmt.Sprintf("https://%s%s", opts.server, opts.https)
	} else if opts.httpsGET != "" {
		opts.httpsURL = fmt.Sprintf("https://%s%s", opts.server, opts.httpsGET)
		opts.httpsUseGET = true
	}

	if opts.subnet != "" {
		prefix, err := netip.ParsePrefix(opts.subnet)
		if err != nil {
			mu.Fatalf("error: invalid subnet: %v", err)
		}
		opts.subnetPrefix = prefix
	}

	opts.probe = strings.ToLower(opts.probe)
	names := set.New(strings.Split(opts.probe, ",")...)
	legit := set.New("all", "dnssd", "ptr", "srv", "naptr")
	for _, name := range names.Items() {
		if !legit.Has(name) {
			mu.Fatalf("invalid probe name: %q", name)
		}
	}
	if names.Has("all") {
		opts.probeNames = set.New("dnssd", "ptr", "srv", "naptr")
	} else {
		opts.probeNames = names
	}

	if opts.serviceNames != "" {
		err := LoadServiceNamesFromFile(opts.serviceNames)
		if err != nil {
			mu.Fatalf("unable to read service names file: %v", err)
		}
	}

	return &opts
}
