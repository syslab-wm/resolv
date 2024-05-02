package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"sync"

	"github.com/miekg/dns"
	"github.com/syslab-wm/mu"
	"github.com/syslab-wm/netx"
	"github.com/syslab-wm/resolv"
)

func processFile(path string, ch chan<- string) {
	defer close(ch)

	f, err := os.Open(path)
	if err != nil {
		mu.Fatalf("failed to open input file: %v", err)
	}
	defer f.Close()

	i := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		ch <- line
		i++
	}

	if err := scanner.Err(); err != nil {
		mu.Fatalf("error: failed to read input file: %v", err)
	}
}

func newClient(opts *Options) *resolv.Client {
	c := &resolv.Client{
		AD:           opts.adflag,
		CD:           opts.cdflag,
		ClientSubnet: opts.subnetPrefix,
		DO:           opts.dnssec,
		MaxCNAMEs:    opts.maxCNAMEs,
		NSID:         opts.nsid,
		RD:           opts.rdflag,
	}

	if opts.tcp {
		c.Transport = &resolv.Do53TCP{
			Server:   netx.TryJoinHostPort(opts.server, "53"),
			IPv4Only: opts.four,
			IPv6Only: opts.six,
			Timeout:  opts.timeout,
			KeepOpen: opts.keepopen,
		}
	} else if opts.tls {
		c.Transport = &resolv.DoT{
			Server:   netx.TryJoinHostPort(opts.server, resolv.DefaultDoTPort),
			IPv4Only: opts.four,
			IPv6Only: opts.six,
			Timeout:  opts.timeout,
			KeepOpen: opts.keepopen,
		}
	} else if opts.httpsURL != "" {
		c.Transport = &resolv.DoH{
			ServerURL: opts.httpsURL,
			Timeout:   opts.timeout,
			UseGET:    opts.httpsUseGET,
			KeepOpen:  opts.keepopen,
		}
	} else {
		c.Transport = &resolv.Do53UDP{
			Server:           netx.TryJoinHostPort(opts.server, "53"),
			IPv4Only:         opts.four,
			IPv6Only:         opts.six,
			Timeout:          opts.timeout,
			UDPBufSize:       opts.bufsize,
			IgnoreTruncation: opts.ignore,
		}
	}

	return c
}

type ScanRecord struct {
	QName      string
	DNSSDProbe *DNSSDProbeResult
	PTRProbe   *PTRProbeResult
	SRVProbe   *SRVProbeResult
}

func NewScanRecord(qname string) *ScanRecord {
	rec := &ScanRecord{}
	rec.QName = qname
	return rec
}

// HasResults returns true if at least one of the probes has result data
func (r *ScanRecord) HasResults() bool {
	return r.DNSSDProbe != nil || r.PTRProbe != nil || r.SRVProbe != nil
}

func main() {
	var wg sync.WaitGroup

	opts := parseOptions()

	inch := make(chan string, opts.numWorkers)
	outch := make(chan *ScanRecord, opts.numWorkers)
	wg.Add(opts.numWorkers)

	for i := 0; i < opts.numWorkers; i++ {
		workerId := i
		// each one of these goroutines is a "worker"
		go func() {
			var c *resolv.Client
			defer func() {
				wg.Done()
				if c != nil {
					c.Close()
				}
				log.Printf("worker %d exiting", workerId)
			}()

			c = newClient(opts)
			for domainname := range inch {
				log.Printf("[w=%d]%s\n", workerId, domainname)
				domainname = dns.Fqdn(domainname)
				rec := NewScanRecord(domainname)
				rec.DNSSDProbe = DoDNSSDProbe(c, domainname)
				rec.PTRProbe = DoPTRProbe(c, domainname)
				rec.SRVProbe = DoSRVProbe(workerId, c, domainname)
				outch <- rec
			}
		}()
	}

	go func() {
		wg.Wait()
		close(outch)
		log.Println("closed outch")
	}()

	go processFile(opts.inputFile, inch)

	jsonWriter := json.NewEncoder(os.Stdout)
	//jsonWriter.SetIndent("", "    ")
	for r := range outch {
		if !r.HasResults() {
			continue
		}
		jsonWriter.Encode(r)
	}

}
