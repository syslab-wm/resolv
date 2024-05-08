package main

import (
	"bufio"
	"encoding/json"
	"log"
	"math/rand"
	"os"
	"sync"

	"github.com/miekg/dns"
	"github.com/syslab-wm/mu"
	"github.com/syslab-wm/netx"
	"github.com/syslab-wm/resolv"
)

type InputRecord struct {
	Rank       int
	Domainname string
}

type ScanRecord struct {
	Rank       int
	QName      string
	DNSSDProbe *DNSSDProbeResult
	PTRProbe   *PTRProbeResult
	SRVProbe   *SRVProbeResult
	NAPTRProbe *NAPTRProbeResult
}

func NewScanRecord(rank int, qname string) *ScanRecord {
	rec := &ScanRecord{}
	rec.Rank = rank
	rec.QName = qname
	return rec
}

// HasResults returns true if at least one of the probes has result data
func (r *ScanRecord) HasResults() bool {
	return r.DNSSDProbe != nil || r.PTRProbe != nil || r.SRVProbe != nil || r.NAPTRProbe != nil
}

func processFile(path string, ch chan<- *InputRecord) {
	defer close(ch)

	f, err := os.Open(path)
	if err != nil {
		mu.Fatalf("failed to open input file: %v", err)
	}
	defer f.Close()

	rank := 1
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		domainname := dns.Fqdn(line)
		ch <- &InputRecord{Rank: rank, Domainname: domainname}
		rank++
	}

	if err := scanner.Err(); err != nil {
		mu.Fatalf("error: failed to read input file: %v", err)
	}
}

func newClient(opts *Options) *resolv.Client {
	// Note that we set AD=0 and CD=1 so that the DNS resolver returns
	// results regardless of whether the results pass DNSSEC validation.
	// The individual probes can then toggle these bits to check if the records
	// are in fact DNSSEC-validated.

	c := &resolv.Client{
		AD:           false,
		CD:           true,
		ClientSubnet: opts.subnetPrefix,
		DO:           true,
		MaxCNAMEs:    opts.maxCNAMEs,
		NSID:         opts.nsid,
		RD:           true,
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

func main() {
	var wg sync.WaitGroup

	opts := parseOptions()

	inch := make(chan *InputRecord, opts.numWorkers)
	outch := make(chan *ScanRecord, opts.numWorkers)
	wg.Add(opts.numWorkers)

	for i := 0; i < opts.numWorkers; i++ {
		workerId := i
		// each one of these goroutines is a "worker"
		go func() {
			var drawBatch bool
			var c *resolv.Client
			defer func() {
				wg.Done()
				if c != nil {
					c.Close()
				}
				log.Printf("worker %d exiting", workerId)
			}()

			c = newClient(opts)

			r := rand.New(rand.NewSource(int64(workerId)))
			serviceNames := ServiceNames
			if opts.probeNames.Has("ptr") || opts.probeNames.Has("srv") {
				if opts.serviceNamesBatchSize > 0 {
					drawBatch = true
				}
			}

			for inRec := range inch {
				log.Printf("[w=%d] %d %s\n", workerId, inRec.Rank, inRec.Domainname)
				rec := NewScanRecord(inRec.Rank, inRec.Domainname)

				if drawBatch {
					serviceNames = ChooseNRandomServiceNames(r, opts.serviceNamesBatchSize)
				}

				if opts.probeNames.Has("dnssd") {
					rec.DNSSDProbe = DoDNSSDProbe(c, inRec.Domainname)
				}
				if opts.probeNames.Has("ptr") {
					rec.PTRProbe = DoPTRProbe(c, inRec.Domainname, serviceNames)
				}
				if opts.probeNames.Has("srv") {
					rec.SRVProbe = DoSRVProbe(c, inRec.Domainname, serviceNames)
				}
				if opts.probeNames.Has("naptr") {
					rec.NAPTRProbe = DoNAPTRProbe(c, inRec.Domainname)
				}
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
