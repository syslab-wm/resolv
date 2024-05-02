package resolv

import (
	"github.com/miekg/dns"
	"github.com/syslab-wm/functools"
)

// CollectRRs takes a slice of [github.com/miekg/dns.RR]s and returns
// a slice of with the [github.com/miekg/dns.RR]s of type T.  If not such
// records exist, the function returns a zero-length slice.
func CollectRRs[T dns.RR](rrs []dns.RR) []T {
	recs := functools.Filter(rrs, func(rr dns.RR) bool {
		_, ok := rr.(T)
		return ok
	})

	return functools.Map[dns.RR, T](recs, func(rr dns.RR) T {
		return rr.(T)
	})
}

func OrderCNAMEs(a []*dns.CNAME) bool {
	if len(a) == 0 {
		return true
	}

	n := 1       // number sorted; so [0, n-1] are sorted
	flag := true // during a pass, did we sort one more cname
	for flag {
		flag = false
		for i := n; i < len(a); i++ {
			if a[i].Target == a[0].Hdr.Name {
				tmp := a[i]
				for j := i; j > 0; j-- {
					a[j] = a[j-1]
				}
				a[0] = tmp
				flag = true
				n++
			}

			if a[n-1].Target == a[i].Hdr.Name {
				a[n], a[i] = a[i], a[n]
				flag = true
				n++
			}
		}
	}

	return n == len(a)
}
