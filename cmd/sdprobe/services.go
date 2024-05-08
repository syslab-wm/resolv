package main

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"slices"
	"strings"

	"github.com/syslab-wm/mu"
)

// ServiceNames is the list of default service names.  The function
// [LoadServiceNamesFromFile] loads a list of names from files and sets this
// global variable to that new list.
var ServiceNames = []string{
	"_afpovertcp._tcp",
	"_autodiscover._tcp",
	"_avaya-ep-config._tcp",
	"_caldav._tcp",
	"_caldavs._tcp",
	"_carddav._tcp",
	"_carddavs._tcp",
	"_cisco-uds._tcp",
	"_collab-edge._tls",
	"_cuplogin._tcp",
	"_ftp._tcp",
	"_h323cs._tcp",
	"_h323ls._udp",
	"_h323rs._udp",
	"_http._tcp",
	"_https._tcp",
	"_iax._tcp",
	"_imap._tcp",
	"_imaps._tcp",
	"_informacast._tcp",
	"_informacastpg._tls",
	"_ipp._tcp",
	"_ipp._tcp.pc-printer-discovery",
	"_ipp._tls.pc-printer-discovery",
	"_ipps._tcp",
	"_ipps._tcp.pc-printer-discovery",
	"_ipps._tls.pc-printer-discovery",
	"_jabber._tcp",
	"_kerberos._tcp",
	"_kerberos._udp",
	"_ldap._tcp",
	"_ldap._tcp.dc._msdcs",
	"_ldaps._tcp",
	"_minecraft._tcp",
	"_mongodb._tcp",
	"_mysql._tcp",
	"_mysqlx._tcp",
	"_net-assistant._udp",
	"_nfs._tcp",
	"_nssocketport._tcp",
	"_ocsp._tcp",
	"_opcua._tcp",
	"_opcua._tls",
	"_pexapp._tcp",
	"_plexclient._tcp",
	"_plexmediasvr._tcp",
	"_pcoip-bootstrap._tcp",
	"_pop3._tcp",
	"_pop3s._tcp",
	"_postgresql._tcp",
	"_printer._tcp",
	"_pkixrep._tcp",
	"_sftp-ssh._tcp",
	"_sip._tcp",
	"_sips._tcp",
	"_sip._tls",
	"_sip._udp",
	"_sipfederationtls._tcp",
	"_skype._tcp",
	"_smb._tcp",
	"_smtp._tcp",
	"_ssh._tcp",
	"_stun._tcp",
	"_submission._tcp",
	"_submissions._tcp",
	"_xmpp-client._tcp",
	"_xmpps-client._tcp",
	"_xmpp-server._tcp",
	"_xmpps-server._tcp",
	"_xmpp._tcp",
	"_x-puppet._tcp",
}

func ChooseNRandomServiceNames(r *rand.Rand, n int) []string {
	numServices := len(ServiceNames)
	if n > numServices {
		mu.Panicf("ChooseNRandomServices: can't choose %d services when slice has only %d", n, numServices)
	}

	indices := r.Perm(numServices)
	batch := indices[:n]
	slices.Sort(batch)

	result := make([]string, n)
	for _, idx := range batch {
		result = append(result, ServiceNames[idx])
	}

	return result
}

func LoadServiceNamesFromFile(path string) error {
	var names []string

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		name := strings.TrimSpace(line)
		names = append(names, name)
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if len(names) == 0 {
		return fmt.Errorf("service file %q does not contain any service names", path)
	}

	ServiceNames = names
	return nil
}
