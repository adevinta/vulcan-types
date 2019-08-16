package types

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go/aws/arn"
	"github.com/docker/distribution/reference"
	"github.com/miekg/dns"
)

const (
	dnsConfFilePath = "/etc/resolv.conf"
)

var (
	dnsConf *dns.ClientConfig
)

// IsIP returns true if the target is an IP address.
func IsIP(target string) bool {
	return net.ParseIP(target) != nil
}

// IsCIDR returns true if the target is a CIDR.
func IsCIDR(target string) bool {
	_, _, err := net.ParseCIDR(target)
	return err == nil
}

// IsHost returns true if the target is a CIDR with mask '/32'.
func IsHost(target string) bool {
	return IsCIDR(target) && strings.HasSuffix(target, "/32")
}

// IsURL returns true if the target is an absolute URL (it has a non-empty scheme).
func IsURL(target string) bool {
	u, err := url.ParseRequestURI(target)
	return err == nil && u.IsAbs()
}

// IsAWSARN returns true if the target is an AWS ARN.
func IsAWSARN(target string) bool {
	_, err := arn.Parse(target)
	return err == nil
}

// IsDockerImage returns true if the target is a Docker image.
//
// The registry must be specified, while the tag is optional:
//   Valid: registry.hub.docker.com/metasploitframework/metasploit-framework:latest
//   Valid: registry.hub.docker.com/metasploitframework/metasploit-framework
//   Valid: registry.hub.docker.com/library/debian
//   Valid: localhost:5500/library/debian
//   Not valid: metasploitframework/metasploit-framework:latest
//   Not valid: metasploitframework/metasploit-framework
//   Not valid: debian
func IsDockerImage(target string) bool {
	n, err := reference.ParseNamed(target)
	if err != nil {
		return false
	}

	if reference.Domain(n) == "" {
		return false
	}

	p := reference.Path(n)
	parts := strings.Split(p, "/")
	return len(parts) == 2
}

// IsDomainName returns true if a query to a domain server returns a SOA record for the
// target.
func IsDomainName(target string) (bool, error) {
	return hasSOARecord(target)
}

func hasSOARecord(target string) (bool, error) {
	var err error
	// Read the local dns server config only the first time.
	if dnsConf == nil {
		dnsConf, err = dns.ClientConfigFromFile(dnsConfFilePath)
		if err != nil {
			return false, err
		}
	}

	target = target + "."

	m := &dns.Msg{}
	m.SetQuestion(target, dns.TypeSOA)
	c := dns.Client{}
	var r *dns.Msg
	// Try to get an answer using local configured dns servers.
	for _, srv := range dnsConf.Servers {
		r = nil
		r, _, err = c.Exchange(m, fmt.Sprintf("%s:%s", srv, dnsConf.Port))
		if err != nil {
			return false, err
		}

		if r.Rcode == dns.RcodeSuccess && r != nil {
			break
		}
	}
	if r == nil {
		return false, errors.New("failed to get a valid answer")
	}

	return soaHeaderForName(r, target), nil
}

func soaHeaderForName(r *dns.Msg, name string) bool {
	for _, a := range r.Answer {
		h := a.Header()
		if h.Name == name && h.Rrtype == dns.TypeSOA {
			return true
		}
	}
	return false
}

// IsHostname returns true if the target is not an IP but can be resolved to an IP.
func IsHostname(target string) bool {
	// If the target is an IP can not be a hostname.
	if IsIP(target) {
		return false
	}

	resolv := &net.Resolver{PreferGo: true}
	r, err := resolv.LookupHost(context.Background(), target)
	if err != nil {
		return false
	}

	return len(r) > 0
}
