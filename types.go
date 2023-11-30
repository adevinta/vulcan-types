/*
Copyright 2019 Adevinta
*/

package types

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
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
//
// This method is kept to don't break compatibility, use IsWebAddress instead.
func IsURL(target string) bool {
	return IsWebAddress(target)
}

// IsGitRepository returns true if the target has the format of a Git repository.
func IsGitRepository(target string) bool {
	matched, err := regexp.MatchString(
		`((git|ssh|http(s)?)|(git@[\w\.]+))(:(//)?)([\w\.@\:/\-~]+)(\.git)(/)?`,
		target,
	)
	return matched && err == nil
}

// IsWebAddress returns true if the target is an absolute URL.
//
//   - It has a non-empty scheme (http or https)
//   - It has a non-empty hostname
func IsWebAddress(target string) bool {
	u, err := url.ParseRequestURI(target)
	if err != nil {
		return false
	}
	return u.IsAbs() && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != ""
}

// IsAWSARN returns true if the target is an AWS ARN.
func IsAWSARN(target string) bool {
	_, err := arn.Parse(target)
	return err == nil
}

// IsAWSAccount returns true if the target is an AWS account.
func IsAWSAccount(target string) bool {
	targetARN, err := arn.Parse(target)
	if err != nil {
		return false
	}

	// An account ARN has the format "arn:aws:iam::123456789012:root".
	return targetARN.Service == "iam" && targetARN.Resource == "root"
}

// IsDockerImage returns true if the target is a Docker image.
//
// The registry must be specified, while the tag is optional:
//
//   - Valid: registry.hub.docker.com/metasploitframework/metasploit-framework:latest
//   - Valid: registry.hub.docker.com/metasploitframework/metasploit-framework
//   - Valid: registry.hub.docker.com/library/debian
//   - Valid: registry.hub.docker.com/path1/path2/artifact (compliant with V2 spec)
//   - Valid: registry.hub.docker.com/artifact (compliant with V2 spec)
//   - Valid: localhost:5500/library/debian
//   - Valid: registry-1.docker.io/library/postgres:latest
//   - Valid: docker.io/library/busybox
//   - Valid: ghcr.io/puppeteer/puppeteer
//   - Not valid: metasploitframework/metasploit-framework:latest
//   - Not valid: metasploitframework/metasploit-framework
//   - Not valid: debian
func IsDockerImage(target string) bool {
	// If the target is a CIDR we assume it's not a Docker Image.
	// This is not strictly correct, but will discard conflicts with
	// CIDR ranges that comply with Docker Images but are improbable.
	// E.g.: 192.0.2.1/32
	if IsCIDR(target) {
		return false
	}

	n, err := reference.ParseNamed(target)
	if err != nil {
		return false
	}

	if reference.Domain(n) == "" {
		return false
	}

	// All registry path components must match with this regexp.
	// Reference: https://docs.docker.com/registry/spec/api/#overview
	r, _ := regexp.Compile("[a-z0-9]+(?:[._-][a-z0-9]+)*")

	pathParts := strings.Split(reference.Path(n), "/")
	for _, p := range pathParts {
		if !r.MatchString(p) {
			return false
		}
	}

	return true
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
	m.SetEdns0(dns.DefaultMsgSize, false)
	c := dns.Client{}
	var r *dns.Msg
	// Try to get an answer using local configured dns servers.
	for _, srv := range dnsConf.Servers {
		r = nil
		address := fmt.Sprintf("%s:%s", srv, dnsConf.Port)

		r, _, err = c.Exchange(m, address)
		if err != nil {
			return false, err
		}

		// If UDP response was truncated
		// then try through TCP.
		if r.Truncated {
			c.Net = "tcp"
			r, _, err = c.Exchange(m, address)
			if err != nil {
				return false, err
			}
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

// IsHostnameNoDnsResolution returns true if the target is not an IP.
func IsHostnameNoDnsResolution(target string) bool {
	// If the target is an IP can not be a hostname.
	if IsIP(target) {
		return false
	}

	// We don't want to onboard TLDs to vulcan
	if !strings.Contains(target, ".") {
		return false
	}

	return true
}

// IsGCPProjectID returns true if the target is a GCP Project.
//
// A GCP project id is the unique, user-assigned id of the project. It must be 6 to 30 lowercase ASCII letters, digits, or hyphens.
// It must start with a letter. Trailing hyphens are prohibited.
//
//	Valid: googleproject
//	Valid: google-project
//	Valid: google-project123
//	Valid: google-123-project
//	Not valid: googleProject
//	Not valid: google_project
//	Not valid: google-project-
//	Not valid: 123-google-project
func IsGCPProjectID(target string) bool {
	matched, err := regexp.MatchString("^[a-z][-a-z0-9]{4,28}[a-z0-9]{1}$", target)

	if err != nil {
		return false
	}
	return matched
}

type AssetType string

// Asset types for vulcan assets.
const (
	AWSAccount    AssetType = "AWSAccount"
	DockerImage   AssetType = "DockerImage"
	GitRepository AssetType = "GitRepository"
	IP            AssetType = "IP"
	IPRange       AssetType = "IPRange"
	DomainName    AssetType = "DomainName"
	Hostname      AssetType = "Hostname"
	WebAddress    AssetType = "WebAddress"
)

// String returns the string representation of the [AssetType].
func (t AssetType) String() string {
	return string(t)
}

// Parse parses a string representing an asset type into an [AssetType].
// It returns error if the provided string does not match any known asset
// type.
func Parse(assetType string) (t AssetType, err error) {
	switch AssetType(assetType) {
	case AWSAccount:
		t = AWSAccount
	case DockerImage:
		t = DockerImage
	case GitRepository:
		t = GitRepository
	case IP:
		t = IP
	case IPRange:
		t = IPRange
	case Hostname:
		t = Hostname
	case DomainName:
		t = DomainName
	case WebAddress:
		t = WebAddress
	default:
		err = fmt.Errorf("unknown type: %v", assetType)
	}
	return t, err
}

// DetectAssetTypes detects the asset types from an identifier.
func DetectAssetTypes(identifier string) ([]AssetType, error) {
	if IsAWSAccount(identifier) {
		return []AssetType{AWSAccount}, nil
	}

	if IsDockerImage(identifier) {
		return []AssetType{DockerImage}, nil
	}

	if IsGitRepository(identifier) {
		return []AssetType{GitRepository}, nil
	}

	if IsIP(identifier) {
		return []AssetType{IP}, nil
	}

	if IsCIDR(identifier) {
		assetType := IPRange

		// In case the CIDR has a /32 mask, remove the mask
		// and add the asset as an IP.
		if IsHost(identifier) {
			assetType = IP
		}

		return []AssetType{assetType}, nil
	}

	var assetTypes []AssetType

	isWeb := false
	if IsWebAddress(identifier) {
		isWeb = true

		// From a URL like https://adevinta.com not only a WebAddress
		// type can be extracted, also a hostname (adevinta.com) and
		// potentially a domain name.
		u, err := url.ParseRequestURI(identifier)
		if err != nil {
			return nil, err
		}
		// Overwrite identifier to check for hostname and domain.
		identifier = u.Hostname()
	}

	if IsHostname(identifier) {
		assetTypes = append(assetTypes, Hostname)

		// Add WebAddress type only for URLs with valid hostnames.
		if isWeb {
			assetTypes = append(assetTypes, WebAddress)
		}
	}

	ok, err := IsDomainName(identifier)
	if err != nil {
		return nil, fmt.Errorf("cannot guess if the asset is a domain: %w", err)
	}
	if ok {
		assetTypes = append(assetTypes, DomainName)
	}

	return assetTypes, nil
}

// IsValid reports whether the [AssetType] is known. The zero value is
// considered valid.
func (t AssetType) IsValid() bool {
	if t == "" {
		return true
	}
	_, err := Parse(string(t))
	return err == nil
}
