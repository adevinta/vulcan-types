/*
Copyright 2019 Adevinta
*/

package types

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestIsIP(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{
			name:   "IPv4",
			target: "127.0.0.1",
			want:   true,
		},
		{
			name:   "IPv6",
			target: "::1",
			want:   true,
		},
		{
			name:   "CIDR",
			target: "::1/32",
			want:   false,
		},
		{
			name:   "Garbage",
			target: "31337",
			want:   false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := IsIP(tt.target)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsCIDR(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{
			name:   "IPv4",
			target: "127.0.0.1",
			want:   false,
		},
		{
			name:   "IPv6",
			target: "::1",
			want:   false,
		},
		{
			name:   "IPv4 CIDR",
			target: "127.0.0.1/32",
			want:   true,
		},
		{
			name:   "IPv6 CIDR",
			target: "::1/32",
			want:   true,
		},
		{
			name:   "Garbage",
			target: "31337",
			want:   false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := IsCIDR(tt.target)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsHost(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{
			name:   "IPv4 no mask",
			target: "127.0.0.1",
			want:   false,
		},
		{
			name:   "IPv6 no mask",
			target: "::1",
			want:   false,
		},
		{
			name:   "IPv4 mask 32",
			target: "127.0.0.1/32",
			want:   true,
		},
		{
			name:   "IPv6 mask 32",
			target: "::1/32",
			want:   true,
		},
		{
			name:   "IPv4 mask 16",
			target: "127.0.0.1/16",
			want:   false,
		},
		{
			name:   "IPv6 mask 16",
			target: "::1/16",
			want:   false,
		},
		{
			name:   "Garbage",
			target: "31337",
			want:   false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := IsHost(tt.target)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsWebAddress(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{
			name:   "URL",
			target: "http://127.0.0.1",
			want:   true,
		},
		{
			name:   "FTP",
			target: "ftp://127.0.0.1",
			want:   false,
		},
		{
			name:   "URL with empty scheme (IP)",
			target: "127.0.0.1:8080",
			want:   false,
		},
		{
			name:   "URL with empty scheme (Hostname)",
			target: "localhost:8080",
			want:   false,
		},
		{
			name:   "Path",
			target: "/etc/passwd",
			want:   false,
		},
		{
			name:   "IP",
			target: "127.0.0.1",
			want:   false,
		},
		{
			name:   "Garbage",
			target: "31337",
			want:   false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := IsWebAddress(tt.target)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsDockerImage(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{
			name:   "With registry",
			target: "registry.hub.docker.com:5500/metasploitframework/metasploit-framework:latest",
			want:   true,
		},
		{
			name:   "Without tag",
			target: "registry.hub.docker.com/metasploitframework/metasploit-framework",
			want:   true,
		},
		{
			name:   "Without registry",
			target: "metasploitframework/metasploit-framework:latest",
			want:   false,
		},
		{
			name:   "URL",
			target: "https://registry.hub.docker.com/metasploitframework/metasploit-framework",
			want:   false,
		},
		{
			name:   "3 parts path registry",
			target: "registry.hub.docker.com/hdmoore/metasploitframework/metasploit-framework",
			want:   true,
		},
		{
			name:   "Single path registry",
			target: "registry.hub.docker.com/metasploit-framework",
			want:   true,
		},
		{
			name:   "Path",
			target: "/etc/passwd",
			want:   false,
		},
		{
			name:   "IP",
			target: "127.0.0.1",
			want:   false,
		},
		{
			name:   "IPRange",
			target: "192.0.2.1/32",
			want:   false,
		},
		{
			name:   "Garbage",
			target: "31337",
			want:   false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := IsDockerImage(tt.target)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsAWSARN(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{
			name:   "AWS ARN Account",
			target: "arn:aws:iam::123456789012:root",
			want:   true,
		},
		{
			name:   "AWS ARN S3",
			target: "arn:aws:s3:::my_corporate_bucket/Development/*",
			want:   true,
		},
		{
			name:   "AWS ARN VPC",
			target: "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0e9801d129EXAMPLE",
			want:   true,
		},
		{
			name:   "IP Path Web Address",
			target: "http://127.0.0.1/path/to/directory",
			want:   false,
		},
		{
			name:   "Docker Image",
			target: "registry.hub.docker.com/metasploitframework/metasploit-framework",
			want:   false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := IsAWSARN(tt.target)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsAWSAccount(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{
			name:   "AWS ARN Account",
			target: "arn:aws:iam::123456789012:root",
			want:   true,
		},
		{
			name:   "AWS ARN IAM",
			target: "arn:aws:iam::123456789012:user/root",
			want:   false,
		},
		{
			name:   "AWS ARN S3",
			target: "arn:aws:s3:::bucket_name/key_name",
			want:   false,
		},
		{
			name:   "AWS ARN VPC",
			target: "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0e9801d129EXAMPLE",
			want:   false,
		},
		{
			name:   "invalid AWS ARN",
			target: "arn:iam::123456789012:root",
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAWSAccount(tt.target)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsGitRepository(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{
			name:   "Github HTTPS",
			target: "https://github.com/user/project.git",
			want:   true,
		},
		{
			name:   "Github HTTP",
			target: "http://github.com/user/project.git",
			want:   true,
		},
		{
			name:   "IP SSH",
			target: "git@192.168.101.127:user/project.git",
			want:   true,
		},
		{
			name:   "IP HTTPS",
			target: "https://192.168.101.127/user/project.git",
			want:   true,
		},
		{
			name:   "IP HTTP",
			target: "http://192.168.101.127/user/project.git",
			want:   true,
		},
		{
			name:   "Host Port User Path SSH",
			target: "ssh://user@host.xz:port/path/to/repo.git/",
			want:   true,
		},
		{
			name:   "Host User Path SSH",
			target: "ssh://user@host.xz/path/to/repo.git/",
			want:   true,
		},
		{
			name:   "Host Port Path SSH",
			target: "ssh://host.xz:port/path/to/repo.git/",
			want:   true,
		},
		{
			name:   "Host Path SSH",
			target: "ssh://host.xz/path/to/repo.git/",
			want:   true,
		},
		{
			name:   "Host User Tilde Path SSH",
			target: "ssh://user@host.xz/~user/path/to/repo.git/",
			want:   true,
		},
		{
			name:   "Host Tilde Path SSH",
			target: "ssh://host.xz/~user/path/to/repo.git/",
			want:   true,
		},
		{
			name:   "Host User Lone Tilde Path SSH",
			target: "ssh://user@host.xz/~/path/to/repo.git",
			want:   true,
		},
		{
			name:   "Host Lone Tilde Path SSH",
			target: "ssh://host.xz/~/path/to/repo.git",
			want:   true,
		},
		{
			name:   "Host Path Git",
			target: "git://host.xz/path/to/repo.git/",
			want:   true,
		},
		{
			name:   "Host Tilde Path Git",
			target: "git://host.xz/~user/path/to/repo.git/",
			want:   true,
		},
		{
			name:   "Host Path HTTP",
			target: "http://host.xz/path/to/repo.git/",
			want:   true,
		},
		{
			name:   "Host Path HTTPS",
			target: "https://host.xz/path/to/repo.git/",
			want:   true,
		},
		{
			name:   "Absolute Path",
			target: "/path/to/repo.git/",
			want:   false,
		},
		{
			name:   "Relative Path",
			target: "path/to/repo.git/",
			want:   false,
		},
		{
			name:   "Tilde Path",
			target: "~/path/to/repo.git",
			want:   false,
		},
		{
			name:   "Absolute Path File Protocol",
			target: "file:///path/to/repo.git/",
			want:   false,
		},
		{
			name:   "Tilde Path File Protocol",
			target: "file://~/path/to/repo.git/",
			want:   false,
		},
		{
			name:   "User Host Absolute Path SSH URI",
			target: "user@host.xz:/path/to/repo.git/",
			want:   false,
		},
		{
			name:   "User Host Relative Path SSH URI",
			target: "user@host.xz:path/to/repo.git",
			want:   false,
		},
		{
			name:   "Host Path SSH URI",
			target: "host.xz:/path/to/repo.git/",
			want:   false,
		},
		{
			name:   "User Host Tilde Path SSH URI",
			target: "user@host.xz:~user/path/to/repo.git/",
			want:   false,
		},
		{
			name:   "Host Tilde Path SSH URI",
			target: "host.xz:~user/path/to/repo.git/",
			want:   false,
		},
		{
			name:   "Host Path SSH URI",
			target: "host.xz:path/to/repo.git",
			want:   false,
		},
		{
			name:   "Rsync",
			target: "rsync://host.xz/path/to/repo.git/",
			want:   false,
		},
		{
			name:   "Host Web Address",
			target: "https://www.adevinta.com",
			want:   false,
		},
		{
			name:   "Host Path Web Address",
			target: "https://www.adevinta.com/path/to/directory",
			want:   false,
		},
		{
			name:   "IP Web Address",
			target: "http://127.0.0.1",
			want:   false,
		},
		{
			name:   "IP Path Web Address",
			target: "http://127.0.0.1/path/to/directory",
			want:   false,
		},
		{
			name:   "AWS ARN",
			target: "arn:aws:iam::123456789012:root",
			want:   false,
		},
		{
			name:   "Docker Image",
			target: "registry.hub.docker.com/metasploitframework/metasploit-framework",
			want:   false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := IsGitRepository(tt.target)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

/*
//   Valid: registry.hub.docker.com/metasploitframework/metasploit-framework:latest
//   Valid: registry.hub.docker.com/metasploitframework/metasploit-framework
//   Valid: registry.hub.docker.com/library/debian
//   Valid: localhost:5500/library/debian
//   Not valid: metasploitframework/metasploit-framework:latest
//   Not valid: metasploitframework/metasploit-framework
//   Not valid: debian
*/
func TestIsDomainName(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		want    bool
		wantErr bool
	}{
		{
			name:   "Domain",
			target: "adevinta.com",
			want:   true,
		},
		{
			name:   "Hostname",
			target: "www.adevinta.com",
			want:   false,
		},
		{
			name:   "Garbage",
			target: "31337",
			want:   false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsDomainName(tt.target)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
			if (tt.wantErr && err == nil) || (!tt.wantErr && err != nil) {
				t.Errorf("got error %v, want error %v", err != nil, tt.wantErr)
			}
		})
	}
}

func TestIsHostname(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		want    bool
		wantErr bool
	}{
		{
			name:   "Domain",
			target: "adevinta.com",
			want:   true,
		},
		{
			name:   "Hostname",
			target: "www.adevinta.com",
			want:   true,
		},
		{
			name:   "IP",
			target: "127.0.0.1",
			want:   false,
		},
		{
			name:   "Garbage",
			target: "31337",
			want:   false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := IsHostname(tt.target)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsHostnameNoDnsResolution(t *testing.T) {
	tests := []struct {
		name    string
		target  string
		want    bool
		wantErr bool
	}{
		{
			name:   "Domain",
			target: "adevinta.com",
			want:   true,
		},
		{
			name:   "Hostname",
			target: "www.adevinta.com",
			want:   true,
		},
		{
			name:   "IP",
			target: "127.0.0.1",
			want:   false,
		},
		{
			name:   "Garbage",
			target: "31337",
			want:   false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := IsHostnameNoDnsResolution(tt.target)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsGCPProjectID(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   bool
	}{
		{
			name:   "GCP Project ID with length equal to or greater than 6 characters",
			target: "rabbit",
			want:   true,
		},
		{
			name:   "GCP Project ID length should not be less than 6 characters",
			target: "hello",
			want:   false,
		},
		{
			name:   "GCP Project ID with length equal to or less than 30 characters",
			target: "bagase-crucible-bubble-gorilla",
			want:   true,
		},
		{
			name:   "GCP Project ID length should not be greater than 30 characters",
			target: "thalamus-instinct-teaching-bemadden-word",
			want:   false,
		},
		{
			name:   "GCP Project ID should only contain lowercase ASCII letters",
			target: "macabre-MONOXIDE-bluish-biped",
			want:   false,
		},
		{
			name:   "GCP Project ID should not start with numbers",
			target: "007bond",
			want:   false,
		},
		{
			name:   "GCP Project ID should only end with letters or digits",
			target: "inherent-derris-",
			want:   false,
		},
		{
			name:   "GCP Project ID can only have hyphens and symbols",
			target: "feebly-chrome_belittle-eyebrow",
			want:   false,
		},
		{
			name:   "AWS ARN Account",
			target: "arn:aws:iam::123456789012:root",
			want:   false,
		},
		{
			name:   "IP Path Web Address",
			target: "http://127.0.0.1/path/to/directory",
			want:   false,
		},
		{
			name:   "Docker Image",
			target: "registry.hub.docker.com/metasploitframework/metasploit-framework",
			want:   false,
		},
		{
			name:   "WebAddress",
			target: "http://localhost:1234/",
			want:   false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := IsGCPProjectID(tt.target)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDetectAssetTypes(t *testing.T) {
	var tests = []struct {
		name           string
		identifier     string
		wantAssetTypes []AssetType
		wantNilErr     bool
	}{
		{
			name:           "valid AWS account",
			identifier:     "arn:aws:iam::123456789012:root",
			wantAssetTypes: []AssetType{AWSAccount},
			wantNilErr:     true,
		},
		{
			name:           "invalid AWS account",
			identifier:     "arn:aws:s3:::bucket_name/key_name",
			wantAssetTypes: nil,
			wantNilErr:     true,
		},
		{
			name:           "valid IP",
			identifier:     "192.0.2.1",
			wantAssetTypes: []AssetType{IP},
			wantNilErr:     true,
		},
		{
			name:           "valid single IP CIDR",
			identifier:     "192.0.2.1/32",
			wantAssetTypes: []AssetType{IP},
			wantNilErr:     true,
		},
		{
			name:           "valid IP range",
			identifier:     "192.0.2.0/24",
			wantAssetTypes: []AssetType{IPRange},
			wantNilErr:     true,
		},
		{
			name:           "valid domain name",
			identifier:     "vulcan.mpi-internal.com",
			wantAssetTypes: []AssetType{DomainName},
			wantNilErr:     true,
		},
		{
			name:           "valid hostname and domain",
			identifier:     "adevinta.com",
			wantAssetTypes: []AssetType{Hostname, DomainName},
			wantNilErr:     true,
		},
		{
			name:           "valid hostname",
			identifier:     "www.adevinta.com",
			wantAssetTypes: []AssetType{Hostname},
			wantNilErr:     true,
		},
		{
			name:           "invalid hostname",
			identifier:     "not.a.host.name",
			wantAssetTypes: nil,
			wantNilErr:     true,
		},
		{
			name:           "valid docker image",
			identifier:     "containers.adevinta.com/vulcan/application:5.5.2",
			wantAssetTypes: []AssetType{DockerImage},
			wantNilErr:     true,
		},
		{
			name:           "valid docker image external registry",
			identifier:     "registry-1.docker.io/library/postgres:latest",
			wantAssetTypes: []AssetType{DockerImage},
			wantNilErr:     true,
		},
		{
			name:           "valid docker image using docker.io",
			identifier:     "docker.io/library/busybox",
			wantAssetTypes: []AssetType{DockerImage},
			wantNilErr:     true,
		},
		{
			name:           "valid docker image ghcr registry",
			identifier:     "ghcr.io/puppeteer/puppeteer",
			wantAssetTypes: []AssetType{DockerImage},
			wantNilErr:     true,
		},
		{
			name:           "invalid docker image",
			identifier:     "finntech/docker-elasticsearch-kubernetes",
			wantAssetTypes: nil,
			wantNilErr:     true,
		},
		{
			name:           "valid hostname and web address",
			identifier:     "https://www.example.com",
			wantAssetTypes: []AssetType{Hostname, WebAddress},
			wantNilErr:     true,
		},
		{
			name:           "valid docker image v2 spec",
			identifier:     "registry-1.docker.io/artifact",
			wantAssetTypes: []AssetType{DockerImage},
			wantNilErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.identifier, func(t *testing.T) {
			got, err := DetectAssetTypes(tt.identifier)
			if (err == nil) != tt.wantNilErr {
				t.Errorf("unexpected error value: %v", err)
			}

			if diff := cmp.Diff(tt.wantAssetTypes, got); diff != "" {
				t.Errorf("configs mismatch (-want +got):\n%v", diff)
			}
		})
	}
}

func TestAssetType_IsValid(t *testing.T) {
	tests := []struct {
		name string
		at   AssetType
		want bool
	}{
		{
			name: "valid",
			at:   Hostname,
			want: true,
		},
		{
			name: "invalid",
			at:   AssetType("invalid"),
			want: false,
		},
		{
			name: "zero value",
			at:   AssetType(""),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.at.IsValid(); got != tt.want {
				t.Errorf("unexpected value: %v", got)
			}
		})
	}
}
