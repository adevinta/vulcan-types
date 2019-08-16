package types

import "testing"

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

func TestIsURL(t *testing.T) {
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
			got := IsURL(tt.target)
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
			got := IsDockerImage(tt.target)
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
