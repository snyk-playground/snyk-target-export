package internal

import "testing"

func TestIsAllowedNextURL(t *testing.T) {
	tests := []struct {
		name        string
		nextURL     string
		allowedHost string
		want        bool
	}{
		// Relative URLs are always allowed
		{"relative path", "/rest/orgs/abc/projects?page=2", "api.snyk.io", true},
		{"relative root", "/", "api.snyk.io", true},

		// Same host is allowed
		{"same host https", "https://api.snyk.io/rest/orgs/abc/projects", "api.snyk.io", true},

		// Subdomain of allowed host is allowed
		{"subdomain", "https://app.api.snyk.io/something", "api.snyk.io", true},

		// EU tenant
		{"eu tenant", "https://api.eu.snyk.io/rest/orgs/abc/projects", "api.eu.snyk.io", true},

		// Different host is blocked
		{"different host", "https://evil.com/rest/orgs/abc/projects", "api.snyk.io", false},

		// HTTP (not HTTPS) is blocked
		{"http not https", "http://api.snyk.io/rest/orgs/abc/projects", "api.snyk.io", false},

		// Empty URL is blocked
		{"empty url", "", "api.snyk.io", false},

		// Tricky subdomain that doesn't actually match
		{"fake subdomain", "https://notapi.snyk.io/path", "api.snyk.io", false},

		// Host suffix attack (evilapi.snyk.io matches .api.snyk.io -- but not api.snyk.io directly)
		{"suffix attack", "https://evilapi.snyk.io/path", "api.snyk.io", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAllowedNextURL(tt.nextURL, tt.allowedHost)
			if got != tt.want {
				t.Errorf("isAllowedNextURL(%q, %q) = %v, want %v", tt.nextURL, tt.allowedHost, got, tt.want)
			}
		})
	}
}
