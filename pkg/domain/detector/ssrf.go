package detector

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/m-mizutani/semgate-example/pkg/domain/model"
)

// SSRF models a URL-preview endpoint. It fires when the requested URL targets
// something a server-side fetcher must never reach: a non-HTTP scheme, or a
// host that resolves to loopback, link-local (cloud metadata), or a private
// range. It NEVER performs the fetch and never resolves DNS; only literal IPs
// and well-known hostnames are classified.
type SSRF struct{}

// NewSSRF builds the SSRF detector.
func NewSSRF() *SSRF { return &SSRF{} }

// forbiddenSchemes are non-HTTP schemes an SSRF payload uses to reach the local
// host or internal services.
var forbiddenSchemes = map[string]struct{}{
	"file": {}, "gopher": {}, "dict": {}, "ftp": {}, "ldap": {}, "jar": {},
}

// Inspect evaluates the requested URL.
func (d *SSRF) Inspect(rawURL string) model.Verdict {
	trimmed := strings.TrimSpace(rawURL)
	u, err := url.Parse(trimmed)
	if err != nil {
		return model.NotFired()
	}

	scheme := strings.ToLower(u.Scheme)
	if _, bad := forbiddenSchemes[scheme]; bad {
		return model.Fire(model.CategorySSRF, "ssrf_forbidden_scheme",
			fmt.Sprintf("scheme %q can reach local resources", scheme))
	}

	host := u.Hostname()
	if host == "" {
		return model.NotFired()
	}

	if strings.EqualFold(host, "localhost") {
		return model.Fire(model.CategorySSRF, "ssrf_localhost", "host is localhost")
	}

	ip := net.ParseIP(host)
	if ip == nil {
		// A named public host is benign for this range's purpose.
		return model.NotFired()
	}

	switch classifyIP(ip) {
	case "metadata":
		return model.Fire(model.CategorySSRF, "ssrf_metadata",
			fmt.Sprintf("host %s is the cloud metadata address", host))
	case "loopback":
		return model.Fire(model.CategorySSRF, "ssrf_loopback",
			fmt.Sprintf("host %s is a loopback address", host))
	case "link_local":
		return model.Fire(model.CategorySSRF, "ssrf_link_local",
			fmt.Sprintf("host %s is a link-local address", host))
	case "private":
		return model.Fire(model.CategorySSRF, "ssrf_private",
			fmt.Sprintf("host %s is a private-range address", host))
	}
	return model.NotFired()
}

// metadataIP is the cloud instance metadata endpoint (link-local, but called
// out specifically because it is the canonical SSRF target).
var metadataIP = net.ParseIP("169.254.169.254")

func classifyIP(ip net.IP) string {
	if ip.Equal(metadataIP) {
		return "metadata"
	}
	if ip.IsLoopback() {
		return "loopback"
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return "link_local"
	}
	if ip.IsPrivate() {
		return "private"
	}
	return "public"
}
