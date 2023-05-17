package caddypsl

import (
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"golang.org/x/net/publicsuffix"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("psl", parseCaddyfile)
}

// Handler adds placeholders that return values based on the Public Suffix List, or PSL (https://publicsuffix.org).
// The placeholders can be useful for routing, responses, headers, or any other logic in your server config.
//
// Placeholders are created with these possible input prefixes:
//
// - **`qs.*`** gets a value from the query string with the named key, e.g. for a query string `?foo=example.com`,
// `qs.foo` would refer to the value `example.com`.
// - **`header.*`** gets a value from the header with the named field, e.g. for a header `Host: example.com:1234`,
// `header.Host` refers to the value `example.com`.
//
// For all input values, ports are ignored automatically.
//
// The placeholders created by this handler must then have one of the following output endings:
//
// - **`.is_icann`** returns true if the longest matching suffix is ICANN-managed, or false if the domain is
// privately managed (i.e. not an ICANN ending).
//
// - **`.public_suffix`** returns the "Effective TLD" or the eTLD, which is basically the matching ICANN-managed
// entry in the PSL. For example, the eTLD of `sub.example.com` is `com`, and the eTLD of `foo.bar.com.au` is
// `com.au`. Privately-managed endings are NOT matched by this placeholder, so `foo.blogspot.com` would return
// `com`, not `blogspot.com` even though `blogspot.com` is on the PSL.
//
// - **`.domain_suffix`** is the same as the `.public_suffix` placeholder ending, except that it doesn't
// discriminate ICANN-managed labels. In other words, in `foo.blogspot.com`, this one would return `blogspot.com`.
//
// - **`.registered_domain`** returns the "Effective TLD+1" or "eTLD+1", using only ICANN-managed labels as the
// authority. For example, in `sub.example.com`, the registered domain is `example.com` because the public suffix
// is `com`. In `sub.example.co.uk`, the registered domain is `example.co.uk` because the public suffix is `co.uk`.
// In `foo.blogspot.com`, the registered domain is `blogspot.com` even though `blogspot.com` is itself on the PSL;
// this is because `blogspot.com` is privately-managed, not an ICANN suffix.
//
// - **`.public_registered_domain`** is the same as the `.registered_domain` placeholder, except that it
// only returns a value if the suffix is an ICANN ending. In other words, it returns the registered domain
// only if `is_icann` is true.
//
// Concatenate any of the placeholder prefixes with any of the placeholder endings to use the placeholder.
//
// Examples:
//
// - `{qs.domain.public_suffix}` returns the public suffix of the value in the `domain` query string parameter.
// - `{header.Host.registered_domain}` returns the registered domain of the value in the `Host` header field.
// - `{header.Host.public_registered_domain}` is the same as the previous, but only returns a non-empty value if
// the domain suffix is a public/ICANN-managed ending.
type Handler struct{}

// CaddyModule returns the Caddy module information.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.public_suffix",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	repl.Map(func(key string) (any, bool) {
		if !strings.HasSuffix(key, ".registered_domain") &&
			!strings.HasSuffix(key, ".public_registered_domain") &&
			!strings.HasSuffix(key, ".public_suffix") &&
			!strings.HasSuffix(key, ".domain_suffix") &&
			!strings.HasSuffix(key, ".is_icann") {
			return nil, false
		}

		parts := strings.Split(key, ".")
		if len(parts) < 3 {
			return nil, false
		}

		var host string

		switch parts[0] {
		case "qs":
			host = r.URL.Query().Get(parts[1])
		case "header":
			if strings.ToLower(parts[1]) == "host" {
				host = r.Host
			} else {
				host = r.Header.Get(parts[1])
			}
		default:
			return nil, false
		}

		// it's OK if there's an error here, just assume there was no port
		domain, _, err := net.SplitHostPort(host)
		if err != nil {
			domain = host
		}

		// I think the publicsuffix package API is confusing/misleading.
		// The `PublicSuffix()` function actually returns any matching
		// suffix, even if it's a privately-managed domain ending like
		// blogspot.com. And `EffectiveTLDPlusOne()` ignores the "icann"
		// flag, so I have to roll my own logic here and stick to my
		// own placeholder names that I think make more sense.
		switch parts[2] {
		case "registered_domain":
			return registeredDomain(domain), true

		case "public_registered_domain":
			eTLD, icann := publicsuffix.PublicSuffix(domain)
			if icann {
				return suffixPlusOne(domain, eTLD), true
			}
			return "", true

		case "public_suffix":
			// this placeholder should only return a value if the domain suffix is ICANN-managed,
			// i.e. is a "public" eTLD someone can purchase a domain for from a registrar; we need
			// to trim labels off the domain until we find the ICANN eTLD
			return icannSuffix(domain), true

		case "domain_suffix":
			eTLD, _ := publicsuffix.PublicSuffix(domain)
			return eTLD, true

		case "is_icann":
			_, icann := publicsuffix.PublicSuffix(domain)
			return icann, true
		}

		return nil, false
	})

	return next.ServeHTTP(w, r)
}

// registeredDomain returns the eTLD+1, where the eTLD must be ICANN-managed.
func registeredDomain(domain string) string {
	publicSuffix := icannSuffix(domain)
	return suffixPlusOne(domain, publicSuffix)
}

// suffixPlusOne returns the suffix plus one more label (the next-left just before the suffix).
func suffixPlusOne(domain, suffix string) string {
	if len(suffix) >= len(domain) {
		return ""
	}
	i := len(domain) - len(suffix) - 1
	if domain[i] != '.' {
		return ""
	}
	return domain[strings.LastIndex(domain[:i], ".")+1:]
}

// icannSuffix returns the eTLD that is ICANN-managed; i.e. "foo.blogspot.com" -> "com", even
// though "blogspot.com" is on the PSL.
func icannSuffix(domain string) string {
	for {
		eTLD, icann := publicsuffix.PublicSuffix(domain)
		if icann {
			return eTLD
		}
		// not an ICANN domain, so must be a privately-managed domain if there's a dot
		if strings.IndexByte(eTLD, '.') >= 0 {
			var ok bool
			_, domain, ok = strings.Cut(eTLD, ".")
			if !ok {
				return ""
			}
		}
	}
}

// Interface guards
var _ caddyhttp.MiddlewareHandler = (*Handler)(nil)
