Caddy Public Suffix List (PSL) module
======================================

This module is an HTTP handler that creates placeholders based on the [Public Suffix List (PSL)](https://publicsuffix.org).

:warning: This module is experimental and subject to change.

> [!NOTE]
> This is not an official repository of the [Caddy Web Server](https://github.com/caddyserver) organization.

Placeholders are created with these possible input prefixes:

- **`qs.*`** gets a value from the query string with the named key, e.g. for a query string `?foo=example.com`,
`qs.foo` would refer to the value `example.com`.
- **`header.*`** gets a value from the header with the named field, e.g. for a header `Host: example.com:1234`,
`header.Host` refers to the value `example.com`.

For all input values, ports are ignored automatically.

The placeholders created by this handler must then have one of the following output endings:

- **`.is_icann`** returns true if the longest matching suffix is ICANN-managed, or false if the domain is
privately managed (i.e. not an ICANN ending).

- **`.public_suffix`** returns the "Effective TLD" or the eTLD, which is basically the matching ICANN-managed
entry in the PSL. For example, the eTLD of `sub.example.com` is `com`, and the eTLD of `foo.bar.com.au` is
`com.au`. Privately-managed endings are NOT matched by this placeholder, so `foo.blogspot.com` would return
`com`, not `blogspot.com` even though `blogspot.com` is on the PSL.

- **`.domain_suffix`** is the same as the `.public_suffix` placeholder ending, except that it doesn't
discriminate ICANN-managed labels. In other words, in `foo.blogspot.com`, this one would return `blogspot.com`.

- **`.registered_domain`** returns the "Effective TLD+1" or "eTLD+1", using only ICANN-managed labels as the
authority. For example, in `sub.example.com`, the registered domain is `example.com` because the public suffix
is `com`. In `sub.example.co.uk`, the registered domain is `example.co.uk` because the public suffix is `co.uk`.
In `foo.blogspot.com`, the registered domain is `blogspot.com` even though `blogspot.com` is itself on the PSL;
this is because `blogspot.com` is privately-managed, not an ICANN suffix.

- **`.public_registered_domain`** is the same as the `.registered_domain` placeholder ending, except that it
only returns a value if the suffix is an ICANN ending. In other words, it returns the registered domain
only if `is_icann` is true.

Concatenate any of the placeholder prefixes with any of the placeholder endings to use the placeholder.

Examples:

- `{qs.domain.public_suffix}` returns the public suffix of the value in the `domain` query string parameter.
- `{header.Host.registered_domain}` returns the registered domain of the value in the `Host` header field.
- `{header.Host.public_registered_domain}` is the same as the previous, but only returns a non-empty value if
the domain suffix is a public/ICANN-managed ending.

Example usage:

```
{
	order psl first
}

:1234

psl
respond "
	Public Registered Domain: {header.Host.public_registered_domain}
	Registered Domain: {header.Host.registered_domain}
	Public Suffix: {header.Host.public_suffix}
	Domain Suffix: {header.Host.domain_suffix}
	Is ICANN: {header.Host.is_icann}"
```
