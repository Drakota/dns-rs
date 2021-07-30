# dns-rs

<h4 align="center">
dns-rs is a small (and incomplete) DNS server and protocol parser made from scratch in Rust with the intent to learn the language.
</h4>

## Crates
|Crate|Description|
|-|-|
|parser|DNS protocol parser library, used by the other crates|
|proxy|Proxy server which forwards queries to another caching server|
|server|Caching server holding DNS records implementing recursive lookups|