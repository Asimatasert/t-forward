module t-forward-web

go 1.26

// Standard-library patch floor: go1.26.9/1.26.10 fix stdlib vulnerabilities
// reachable from the daemon (net/textproto, crypto/x509, net/http, ...).
toolchain go1.26.10
