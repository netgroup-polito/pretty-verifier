module test_pretty_verifier

go 1.25.0

require (
	github.com/cilium/ebpf v0.20.0
	github.com/netgroup-polito/pretty-verifier/lib/go v0.0.0-00010101000000-000000000000
)

require golang.org/x/sys v0.37.0 // indirect

replace github.com/netgroup-polito/pretty-verifier/lib/go => ../../../lib/go
