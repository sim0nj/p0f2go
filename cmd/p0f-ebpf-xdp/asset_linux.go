//go:build linux

package main

import _ "embed"

//go:embed ebpf/xdp_syn.o
var xdpObj []byte
