//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"p0f2go/p0f"
)

func htons(v uint16) uint16 { return (v<<8)&0xff00 | v>>8 }

func main() {
	var iface string
	var jsonOut bool
	var rate int
	var sample float64
	var dport int
	var srcFilter string
	var dstFilter string
	var metrics bool
	var metricsAddr string
	flag.StringVar(&iface, "iface", "", "net interface")
	flag.BoolVar(&jsonOut, "json", false, "json output")
	flag.IntVar(&rate, "rate", 0, "max events per second")
	flag.Float64Var(&sample, "sample", 1.0, "sampling ratio 0..1")
	flag.IntVar(&dport, "dport", 0, "destination tcp port filter")
	flag.StringVar(&srcFilter, "src", "", "exclude source ip (host or CIDR)")
	flag.StringVar(&dstFilter, "dst", "", "exclude destination ip (host or CIDR)")
	flag.BoolVar(&metrics, "metrics", false, "enable /metrics")
	flag.StringVar(&metricsAddr, "metrics.addr", ":9100", "metrics listen addr")
	flag.Parse()
	if iface == "" {
		iface = os.Getenv("IFACE")
	}
	if iface == "" {
		iface = "eth0"
	}
	i, err := net.InterfaceByName(iface)
	if err != nil {
		fmt.Println(err)
		return
	}
	var srcIPHost net.IP
	var srcIPNet *net.IPNet
	if srcFilter != "" {
		if strings.Contains(srcFilter, "/") {
			ip, ipn, err := net.ParseCIDR(srcFilter)
			if err != nil {
				fmt.Println("invalid src filter")
				return
			}
			srcIPHost = ip
			srcIPNet = ipn
		} else {
			srcIPHost = net.ParseIP(srcFilter)
			if srcIPHost == nil {
				fmt.Println("invalid src filter")
				return
			}
		}
		srcIPHost = srcIPHost.To4()
		if srcIPHost == nil {
			fmt.Println("invalid src filter")
			return
		}
	}
	var dstIPHost net.IP
	var dstIPNet *net.IPNet
	if dstFilter != "" {
		if strings.Contains(dstFilter, "/") {
			ip, ipn, err := net.ParseCIDR(dstFilter)
			if err != nil {
				fmt.Println("invalid dst filter")
				return
			}
			dstIPHost = ip
			dstIPNet = ipn
		} else {
			dstIPHost = net.ParseIP(dstFilter)
			if dstIPHost == nil {
				fmt.Println("invalid dst filter")
				return
			}
		}
		dstIPHost = dstIPHost.To4()
		if dstIPHost == nil {
			fmt.Println("invalid dst filter")
			return
		}
	}
	type mstate struct {
		mu            sync.Mutex
		byLabel       map[string]*int64
		droppedRate   int64
		droppedSample int64
		outputErrors  int64
		rateLimit     int64
		samplingRatio float64
	}
	var ms mstate
	ms.byLabel = make(map[string]*int64)
	ms.rateLimit = int64(rate)
	ms.samplingRatio = sample
	incr := func(lbl string) {
		ms.mu.Lock()
		p, ok := ms.byLabel[lbl]
		if !ok {
			var v int64
			p = &v
			ms.byLabel[lbl] = p
		}
		ms.mu.Unlock()
		atomic.AddInt64(p, 1)
	}
	if metrics {
		http.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
			var b strings.Builder
			ms.mu.Lock()
			for k, p := range ms.byLabel {
				b.WriteString("p0f_events_total{label=\"")
				b.WriteString(k)
				b.WriteString("\"} ")
				b.WriteString(fmt.Sprintf("%d\n", atomic.LoadInt64(p)))
			}
			ms.mu.Unlock()
			b.WriteString(fmt.Sprintf("p0f_events_dropped_total{reason=\"rate_limit\"} %d\n", atomic.LoadInt64(&ms.droppedRate)))
			b.WriteString(fmt.Sprintf("p0f_events_dropped_total{reason=\"sample\"} %d\n", atomic.LoadInt64(&ms.droppedSample)))
			b.WriteString(fmt.Sprintf("p0f_output_errors_total{type=\"json\"} %d\n", atomic.LoadInt64(&ms.outputErrors)))
			b.WriteString(fmt.Sprintf("p0f_sampling_ratio %g\n", ms.samplingRatio))
			b.WriteString(fmt.Sprintf("p0f_rate_limit %d\n", ms.rateLimit))
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			_, _ = w.Write([]byte(b.String()))
		})
		go func() {
			_ = http.ListenAndServe(metricsAddr, nil)
		}()
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0800)))
	if err != nil {
		fmt.Println(err)
		return
	}
	defer syscall.Close(fd)
	sll := &syscall.SockaddrLinklayer{Protocol: htons(0x0800), Ifindex: i.Index}
	if err := syscall.Bind(fd, sll); err != nil {
		fmt.Println(err)
		return
	}
	buf := make([]byte, 65536)
	var ts int64
	var count int
	if sample < 1.0 {
		rand.Seed(time.Now().UnixNano())
	}
	for {
		n, err := syscall.Read(fd, buf)
		if err != nil || n < 54 {
			continue
		}
		eth := buf[:14]
		if binary.BigEndian.Uint16(eth[12:14]) != 0x0800 {
			continue
		}
		ip := buf[14:]
		if len(ip) < 20 {
			continue
		}
		if ip[0]>>4 != 4 {
			continue
		}
		ihl := int(ip[0]&0x0f) * 4
		if len(ip) < ihl {
			continue
		}
		if ip[9] != 6 {
			continue
		}
		srcIP := net.IP(ip[12:16])
		dstIP := net.IP(ip[16:20])
		if srcIPHost != nil {
			if srcIPNet != nil {
				if srcIPNet.Contains(srcIP) {
					continue
				}
			} else if srcIP.Equal(srcIPHost) {
				continue
			}
		}
		if dstIPHost != nil {
			if dstIPNet != nil {
				if dstIPNet.Contains(dstIP) {
					continue
				}
			} else if dstIP.Equal(dstIPHost) {
				continue
			}
		}
		ttl := int(ip[8])
		tcp := ip[ihl:]
		if len(tcp) < 20 {
			continue
		}
		if dport > 0 {
			dp := int(binary.BigEndian.Uint16(tcp[2:4]))
			if dp != dport {
				continue
			}
		}
		dataOffset := int((tcp[12] >> 4) * 4)
		if len(tcp) < dataOffset {
			continue
		}
		flags := tcp[13]
		if flags&0x02 == 0 || flags&0x10 != 0 {
			continue
		}
		if sample < 1.0 && rand.Float64() >= sample {
			atomic.AddInt64(&ms.droppedSample, 1)
			continue
		}
		if rate > 0 {
			now := time.Now().Unix()
			if now != ts {
				ts = now
				count = 0
			}
			if count >= rate {
				atomic.AddInt64(&ms.droppedRate, 1)
				continue
			}
			count++
		}
		win := binary.BigEndian.Uint16(tcp[14:16])
		opts := tcp[20:dataOffset]
		o, mss, wscale := p0f.ParseTCPOptions(opts)
		meta := p0f.PacketMeta{TTL: ttl, Win: win, MSS: mss, WScale: wscale, Options: o, ECN: flags&0x40 != 0}
		lbl := p0f.Detect(meta)
		if jsonOut {
			srcIPStr := srcIP.String()
			dstIPStr := dstIP.String()
			srcPort := int(binary.BigEndian.Uint16(tcp[0:2]))
			dstPort := int(binary.BigEndian.Uint16(tcp[2:4]))
			out := struct {
				Label   string   `json:"label"`
				TTL     int      `json:"ttl"`
				Win     uint16   `json:"win"`
				MSS     uint16   `json:"mss"`
				Options []string `json:"options"`
				ECN     bool     `json:"ecn"`
				DPort   int      `json:"dport"`
				SrcIP   string   `json:"src_ip"`
				DstIP   string   `json:"dst_ip"`
				SrcPort int      `json:"src_port"`
				DstPort int      `json:"dst_port"`
			}{Label: lbl, TTL: meta.TTL, Win: meta.Win, MSS: meta.MSS, Options: meta.Options, ECN: meta.ECN, DPort: dstPort, SrcIP: srcIPStr, DstIP: dstIPStr, SrcPort: srcPort, DstPort: dstPort}
			b, err := json.Marshal(out)
			if err != nil {
				atomic.AddInt64(&ms.outputErrors, 1)
			} else {
				fmt.Println(string(b))
			}
		} else {
			fmt.Println(lbl)
		}
		incr(lbl)
	}
}
