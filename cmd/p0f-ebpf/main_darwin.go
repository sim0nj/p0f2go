//go:build darwin

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sim0nj/p0f2go/p0f"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

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
	flag.StringVar(&iface, "iface", "en0", "net interface")
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
		iface = "en0"
	}
	handle, err := pcap.OpenLive(iface, 65535, true, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer handle.Close()
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
	filter := "tcp"
	if dport > 0 {
		filter = fmt.Sprintf("tcp and dst port %d", dport)
	}
	// 排除过滤在用户态完成，BPF 仅保留最小 tcp 过滤与 dport（避免包含语义误解）
	if err := handle.SetBPFFilter(filter); err != nil {
		fmt.Println(err)
		return
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
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	var ts int64
	var count int
	if sample < 1.0 {
		rand.Seed(time.Now().UnixNano())
	}
	for {
		select {
		case <-sig:
			return
		case pkt, ok := <-packetSource.Packets():
			if !ok {
				return
			}
			ipLayer := pkt.Layer(layers.LayerTypeIPv4)
			tcpLayer := pkt.Layer(layers.LayerTypeTCP)
			if ipLayer == nil || tcpLayer == nil {
				continue
			}
			ip, _ := ipLayer.(*layers.IPv4)
			tcp, _ := tcpLayer.(*layers.TCP)
			if ip == nil || tcp == nil {
				continue
			}
			if srcIPHost != nil {
				if srcIPNet != nil {
					if srcIPNet.Contains(ip.SrcIP) {
						continue
					}
				} else if ip.SrcIP.Equal(srcIPHost) {
					continue
				}
			}
			if dstIPHost != nil {
				if dstIPNet != nil {
					if dstIPNet.Contains(ip.DstIP) {
						continue
					}
				} else if ip.DstIP.Equal(dstIPHost) {
					continue
				}
			}
			if !tcp.SYN || tcp.ACK {
				continue
			}
			ttl := int(ip.TTL)
			if len(tcp.Contents) < 20 {
				continue
			}
			hlen := int(tcp.DataOffset) * 4
			if hlen < 20 || len(tcp.Contents) < hlen {
				continue
			}
			opts := tcp.Contents[20:hlen]
			win := uint16(tcp.Window)
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
			o, mss, wscale := p0f.ParseTCPOptions(opts)
			meta := p0f.PacketMeta{TTL: ttl, Win: win, MSS: mss, WScale: wscale, Options: o, ECN: tcp.ECE}
			lbl := p0f.Detect(meta)
			if jsonOut {
				srcIP := ip.SrcIP.String()
				dstIP := ip.DstIP.String()
				srcPort := int(tcp.SrcPort)
				dstPort := int(tcp.DstPort)
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
				}{Label: lbl, TTL: meta.TTL, Win: meta.Win, MSS: meta.MSS, Options: meta.Options, ECN: meta.ECN, DPort: dstPort, SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort}
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
}
