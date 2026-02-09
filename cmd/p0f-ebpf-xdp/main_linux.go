//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
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

	"p0f2go/p0f"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

type event struct {
	TTL   uint8
	Win   uint16
	MSS   uint16
	Opts  uint32
	ECN   uint8
	Sip   uint32
	Dip   uint32
	Sport uint16
	Dport uint16
} // packed in C

func optsToSlice(mask uint32) []string {
	var o []string
	if mask&(1<<4) != 0 {
		o = append(o, "nop")
	}
	if mask&(1<<0) != 0 {
		o = append(o, "mss")
	}
	if mask&(1<<1) != 0 {
		o = append(o, "ws")
	}
	if mask&(1<<2) != 0 {
		o = append(o, "sok")
	}
	if mask&(1<<3) != 0 {
		o = append(o, "ts")
	}
	return o
}

func main() {
	var iface string
	var jsonOut bool
	var rate int
	var sample float64
	var sport, dport int
	var srcFilter string
	var dstFilter string
	var metrics bool
	var metricsAddr string
	flag.StringVar(&iface, "iface", "", "net interface")
	flag.BoolVar(&jsonOut, "json", false, "json output")
	flag.IntVar(&rate, "rate", 0, "max events per second")
	flag.Float64Var(&sample, "sample", 1.0, "sampling ratio 0..1")
	flag.IntVar(&sport, "sport", 0, "source tcp port filter")
	flag.IntVar(&dport, "dport", 0, "destination tcp port filter")
	flag.StringVar(&srcFilter, "src", "", "exclude source ip (host or CIDR)")
	flag.StringVar(&dstFilter, "dst", "", "exclude destination ip (host or CIDR)")
	flag.BoolVar(&metrics, "metrics", false, "enable /metrics")
	flag.StringVar(&metricsAddr, "metrics.addr", ":9100", "metrics listen addr")
	flag.Parse()
	if iface == "" {
		iface = os.Getenv("IFACE")
	}
	_ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: ^uint64(0), Max: ^uint64(0)})
	if iface == "" {
		iface = "eth0"
	}
	ni, err := net.InterfaceByName(iface)
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
	var spec *ebpf.CollectionSpec
	if _, statErr := os.Stat("ebpf/xdp_syn.o"); statErr == nil {
		spec, err = ebpf.LoadCollectionSpec("ebpf/xdp_syn.o")
	} else if len(xdpObj) > 0 {
		r := bytes.NewReader(xdpObj)
		spec, err = ebpf.LoadCollectionSpecFromReader(r)
	} else {
		err = fmt.Errorf("xdp object not found")
	}
	if err != nil {
		fmt.Println(err)
		return
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer coll.Close()
	prog := coll.Programs["xdp_main"]
	if prog == nil {
		fmt.Println("program not found")
		return
	}
	l, err := link.AttachXDP(link.XDPOptions{Program: prog, Interface: ni.Index})
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()
	events := coll.Maps["events"]
	if events == nil {
		fmt.Println("events map not found")
		return
	}
	rd, err := perf.NewReader(events, 4096)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer rd.Close()
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
		default:
		}
		rec, err := rd.Read()
		if err != nil {
			continue
		}
		var ev event
		if len(rec.RawSample) < 22 {
			continue
		}
		ev.TTL = rec.RawSample[0]
		ev.Win = binary.LittleEndian.Uint16(rec.RawSample[1:3])
		ev.MSS = binary.LittleEndian.Uint16(rec.RawSample[3:5])
		ev.Opts = binary.LittleEndian.Uint32(rec.RawSample[5:9])
		ev.ECN = rec.RawSample[9]
		ev.Sip = binary.LittleEndian.Uint32(rec.RawSample[10:14])
		ev.Dip = binary.LittleEndian.Uint32(rec.RawSample[14:18])
		ev.Sport = binary.LittleEndian.Uint16(rec.RawSample[18:20])
		ev.Dport = binary.LittleEndian.Uint16(rec.RawSample[20:22])
		if sport > 0 && int(ev.Sport) != sport {
			continue
		}
		if dport > 0 && int(ev.Dport) != dport {
			continue
		}
		if srcIPHost != nil {
			sipB := make([]byte, 4)
			binary.BigEndian.PutUint32(sipB, ev.Sip)
			ip := net.IP(sipB)
			if srcIPNet != nil {
				if srcIPNet.Contains(ip) {
					continue
				}
			} else if ip.Equal(srcIPHost) {
				continue
			}
		}
		if dstIPHost != nil {
			dipB := make([]byte, 4)
			binary.BigEndian.PutUint32(dipB, ev.Dip)
			ip := net.IP(dipB)
			if dstIPNet != nil {
				if dstIPNet.Contains(ip) {
					continue
				}
			} else if ip.Equal(dstIPHost) {
				continue
			}
		}
		meta := p0f.PacketMeta{
			TTL:     int(ev.TTL),
			Win:     ev.Win,
			MSS:     ev.MSS,
			WScale:  0,
			Options: optsToSlice(ev.Opts),
			ECN:     ev.ECN != 0,
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
		lbl := p0f.Detect(meta)
		sipB := make([]byte, 4)
		dipB := make([]byte, 4)
		binary.BigEndian.PutUint32(sipB, ev.Sip)
		binary.BigEndian.PutUint32(dipB, ev.Dip)
		src := net.IP(sipB).String()
		dst := net.IP(dipB).String()
		if jsonOut {
			out := struct {
				Label   string   `json:"label"`
				TTL     int      `json:"ttl"`
				Win     uint16   `json:"win"`
				MSS     uint16   `json:"mss"`
				Options []string `json:"options"`
				ECN     bool     `json:"ecn"`
				SrcIP   string   `json:"src_ip"`
				DstIP   string   `json:"dst_ip"`
				SrcPort int      `json:"src_port"`
				DstPort int      `json:"dst_port"`
			}{Label: lbl, TTL: meta.TTL, Win: meta.Win, MSS: meta.MSS, Options: meta.Options, ECN: meta.ECN, SrcIP: src, DstIP: dst, SrcPort: int(ev.Sport), DstPort: int(ev.Dport)}
			b, err := json.Marshal(out)
			if err != nil {
				atomic.AddInt64(&ms.outputErrors, 1)
			} else {
				fmt.Println(string(b))
			}
		} else {
			fmt.Printf("%s src=%s:%d dst=%s:%d\n", lbl, src, ev.Sport, dst, ev.Dport)
		}
		incr(lbl)
	}
}
