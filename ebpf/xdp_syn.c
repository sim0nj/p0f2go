#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

struct event {
	__u8 ttl;
	__u16 win;
	__u16 mss;
	__u32 opts;
	__u8 ecn;
	__u32 sip;
	__u32 dip;
	__u16 sport;
	__u16 dport;
} __attribute__((packed));

static __always_inline int parse(struct xdp_md *ctx) {
	void *pos = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = pos;
	if (pos + sizeof(*eth) > end) return XDP_PASS;
	pos += sizeof(*eth);
	if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
	struct iphdr iph;
	if (pos + sizeof(iph) > end) return XDP_PASS;
	__builtin_memcpy(&iph, pos, sizeof(iph));
	if (iph.version != 4) return XDP_PASS;
	if (iph.protocol != IPPROTO_TCP) return XDP_PASS;
	__u32 ihl = iph.ihl * 4;
	if (ihl < sizeof(iph)) ihl = sizeof(iph);
	if ((char *)pos + ihl > (char *)end) return XDP_PASS;
	pos = (char *)pos + ihl;
	struct tcphdr tcph;
	if (pos + sizeof(tcph) > end) return XDP_PASS;
	__builtin_memcpy(&tcph, pos, sizeof(tcph));
	if (!tcph.syn || tcph.ack) return XDP_PASS;
	__u32 doff = tcph.doff * 4;
	if (doff < sizeof(tcph)) doff = sizeof(tcph);
	if ((char *)pos + doff > (char *)end) return XDP_PASS;
	struct event e = {};
	e.ttl = iph.ttl;
	e.win = bpf_ntohs(tcph.window);
	e.sip = bpf_ntohl(iph.saddr);
	e.dip = bpf_ntohl(iph.daddr);
	e.sport = bpf_ntohs(tcph.source);
	e.dport = bpf_ntohs(tcph.dest);
	__u8 *opt = (void *)((char *)pos + sizeof(tcph));
	__u8 *opt_end = (void *)((char *)pos + doff);
	while (opt < opt_end) {
		__u8 kind = *opt;
		if (kind == 0) break;
		if (kind == 1) { e.opts |= (1<<4); opt++; continue; }
		if (opt + 1 >= opt_end) break;
		__u8 len = *(opt + 1);
		if (len < 2 || opt + len > opt_end) break;
		if (kind == 2 && len == 4) { e.mss = bpf_ntohs(*(__u16 *)(opt + 2)); e.opts |= (1<<0); }
		if (kind == 3) { e.opts |= (1<<1); }
		if (kind == 4) { e.opts |= (1<<2); }
		if (kind == 8 && len == 10) { e.opts |= (1<<3); }
		opt += len;
	}
	if (tcph.ece) e.ecn = 1;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return XDP_PASS;
}

SEC("xdp")
int xdp_main(struct xdp_md *ctx) { return parse(ctx); }

char _license[] SEC("license") = "GPL";
