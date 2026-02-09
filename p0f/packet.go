package p0f

import "encoding/binary"

type PacketMeta struct {
	TTL     int
	Win     uint16
	MSS     uint16
	WScale  int
	Options []string
	ECN     bool
}

func ParseTCPOptions(b []byte) (opts []string, mss uint16, wscale int) {
	i := 0
	wscale = 0
	for i < len(b) {
		o := b[i]
		if o == 0 {
			break
		}
		if o == 1 {
			opts = append(opts, "nop")
			i++
			continue
		}
		if i+1 >= len(b) {
			break
		}
		l := int(b[i+1])
		if l < 2 || i+l > len(b) {
			break
		}
		switch o {
		case 2:
			if l == 4 {
				mss = binary.BigEndian.Uint16(b[i+2 : i+4])
				opts = append(opts, "mss")
			}
		case 3:
			if l == 3 {
				wscale = int(b[i+2])
			}
			opts = append(opts, "ws")
		case 4:
			opts = append(opts, "sok")
		case 8:
			if l == 10 {
				opts = append(opts, "ts")
			}
		}
		i += l
	}
	return
}
