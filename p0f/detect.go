package p0f

import (
	"strconv"
	"strings"
)

func Detect(m PacketMeta) string {
	bestClass := matchP0fSignature(m.TTL, int(m.Win), m.WScale, int(m.MSS), strings.Join(m.Options, ","))
	if bestClass == "" {
		return "Unknown"
	}
	return bestClass
}

func matchP0fSignature(ttlInit int, win int, wscale int, mss int, optLayout string) string {
	if len(Data.Entries) == 0 {
		return ""
	}
	winStr := strconv.Itoa(win)
	if wscale > 0 {
		winStr = winStr + "," + strconv.Itoa(wscale)
	}
	opts := normalizeOpts(strings.Split(strings.ToLower(strings.TrimSpace(optLayout)), ","))
	bestClass := ""
	bestScore := -1.0
	for _, e := range Data.Entries {
		if e.Section != "tcp:request" {
			continue
		}
		for _, sig := range e.Sig {
			ttlSig, winExpr, wscaleExpr, optExpr, ok := parseTcpRequestSig(sig)
			if !ok {
				continue
			}
			score := 0.0
			if e.Label == "" {
				continue
			}
			if ttlMatch(ttlSig, ttlInit) {
				score += 3
			}
			if winExpr == "*" {
				score += 3
			} else {
				exact := winEquals(winExpr, win, mss)
				if exact {
					if wscaleExpr == "" || wscaleExpr == "*" || wscale <= 0 {
						score += 3
					} else if wsEq(wscaleExpr, wscale) {
						score += 3
					} else {
						score += 2
					}
				} else if nearWin(winExpr, win, mss) {
					score += 2
				}
			}
			if winExpr == "*" && mss > 0 {
				score += 1
			} else if strings.HasPrefix(winExpr, "mss*") && mss > 0 {
				score += 2
			}
			sigOpts := normalizeOpts(strings.Split(optExpr, ","))
			if len(sigOpts) > 0 && len(opts) > 0 {
				actual := make(map[string]struct{}, len(opts))
				for _, o := range opts {
					actual[o] = struct{}{}
				}
				sigSet := make(map[string]struct{}, len(sigOpts))
				for _, o := range sigOpts {
					sigSet[o] = struct{}{}
				}
				sim := jaccardSimilarity(sigSet, actual)
				if sim == 1 {
					score += 3
				}
				if sim > 0.5 {
					score += 2
				}
				score += sim
			}
			if score > bestScore {
				bestScore = score
				bestClass = e.Label
			}
		}
	}
	return bestClass
}

func parseTcpRequestSig(sig string) (string, string, string, string, bool) {
	parts := strings.Split(sig, ":")
	if len(parts) < 5 {
		return "", "", "", "", false
	}
	ttlSig := strings.TrimSpace(parts[1])
	winField := strings.TrimSpace(parts[3])
	winExpr := winField
	wscaleExpr := ""
	if idx := strings.Index(winField, ","); idx >= 0 {
		winExpr = strings.TrimSpace(winField[:idx])
		wscaleExpr = strings.TrimSpace(winField[idx+1:])
	}
	optExpr := strings.TrimSpace(parts[4])
	return ttlSig, winExpr, wscaleExpr, optExpr, true
}

func ttlMatch(ttlSig string, ttlInit int) bool {
	if ttlSig == "*" {
		return true
	}
	if strings.HasSuffix(ttlSig, "-") {
		n, err := strconv.Atoi(strings.TrimSuffix(ttlSig, "-"))
		if err != nil {
			return false
		}
		return ttlInit <= n
	}
	if strings.Contains(ttlSig, "-") {
		parts := strings.SplitN(ttlSig, "-", 2)
		if len(parts) != 2 {
			return false
		}
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return false
		}
		return ttlInit >= lo && ttlInit <= hi
	}
	n, err := strconv.Atoi(ttlSig)
	if err != nil {
		return false
	}
	base := 255
	if ttlInit <= 64 {
		base = 64
	} else if ttlInit <= 128 {
		base = 128
	}
	return base == n || ttlInit == n
}

func nearWin(winExpr string, win int, mss int) bool {
	if winExpr == "" || winExpr == "*" {
		return false
	}
	if strings.HasPrefix(winExpr, "mss*") {
		if mss <= 0 {
			return false
		}
		n, err := strconv.Atoi(strings.TrimPrefix(winExpr, "mss*"))
		if err != nil {
			return false
		}
		target := mss * n
		return withinRatio(win, target, 0.15)
	}
	if strings.HasPrefix(winExpr, "mtu*") {
		return false
	}
	n, err := strconv.Atoi(winExpr)
	if err != nil {
		return false
	}
	return withinRatio(win, n, 0.15)
}

func winEquals(winExpr string, win int, mss int) bool {
	if winExpr == "*" || winExpr == "" {
		return true
	}
	if strings.HasPrefix(winExpr, "mss*") {
		if mss <= 0 {
			return false
		}
		n, err := strconv.Atoi(strings.TrimPrefix(winExpr, "mss*"))
		if err != nil {
			return false
		}
		return win == mss*n
	}
	if strings.HasPrefix(winExpr, "mtu*") {
		return false
	}
	n, err := strconv.Atoi(winExpr)
	if err != nil {
		return false
	}
	return win == n
}

func wsEq(sig string, wscale int) bool {
	if sig == "" || sig == "*" {
		return true
	}
	n, err := strconv.Atoi(sig)
	if err != nil {
		return false
	}
	return wscale == n
}
func withinRatio(a int, b int, ratio float64) bool {
	if a == 0 || b == 0 {
		return false
	}
	lo := float64(b) * (1 - ratio)
	hi := float64(b) * (1 + ratio)
	return float64(a) >= lo && float64(a) <= hi
}

func normalizeOpts(opts []string) []string {
	var out []string
	for _, o := range opts {
		t := strings.TrimSpace(strings.ToLower(o))
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "eol") {
			continue
		}
		switch t {
		case "mss", "ws", "sok", "ts", "nop":
			out = append(out, t)
		}
	}
	return out
}

func jaccardSimilarity(a map[string]struct{}, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	inter := 0
	union := make(map[string]struct{}, len(a)+len(b))
	for k := range a {
		union[k] = struct{}{}
	}
	for k := range b {
		union[k] = struct{}{}
	}
	for k := range a {
		if _, ok := b[k]; ok {
			inter++
		}
	}
	if len(union) == 0 {
		return 0
	}
	return float64(inter) / float64(len(union))
}
