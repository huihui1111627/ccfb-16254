package sim

import (
	"fmt"
	"hash/fnv"
	"math"
	"sort"
)

const virtualVIP = "203.0.113.10"
const virtualPort = 443

func stableHash(parts ...string) uint64 {
	h := fnv.New64a()
	for _, p := range parts {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	return mix64(h.Sum64())
}

// mix64 is SplitMix64's finalizer. Plain FNV outputs for the same key with
// only a short backend suffix can remain correlated; HRW compares those scores
// directly, so an avalanche finalizer is important for uniform placement.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// rendezvousRoute is a stateless highest-random-weight selection. Every LB
// with the same backend list and the same packet key reaches the same answer;
// adding/removing backends perturbs only keys whose winner changes.
func rendezvousRoute(key string, backends []uint32) uint32 {
	var winner uint32
	var best uint64
	for i, b := range backends {
		score := stableHash(key, "backend", fmt.Sprint(b))
		if i == 0 || score > best {
			best = score
			winner = b
		}
	}
	return winner
}

func initialCIDRoute(initialDCID []byte, backends []uint32) uint32 {
	return rendezvousRoute(fmt.Sprintf("initial-dcid:%x", initialDCID), backends)
}

func addressHashRoute(addr Addr, backends []uint32) uint32 {
	return rendezvousRoute("l4-src:"+addr.Key(), backends)
}

func (s *Scenario) backendByN(n uint32) *BackendPlan {
	for _, b := range s.Backends {
		if b.N == n {
			return b
		}
	}
	return nil
}

func backendID(n uint32) string { return fmt.Sprintf("b-%d", n) }
func lbID(n int) string         { return fmt.Sprintf("lb-%d", n) }

// backendNsAt returns ordered backend numbers visible at time t.
func (s *Scenario) backendNsAt(t int, activeOnly bool) []uint32 {
	var out []uint32
	for _, b := range s.Backends {
		if b.AddedT > t {
			continue
		}
		if b.RemoveT != 0 && t >= b.RemoveT {
			continue
		}
		if activeOnly && b.DrainT != 0 && t >= b.DrainT {
			continue
		}
		out = append(out, b.N)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (s *Scenario) lbByID(id string) *LBPlan {
	for _, lb := range s.LBs {
		if lb.ID == id {
			return lb
		}
	}
	return nil
}

// ecmpLBsAt returns ECMP member instances according to coarse health state.
func (s *Scenario) ecmpLBsAt(t int) []*LBPlan {
	var out []*LBPlan
	for _, lb := range s.LBs {
		if lb.AddedT > t {
			continue
		}
		if lb.RemovedT != 0 && t >= lb.RemovedT {
			continue
		}
		unhealthy := false
		for _, r := range lb.Restarts {
			if t >= r.HealthDownT && t < r.HealthyT {
				unhealthy = true
				break
			}
		}
		if !unhealthy {
			out = append(out, lb)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].N < out[j].N })
	return out
}

// lbBlackholeAt reports the small failure-detection window where the process
// is already stopped but ECMP health has not removed it yet.
func (s *Scenario) lbBlackholeAt(id string, t int) bool {
	lb := s.lbByID(id)
	if lb == nil {
		return false
	}
	for _, r := range lb.Restarts {
		if t >= r.At && t < r.HealthDownT {
			return true
		}
	}
	return false
}

// ecmpSelect chooses an LB from the router's ECMP group using the outer
// five-tuple. A source port/address change commonly selects another LB.
func (s *Scenario) ecmpSelect(addr Addr, t int) *LBPlan {
	members := s.ecmpLBsAt(t)
	if len(members) == 0 {
		return nil
	}
	h := stableHash("udp", addr.IP, fmt.Sprint(addr.Port), virtualVIP, fmt.Sprint(virtualPort))
	return members[int(h%uint64(len(members)))]
}

func coefficientOfVariation(values []int) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum int
	for _, v := range values {
		sum += v
	}
	mean := float64(sum) / float64(len(values))
	if mean == 0 {
		return 0
	}
	var sq float64
	for _, v := range values {
		d := float64(v) - mean
		sq += d * d
	}
	variance := sq / float64(len(values))
	return math.Sqrt(variance) / mean
}

func jainFairness(values []int) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum, squares int
	for _, v := range values {
		sum += v
		squares += v * v
	}
	if squares == 0 {
		return 1
	}
	return float64(sum*sum) / float64(len(values)*squares)
}
