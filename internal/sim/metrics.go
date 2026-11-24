package sim

import "math"

// lbRouteDisagreements counts traces seen by more than one LB instance where
// those instances nevertheless resolved different backends. Authenticated CID
// routing should make this zero even without shared connection state.
func lbRouteDisagreements(records []PacketRecord) int {
	type observation struct {
		backends map[string]struct{}
		lbs      map[string]struct{}
	}
	byTrace := map[string]*observation{}
	for _, r := range records {
		if r.TraceID == "" || r.TraceID == "protocol" || r.Routed == "" || r.LB == "" || r.LB == "-" {
			continue
		}
		if r.Kind == "stateless_reset" {
			continue
		}
		o := byTrace[r.TraceID]
		if o == nil {
			o = &observation{backends: map[string]struct{}{}, lbs: map[string]struct{}{}}
			byTrace[r.TraceID] = o
		}
		o.backends[r.Routed] = struct{}{}
		o.lbs[r.LB] = struct{}{}
	}
	bad := 0
	for _, o := range byTrace {
		if len(o.lbs) > 1 && len(o.backends) > 1 {
			bad++
		}
	}
	return bad
}

func fairnessForBackends(sc *Scenario, packets map[uint32]int) (cv, jain float64) {
	rates := make([]float64, 0, len(sc.Backends))
	for _, b := range sc.Backends {
		end := b.RemoveT
		if end == 0 {
			end = sc.Config.DurationMS
		}
		activeSeconds := float64(max0(end-b.AddedT)) / 1000.0
		if activeSeconds < 1 {
			activeSeconds = 1
		}
		rates = append(rates, float64(packets[b.N])/activeSeconds)
	}
	mean := 0.0
	for _, v := range rates {
		mean += v
	}
	mean /= float64(len(rates))
	if mean > 0 {
		sq := 0.0
		for _, v := range rates {
			d := v - mean
			sq += d * d
		}
		cv = math.Sqrt(sq/float64(len(rates))) / mean
	}
	sum, squares := 0.0, 0.0
	for _, v := range rates {
		sum += v
		squares += v * v
	}
	if squares > 0 {
		jain = sum * sum / (float64(len(rates)) * squares)
	} else {
		jain = 1
	}
	return cv, jain
}

func buildLoadSeries(sc *Scenario, cidRecords, oldRecords []PacketRecord, cidConns, oldConns []ConnectionInfo) []LoadPoint {
	const bucketMS = 2000
	buckets := sc.Config.DurationMS/bucketMS + 2
	points := make([]LoadPoint, buckets)
	backendIDs := make([]string, 0, len(sc.Backends))
	for _, b := range sc.Backends {
		backendIDs = append(backendIDs, b.ID)
	}
	for i := range points {
		points[i].T = i * bucketMS
		points[i].CID = map[string]int{}
		points[i].Old = map[string]int{}
		points[i].CIDConns = map[string]int{}
		points[i].OldConns = map[string]int{}
		for _, id := range backendIDs {
			points[i].CID[id] = 0
			points[i].Old[id] = 0
			points[i].CIDConns[id] = 0
			points[i].OldConns[id] = 0
		}
	}

	bucketFor := func(t int) int {
		idx := t / bucketMS
		if idx < 0 {
			return 0
		}
		if idx >= len(points) {
			return len(points) - 1
		}
		return idx
	}
	for _, r := range cidRecords {
		if r.Routed == "" || r.Kind == "stateless_reset" {
			continue
		}
		points[bucketFor(r.T)].CID[r.Routed]++
	}
	for _, r := range oldRecords {
		if r.Routed == "" || r.Kind == "stateless_reset" {
			continue
		}
		points[bucketFor(r.T)].Old[r.Routed]++
	}

	for i := range points {
		mid := points[i].T + bucketMS/2
		for _, c := range cidConns {
			if c.StartT <= mid && mid < c.EndT {
				points[i].CIDConns[c.Owner]++
			}
		}
		for _, c := range oldConns {
			if c.StartT <= mid && mid < c.EndT {
				points[i].OldConns[c.Owner]++
			}
		}
	}
	return points[:sc.Config.DurationMS/bucketMS+1]
}
