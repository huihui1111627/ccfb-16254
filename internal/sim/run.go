package sim

import (
	"fmt"
	"sort"

	"cidlb/internal/quicwire"
)

// Run generates one deterministic scenario and executes both routing models
// against identical packet offers.
func Run(cfg Config) (*Result, error) {
	sc, codec, err := GenerateScenario(cfg)
	if err != nil {
		return nil, err
	}

	migByID := map[string]*Migration{}
	migrations := make([]*Migration, 0, len(sc.Switches))
	for _, sw := range sc.Switches {
		sess := sc.SessionAt(sw.User, sw.T+250)
		sessionID := ""
		if sess != nil {
			sessionID = sess.ID
		}
		beforeLB := sc.ecmpSelect(sw.From, max0(sw.T-250))
		afterLB := sc.ecmpSelect(sw.To, sw.T+450)
		lbBefore, lbAfter := "", ""
		if beforeLB != nil {
			lbBefore = beforeLB.ID
		}
		if afterLB != nil {
			lbAfter = afterLB.ID
		}
		m := &Migration{
			ID: sw.ID, User: sw.User, T: sw.T, From: sw.From, To: sw.To,
			Reason: sw.Reason, SessionID: sessionID,
			LBBefore: lbBefore, LBAfter: lbAfter, LBChanged: lbBefore != lbAfter,
		}
		m.CID.Preserved = true
		migrations = append(migrations, m)
		migByID[m.ID] = m
	}

	cidW := newWorld(sc, codec, "cid", migByID)
	cidW.runCID()
	oldW := newWorld(sc, codec, "old", migByID)
	oldW.runOld()

	backends := make([]*BackendView, 0, len(sc.Backends))
	for _, b := range sc.Backends {
		backends = append(backends, &BackendView{
			BackendPlan: b,
			CIDPackets:  cidW.backendPackets[b.N],
			OldPackets:  oldW.backendPackets[b.N],
		})
	}

	cidConns := cidW.connectionInfos()
	oldConns := oldW.connectionInfos()
	for _, bv := range backends {
		for _, c := range cidConns {
			if c.Owner == bv.ID {
				bv.CIDConns++
			}
		}
		for _, c := range oldConns {
			if c.Owner == bv.ID {
				bv.OldGens++
			}
		}
	}
	var cidTotal, oldTotal int
	for _, bv := range backends {
		cidTotal += bv.CIDPackets
		oldTotal += bv.OldPackets
	}
	for _, bv := range backends {
		if cidTotal > 0 {
			bv.CIDShare = float64(bv.CIDPackets) / float64(cidTotal)
		}
		if oldTotal > 0 {
			bv.OldShare = float64(bv.OldPackets) / float64(oldTotal)
		}
	}

	cidCV, cidJain := fairnessForBackends(sc, cidW.backendPackets)
	oldCV, oldJain := fairnessForBackends(sc, oldW.backendPackets)
	cidW.stats.BackendCV = cidCV
	cidW.stats.JainFairness = cidJain
	cidW.stats.LBDisagreements = lbRouteDisagreements(cidW.records)
	oldW.stats.BackendCV = oldCV
	oldW.stats.JainFairness = oldJain
	oldW.stats.LBDisagreements = lbRouteDisagreements(oldW.records)
	finalizeMigrations(migrations)
	for _, m := range migrations {
		if m.CID.Preserved {
			cidW.stats.Preserved++
		}
		if m.Old.Preserved {
			oldW.stats.Preserved++
		}
	}

	examples := buildCIDExamples(codec, sc.Backends)
	sec := SecurityInfo{
		Algorithm:      "AES-CTR backend ID + truncated HMAC-SHA256 (encrypt-then-MAC)",
		AgreedLength:   quicwire.CIDLength,
		ForgedTotal:    len(sc.Forgeries),
		ForgedRejected: 0,
		ForgedAccepted: 0,
	}
	for _, f := range sc.Forgeries {
		if _, err := codec.Decode(f.CID); err == nil {
			sec.ForgedAccepted++
		} else {
			sec.ForgedRejected++
		}
	}
	wrongCodec := quicwire.NewCIDCodec("wrong-backend-secret", codec.KeyID())
	var nonce [7]byte
	wrongCID, _ := wrongCodec.Encode(1, nonce)
	_, err = codec.Decode(wrongCID)
	sec.WrongKeyReject = err != nil
	cidW.stats.ForgedTotal = sec.ForgedTotal
	cidW.stats.ForgedRejected = sec.ForgedRejected
	cidW.stats.ForgedAccepted = sec.ForgedAccepted

	report := &Report{
		Config:      cfg,
		CID:         &ModeReport{Mode: "cid", Label: "CID 路由", Description: "任何 LB 实例验证 CID 中的认证后端身份", Stats: cidW.stats, Connections: cidConns},
		Old:         &ModeReport{Mode: "old", Label: "源地址哈希", Description: "按外层源 IP:端口哈希；网络迁移后哈希键改变", Stats: oldW.stats, Connections: oldConns},
		Migrations:  migrations,
		Users:       sc.Users,
		Ops:         sc.Ops,
		Backends:    backends,
		LBs:         sc.LBs,
		LoadSeries:  buildLoadSeries(sc, cidW.records, oldW.records, cidConns, oldConns),
		CIDExamples: examples,
		Security:    sec,
	}

	return &Result{
		Report:     report,
		cidPackets: cidW.traces,
		oldPackets: oldW.traces,
	}, nil
}

type world struct {
	sc             *Scenario
	codec          *quicwire.CIDCodec
	mode           string
	migByID        map[string]*Migration
	stats          Stats
	records        []PacketRecord
	traces         map[string][]PacketRecord
	backendPackets map[uint32]int
	oldStates      map[string]*oldSessionState
}

func newWorld(sc *Scenario, codec *quicwire.CIDCodec, mode string, mig map[string]*Migration) *world {
	return &world{
		sc: sc, codec: codec, mode: mode, migByID: mig,
		traces:         map[string][]PacketRecord{},
		backendPackets: map[uint32]int{},
		oldStates:      map[string]*oldSessionState{},
	}
}

func (w *world) addRecord(r PacketRecord) {
	w.records = append(w.records, r)
	w.traces[r.TraceID] = append(w.traces[r.TraceID], r)
}

func (w *world) sessionByID(id string) *Session {
	for _, s := range w.sc.Sessions {
		if s.ID == id {
			return s
		}
	}
	return nil
}

func orderedOffers(sc *Scenario) []*Offer {
	out := append([]*Offer(nil), sc.Offers...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ArrivalT != out[j].ArrivalT {
			return out[i].ArrivalT < out[j].ArrivalT
		}
		if out[i].SendT != out[j].SendT {
			return out[i].SendT < out[j].SendT
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func (w *world) baseRecord(o *Offer) PacketRecord {
	return PacketRecord{
		ID:          fmt.Sprintf("%s-p%d", w.mode, o.ID),
		TraceID:     o.SessionID,
		User:        o.User,
		Seq:         o.Seq,
		SendT:       o.SendT,
		T:           o.ArrivalT,
		Kind:        o.Kind,
		Src:         o.Src,
		MigrationID: o.MigrationID,
	}
}

func (w *world) runCID() {
	w.stats.Migrations = len(w.migByID)
	maxSeq := map[string]int{}
	for _, o := range orderedOffers(w.sc) {
		if o.Kind == "upload" {
			w.stats.Uploads++
		}
		w.stats.Offered++
		pr := w.baseRecord(o)
		sess := w.sessionByID(o.SessionID)
		if sess == nil {
			pr.Detail = "unknown simulation trace"
			w.addRecord(pr)
			continue
		}
		pr.Expected = backendID(sess.Owner)

		if o.Lost {
			w.stats.Lost++
			pr.Lost = true
			pr.Detail = "无线网络丢包，未到达负载均衡"
			w.addRecord(pr)
			continue
		}
		w.stats.Arrived++
		if max, ok := maxSeq[o.SessionID]; ok && o.Seq < max {
			pr.Reordered = true
			w.stats.Reordered++
		} else {
			maxSeq[o.SessionID] = o.Seq
		}

		lb := w.sc.ecmpSelect(o.Src, o.ArrivalT)
		if lb != nil {
			pr.LB = lb.ID
		}
		if lb != nil && w.sc.lbBlackholeAt(lb.ID, o.ArrivalT) {
			w.stats.LBRestartDrops++
			pr.Detail = "LB 进程重启且健康检查尚未摘除，此包被丢弃；CID 路由状态本身无丢失"
			w.addRecord(pr)
			continue
		}

		raw, err := w.buildCIDPacket(o, sess)
		if err != nil {
			w.stats.ParseErrors++
			pr.Detail = err.Error()
			w.addRecord(pr)
			continue
		}
		h, err := quicwire.Parse(raw, quicwire.CIDLength)
		if err != nil {
			w.stats.ParseErrors++
			pr.Header = "malformed"
			pr.Detail = err.Error()
			w.addRecord(pr)
			continue
		}
		pr.Header = string(h.Class)
		if h.Long {
			w.stats.LongPackets++
		} else {
			w.stats.ShortPackets++
		}

		var owner uint32
		switch h.Class {
		case quicwire.ClassShort, quicwire.ClassHandshake, quicwire.ClassZeroRTT, quicwire.ClassRetry:
			owner, err = w.codec.Decode(h.DCID)
			if err != nil {
				w.stats.ParseErrors++
				pr.Detail = "CID 认证失败：" + err.Error()
				w.addRecord(pr)
				continue
			}
		case quicwire.ClassInitial:
			candidates := w.sc.backendNsAt(o.SendT, true)
			owner = initialCIDRoute(h.DCID, candidates)
		default:
			owner = sess.Owner
		}

		pr.Routed = backendID(owner)
		correct := owner == sess.Owner
		pr.Correct = correct
		w.backendPackets[owner]++
		if correct {
			w.stats.Correct++
			w.stats.Delivered++
		} else {
			w.stats.Misrouted++
		}
		if o.Kind == "upload" {
			if correct {
				w.stats.UploadOK++
			} else {
				w.stats.UploadFailed++
			}
		}
		w.markCIDMigration(o, pr)
		w.addRecord(pr)
	}
	w.addProtocolSamples()
}

func (w *world) buildCIDPacket(o *Offer, s *Session) ([]byte, error) {
	marker := []byte("simulated-quic-payload")
	switch o.Kind {
	case "initial":
		return quicwire.BuildInitial(s.InitialDCID, s.ClientSCID, marker), nil
	case "handshake":
		return quicwire.BuildHandshake(s.ServerCID, s.ClientSCID, marker), nil
	default:
		return quicwire.BuildShort(s.ServerCID, marker), nil
	}
}

func (w *world) markCIDMigration(o *Offer, pr PacketRecord) {
	if o.MigrationID == "" {
		return
	}
	m := w.migByID[o.MigrationID]
	if m == nil {
		return
	}
	if m.CID.BeforeBackend == "" {
		m.CID.BeforeBackend = pr.Expected
	}
	m.CID.AfterBackend = pr.Routed
	if !pr.Correct && pr.Routed != "" {
		m.CID.Wrong++
	}
}

func (w *world) connectionInfos() []ConnectionInfo {
	if w.mode == "cid" {
		out := make([]ConnectionInfo, 0, len(w.sc.Sessions))
		for _, s := range w.sc.Sessions {
			recs := w.traces[s.ID]
			wrong := 0
			for _, r := range recs {
				if r.Kind != "stateless_reset" && r.Routed != "" && r.Expected != r.Routed {
					wrong++
				}
			}
			preserved := wrong == 0
			out = append(out, ConnectionInfo{
				ID: s.ID, User: s.User, Gen: 1, StartT: s.StartT, EndT: s.EndT,
				Owner: backendID(s.Owner), CIDPreview: fmt.Sprintf("%x", s.ServerCID),
				InitialCIDPreview: fmt.Sprintf("%x", s.InitialDCID),
				Packets:           len(recs), Wrong: wrong, Preserved: &preserved,
			})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].StartT < out[j].StartT })
		return out
	}
	return w.oldConnectionInfos()
}

func finalizeMigrations(ms []*Migration) {
	for _, m := range ms {
		m.CID.Preserved = m.CID.Wrong == 0
		m.Old.Preserved = m.Old.Wrong == 0
		if m.CID.BeforeBackend == "" {
			m.CID.BeforeBackend = "-"
		}
		if m.CID.AfterBackend == "" {
			m.CID.AfterBackend = m.CID.BeforeBackend
		}
		if m.Old.BeforeBackend == "" {
			m.Old.BeforeBackend = "-"
		}
		if m.Old.AfterBackend == "" {
			m.Old.AfterBackend = m.Old.BeforeBackend
		}
	}
}

func max0(x int) int {
	if x < 0 {
		return 0
	}
	return x
}

func buildCIDExamples(codec *quicwire.CIDCodec, backends []*BackendPlan) []CIDExample {
	var out []CIDExample
	for _, b := range backends {
		for j := 0; j < 2; j++ {
			nonce := [7]byte{byte(b.N), byte(j + 1), 0xAA, 0x17, 0x33, 0x91, byte(j * 7)}
			cid, err := codec.Encode(b.N, nonce)
			if err != nil {
				continue
			}
			out = append(out, CIDExample{Backend: b.ID, CID: fmt.Sprintf("%x", cid)})
		}
	}
	return out
}
