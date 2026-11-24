package sim

import (
	"crypto/sha256"
	"fmt"

	"cidlb/internal/quicwire"
)

type oldGen struct {
	n           int
	owner       uint32
	cid         []byte
	src         Addr
	startT      int
	readyT      int
	breakT      int
	reconnectAt int
	broken      bool
}

type oldSessionState struct {
	gens []*oldGen
	cur  *oldGen
}

func (w *world) runOld() {
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
			w.addRecord(pr)
			continue
		}

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
			pr.Detail = "LB 重启故障检测窗口丢包；传统模式同样会中断"
			w.addRecord(pr)
			continue
		}

		st := w.oldStates[sess.ID]
		if st == nil {
			st = &oldSessionState{}
			w.oldStates[sess.ID] = st
		}

		// Legacy LB still parses the QUIC CID enough to prove it exists, but
		// its forwarding decision deliberately uses only the outer source.
		var dcid, scid []byte
		if o.Kind == "initial" || st.cur == nil {
			dcid = sess.InitialDCID
			scid = sess.ClientSCID
		} else {
			dcid = st.cur.cid
			scid = sess.ClientSCID
		}
		raw := w.buildOldPacket(o, dcid, scid)
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

		candidates := w.sc.backendNsAt(o.ArrivalT, false)
		routed := addressHashRoute(o.Src, candidates)
		pr.Routed = backendID(routed)

		// Initial creates the first backend-owned generation.
		if o.Kind == "initial" || st.cur == nil {
			nonce := sess.CIDNonce
			nonce[6] ^= 0x5A
			cid, _ := w.codec.Encode(routed, nonce)
			g := &oldGen{
				n: 1, owner: routed, cid: cid, src: o.Src,
				startT: o.ArrivalT, readyT: o.ArrivalT + 280,
			}
			st.gens = append(st.gens, g)
			st.cur = g
			pr.Gen = 1
			pr.Expected = backendID(routed)
			pr.Correct = true
			pr.Detail = "新连接首次哈希到该后端，后端建立连接状态并签发自己的 CID"
			w.stats.Correct++
			w.stats.Delivered++
			w.backendPackets[routed]++
			if o.Kind == "upload" {
				w.stats.UploadOK++
			}
			w.addRecord(pr)
			continue
		}

		g := st.cur
		pr.Gen = g.n
		pr.Expected = backendID(g.owner)

		// Reconnect timer elapsed: the next packet is hashed to the new owner
		// and starts another QUIC handshake generation. The triggering short
		// packet is still unknown there.
		if g.broken && o.ArrivalT >= g.reconnectAt {
			w.stats.Misrouted++
			w.backendPackets[routed]++
			pr.Correct = false
			pr.Detail = "客户端按新地址重新握手；旧 CID 的触发包先到达新后端，仍被计为错误路由"
			w.markOldMigration(o, g.owner, routed, true, 1200)
			if o.Kind == "upload" {
				w.stats.UploadFailed++
			}
			w.addRecord(pr)

			nonce := sess.CIDNonce
			nonce[0] ^= byte(g.n + 2)
			newCID, _ := w.codec.Encode(routed, nonce)
			ng := &oldGen{
				n: g.n + 1, owner: routed, cid: newCID, src: o.Src,
				startT: o.ArrivalT, readyT: o.ArrivalT + 620,
			}
			st.gens = append(st.gens, ng)
			st.cur = ng
			continue
		}

		correct := routed == g.owner
		pr.Correct = correct
		w.backendPackets[routed]++

		if correct {
			w.stats.Correct++
			w.stats.Delivered++
			if g.broken {
				pr.Detail = "哈希恰好仍落在原后端"
			}
			if o.Kind == "upload" {
				w.stats.UploadOK++
			}
		} else {
			w.stats.Misrouted++
			w.markOldMigration(o, g.owner, routed, !g.broken, 1200)
			if o.Kind == "upload" {
				w.stats.UploadFailed++
			}
			if !g.broken {
				g.broken = true
				g.breakT = o.ArrivalT
				g.reconnectAt = o.ArrivalT + 760
				w.stats.Rehandshakes++
				w.stats.TotalStallMS += 1200
				w.emitStatelessReset(o, g.owner, routed, g.n)
				pr.Detail = "地址/端口变化导致哈希到陌生后端；后端不认识 CID，触发重置与重新握手"
			} else {
				pr.Detail = "等待客户端按新连接重新握手，期间包继续被错误路由"
			}
		}
		w.addRecord(pr)
	}
	w.addProtocolSamples()
}

func (w *world) buildOldPacket(o *Offer, dcid, scid []byte) []byte {
	marker := []byte("simulated-quic-payload")
	switch o.Kind {
	case "initial":
		return quicwire.BuildInitial(dcid, scid, marker)
	case "handshake":
		return quicwire.BuildHandshake(dcid, scid, marker)
	default:
		return quicwire.BuildShort(dcid, marker)
	}
}

func (w *world) markOldMigration(o *Offer, oldOwner, routed uint32, firstBreak bool, stall int) {
	if o.MigrationID == "" {
		return
	}
	m := w.migByID[o.MigrationID]
	if m == nil {
		return
	}
	if m.Old.BeforeBackend == "" {
		m.Old.BeforeBackend = backendID(oldOwner)
	}
	m.Old.AfterBackend = backendID(routed)
	m.Old.Wrong++
	m.Old.Preserved = false
	if o.Kind == "upload" {
		m.Old.UploadFailed = true
	}
	if firstBreak {
		m.Old.Rehandshake = true
		m.Old.StallMS = stall
		m.Old.RecoveryMS = stall
	}
}

func (w *world) emitStatelessReset(o *Offer, oldOwner, routed uint32, gen int) {
	sum := sha256.Sum256([]byte(fmt.Sprintf("stateless-reset:%s:%d:%d", o.SessionID, gen, o.ID)))
	token := sum[:16]
	prefix := []byte(fmt.Sprintf("unpredictable-reset-padding-%d", o.ID))
	var lookedLikeCID []byte
	if sess := w.sessionByID(o.SessionID); sess != nil {
		lookedLikeCID = sess.ServerCID
	}
	raw := quicwire.BuildStatelessReset(lookedLikeCID, prefix, token)
	if !quicwire.IsStatelessReset(raw, token) {
		return
	}
	w.stats.ResetPackets++
	w.addRecord(PacketRecord{
		ID:          fmt.Sprintf("old-reset-%d-g%d", o.ID, gen),
		TraceID:     o.SessionID,
		User:        o.User,
		Gen:         gen,
		SendT:       o.ArrivalT,
		T:           o.ArrivalT + 42,
		Kind:        "stateless_reset",
		Header:      string(quicwire.ClassStatelessReset),
		LB:          "-",
		Expected:    backendID(oldOwner),
		Routed:      backendID(routed),
		Correct:     false,
		MigrationID: o.MigrationID,
		Detail:      "陌生后端用包尾 16 字节 token 标识无状态重置；客户端收到后放弃原连接",
	})
}

func (w *world) oldConnectionInfos() []ConnectionInfo {
	out := []ConnectionInfo{}
	for sessID, st := range w.oldStates {
		sess := w.sessionByID(sessID)
		for i, g := range st.gens {
			endT := sess.EndT
			if i+1 < len(st.gens) {
				endT = st.gens[i+1].startT
			}
			stall := 0
			preserved := !g.broken
			if g.n > 1 {
				stall = 1200
				preserved = false
			}
			info := ConnectionInfo{
				ID:            fmt.Sprintf("%s#g%d", sessID, g.n),
				User:          sess.User,
				Gen:           g.n,
				ParentID:      sessID,
				StartT:        g.startT,
				EndT:          endT,
				Owner:         backendID(g.owner),
				SourceNetwork: g.src.Network,
				SourceAddr:    g.src.String(),
				CIDPreview:    fmt.Sprintf("%x", g.cid),
				Packets:       0,
				Wrong:         0,
				Preserved:     &preserved,
				Rehandshake:   g.n > 1 || g.broken,
				StallMS:       stall,
			}
			for _, r := range w.traces[sessID] {
				if r.Gen != g.n || r.Kind == "stateless_reset" {
					continue
				}
				info.Packets++
				if r.Routed != "" && r.Expected != r.Routed {
					info.Wrong++
				}
			}
			out = append(out, info)
		}
	}
	return out
}

func (w *world) addProtocolSamples() {
	versions := []uint32{0xfacade01, 0x6b3343cf, 0xff00001d, 0x00000002}
	for i, v := range versions {
		t := 4200 + i*31_000
		dcid := []byte(fmt.Sprintf("probe-dcid-%d", i))
		scid := []byte(fmt.Sprintf("probe-scid-%d", i))
		unknown := quicwire.BuildUnsupportedInitial(v, dcid, scid)
		h, err := quicwire.Parse(unknown, quicwire.CIDLength)
		if err == nil && h.Long {
			w.stats.LongPackets++
		}
		vn := quicwire.BuildVersionNegotiation(dcid, scid, quicwire.Version1, 0x6b3343cf)
		vh, err := quicwire.Parse(vn, quicwire.CIDLength)
		if err == nil && vh.Class == quicwire.ClassVersionNegotiation {
			w.stats.VNPackets++
		}
		w.addRecord(PacketRecord{
			ID:      fmt.Sprintf("%s-vn-%d", w.mode, i),
			TraceID: "protocol",
			User:    0,
			T:       t,
			SendT:   t - 35,
			Kind:    "version_negotiation",
			Header:  string(quicwire.ClassVersionNegotiation),
			Correct: true,
			Detail:  fmt.Sprintf("客户端提议版本 0x%08x；版本协商包 Version=0，按长包头解析 CID 后单独处理，不建立连接状态", v),
		})
	}
}
