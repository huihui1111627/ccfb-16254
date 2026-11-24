package sim

import (
	"fmt"
	"math/rand"
	"sort"

	"cidlb/internal/quicwire"
)

// GenerateScenario builds a deterministic batch of phone users, network
// changes, traffic, backend scaling and LB membership events.
func GenerateScenario(cfg Config) (*Scenario, *quicwire.CIDCodec, error) {
	if cfg.Users <= 0 {
		cfg.Users = DefaultConfig().Users
	}
	if cfg.DurationMS <= 0 {
		cfg.DurationMS = DefaultConfig().DurationMS
	}
	if cfg.PacketIntervalMS <= 0 {
		cfg.PacketIntervalMS = DefaultConfig().PacketIntervalMS
	}
	if cfg.Seed == 0 {
		cfg.Seed = DefaultConfig().Seed
	}
	if cfg.SharedSecret == "" {
		cfg.SharedSecret = DefaultConfig().SharedSecret
	}

	rng := rand.New(rand.NewSource(cfg.Seed))
	codec := quicwire.NewCIDCodec(cfg.SharedSecret, 0xC1)
	d := cfg.DurationMS
	at := func(f float64) int { return int(float64(d) * f) }

	sc := &Scenario{Config: cfg}

	// Backend fleet and scaling plan.
	for n := uint32(1); n <= 6; n++ {
		sc.Backends = append(sc.Backends, &BackendPlan{
			N: n, ID: backendID(n), Addr: fmt.Sprintf("10.20.0.%d:443", 10+n),
			AddedT: 0,
		})
	}
	addBackend := func(n uint32, t int) {
		sc.Backends = append(sc.Backends, &BackendPlan{
			N: n, ID: backendID(n), Addr: fmt.Sprintf("10.20.0.%d:443", 10+n),
			AddedT: t,
		})
		sc.Ops = append(sc.Ops, &OpEvent{
			T: t, Kind: "backend_up", Target: backendID(n), Tone: "good",
			Title:  fmt.Sprintf("后端扩容：上线 %s", backendID(n)),
			Detail: "新连接的初始 DCID 哈希开始把一部分新会话分配给它；已有 CID 不变。",
		})
	}
	addBackend(7, at(0.14))
	addBackend(8, at(0.34))
	addBackend(9, at(0.34))
	sc.Ops = append(sc.Ops, &OpEvent{
		T: at(0.34), Kind: "backend_up_batch", Target: "b-8,b-9", Tone: "good",
		Title:  "后端扩容：批量上线 b-8、b-9",
		Detail: "两个新后端进入 ECMP/ rendezvous 候选集合，只影响之后的新连接。",
	})
	// Remove the individual duplicate operation for b-8/b-9? Keep addBackend
	// events creates three ops at same time plus batch; instead remove individual details?
	// We will filter backend_up for 8/9 below by using only batch wording.

	sc.Ops = append(sc.Ops,
		&OpEvent{T: at(0.46), Kind: "backend_down", Tone: "warn", Title: "后端缩容并排空"},
		&OpEvent{T: at(0.74), Kind: "backend_down", Tone: "warn", Title: "后端缩容并排空"},
	)

	// Stateless LB fleet and ECMP membership changes.
	for n := 1; n <= 3; n++ {
		sc.LBs = append(sc.LBs, &LBPlan{N: n, ID: lbID(n), AddedT: 0})
	}
	tAdd4 := at(0.075)
	sc.LBs = append(sc.LBs, &LBPlan{N: 4, ID: lbID(4), AddedT: tAdd4})
	sc.Ops = append(sc.Ops, &OpEvent{
		T: tAdd4, Kind: "lb_add", Target: "lb-4", Tone: "info",
		Title:  "负载均衡扩容：lb-4 加入 ECMP",
		Detail: "路由器重新计算 ECMP 成员；lb-4 不需要同步连接表，拿到包后直接验证 CID。",
	})

	tRestart2 := at(0.24)
	sc.addRestart("lb-2", 2, tRestart2)
	sc.Ops = append(sc.Ops, &OpEvent{
		T: tRestart2, Kind: "lb_restart", Target: "lb-2", Tone: "warn",
		Title:  "lb-2 进程重启",
		Detail: "重启期间不恢复任何共享状态；所有实例只依赖共享密钥和 CID 中的认证后端身份。",
	})

	tAdd5 := at(0.58)
	sc.LBs = append(sc.LBs, &LBPlan{N: 5, ID: lbID(5), AddedT: tAdd5})
	sc.Ops = append(sc.Ops, &OpEvent{
		T: tAdd5, Kind: "lb_add", Target: "lb-5", Tone: "info",
		Title:  "负载均衡扩容：lb-5 加入 ECMP",
		Detail: "不同手机的五元组可能被 ECMP 散列到新实例；同一 CID 在任何实例上都解析出同一后端。",
	})

	tRestart1 := at(0.66)
	sc.addRestart("lb-1", 1, tRestart1)
	sc.Ops = append(sc.Ops, &OpEvent{
		T: tRestart1, Kind: "lb_restart", Target: "lb-1", Tone: "warn",
		Title:  "lb-1 滚动重启",
		Detail: "健康检查摘除后 ECMP 不再导向它；恢复后无需预热连接表。",
	})

	tRemove4 := at(0.90)
	if l := sc.lbByID("lb-4"); l != nil {
		l.RemovedT = tRemove4
	}
	sc.Ops = append(sc.Ops, &OpEvent{
		T: tRemove4, Kind: "lb_remove", Target: "lb-4", Tone: "info",
		Title:  "负载均衡缩容：摘除 lb-4",
		Detail: "ECMP 成员减少；被重散列到其他 LB 的包仍按 CID 找到原后端。",
	})

	// Phone users and their initial addresses.
	for i := 1; i <= cfg.Users; i++ {
		startNet := "Wi-Fi"
		if rng.Intn(2) == 0 {
			startNet = "4G"
		}
		initial := makeAddr(rng, startNet, i)
		u := &UserTrace{
			ID:          fmt.Sprintf("u%02d", i),
			N:           i,
			StartNet:    startNet,
			InitialAddr: initial,
		}
		sc.Users = append(sc.Users, u)
	}

	// Finite sessions give scale-down operations real connections to drain.
	for _, u := range sc.Users {
		cursor := 700 + rng.Intn(3600)
		idx := 1
		for cursor < d-11_000 {
			duration := 23_000 + rng.Intn(43_000)
			end := cursor + duration
			if end > d-1500 {
				end = d - 800 - rng.Intn(2600)
			}
			if end-cursor < 11_000 {
				break
			}
			s := &Session{
				ID:          fmt.Sprintf("%s-c%d", u.ID, idx),
				User:        u.N,
				Index:       idx,
				StartT:      cursor,
				EndT:        end,
				InitialDCID: randBytes(rng, 8+rng.Intn(13)),
				ClientSCID:  randBytes(rng, 8),
			}
			for j := range s.CIDNonce {
				s.CIDNonce[j] = byte(rng.Intn(256))
			}
			candidates := sc.backendNsAt(s.StartT, true)
			s.Owner = initialCIDRoute(s.InitialDCID, candidates)
			cid, err := codec.Encode(s.Owner, s.CIDNonce)
			if err != nil {
				return nil, nil, err
			}
			s.ServerCID = cid
			sc.Sessions = append(sc.Sessions, s)
			u.SessionIDs = append(u.SessionIDs, s.ID)

			cursor = end + 1100 + rng.Intn(4200)
			idx++
		}
	}

	// Network changes are placed inside active sessions whenever possible.
	for _, u := range sc.Users {
		t := 7500 + rng.Intn(9500)
		currentNet := u.StartNet
		addr := u.InitialAddr
		for t < d-6500 {
			s := sc.SessionAt(u.N, t)
			if s == nil || t < s.StartT+2200 || t > s.EndT-3800 {
				s = sc.nextUsableSession(u.N, t)
				if s == nil {
					break
				}
				lo := s.StartT + 2400
				hi := s.EndT - 3600
				if hi <= lo {
					t = (s.StartT + s.EndT) / 2
				} else {
					t = lo + rng.Intn(hi-lo)
				}
			}

			nextNet := "4G"
			if currentNet == "4G" {
				nextNet = "Wi-Fi"
			}
			nextAddr := makeAddr(rng, nextNet, u.N)
			reason := "走进楼道/电梯，Wi-Fi 信号劣化，切换到 4G"
			if nextNet == "Wi-Fi" {
				reason = "回到 Wi-Fi 覆盖区，切回 Wi-Fi"
			}
			sw := &Switch{
				ID:   fmt.Sprintf("mig-%03d", len(sc.Switches)+1),
				User: u.N, T: t, From: addr, To: nextAddr, Reason: reason,
			}
			sc.Switches = append(sc.Switches, sw)
			addr = nextAddr
			currentNet = nextNet

			t += 14_500 + rng.Intn(17_500)
		}
	}

	sc.generateOffers(rng)
	sc.planDrains(rng, codec)
	sc.generateForgeries(rng, codec)

	sort.Slice(sc.Ops, func(i, j int) bool {
		if sc.Ops[i].T != sc.Ops[j].T {
			return sc.Ops[i].T < sc.Ops[j].T
		}
		return sc.Ops[i].Title < sc.Ops[j].Title
	})
	return sc, codec, nil
}

func (s *Scenario) addRestart(id string, n int, at int) {
	lb := s.lbByID(id)
	if lb == nil {
		lb = &LBPlan{N: n, ID: id, AddedT: 0}
		s.LBs = append(s.LBs, lb)
	}
	lb.Restarts = append(lb.Restarts, Restart{
		At: at, HealthDownT: at + 650, ProcessBackT: at + 2300, HealthyT: at + 3050,
	})
}

func (s *Scenario) generateOffers(rng *rand.Rand) {
	var offers []*Offer
	add := func(o *Offer) { offers = append(offers, o) }

	for _, sess := range s.Sessions {
		mig := s.migrationAtOrBefore(sess.User, sess.StartT)
		add(&Offer{
			User: sess.User, SessionID: sess.ID, SendT: sess.StartT,
			ArrivalT: sess.StartT + 18 + rng.Intn(55), Src: s.AddrAt(sess.User, sess.StartT),
			Kind: "initial", Size: 1180, MigrationID: mig,
		})
		hsT := sess.StartT + 150 + rng.Intn(170)
		add(&Offer{
			User: sess.User, SessionID: sess.ID, SendT: hsT,
			ArrivalT: hsT + 20 + rng.Intn(60), Src: s.AddrAt(sess.User, hsT),
			Kind: "handshake", Size: 320 + rng.Intn(260), MigrationID: s.migrationAtOrBefore(sess.User, hsT),
		})

		t := sess.StartT + 500 + rng.Intn(220)
		for t < sess.EndT-150 {
			delay := 16 + rng.Intn(75)
			reorder := rng.Float64() < 0.045
			if reorder {
				delay += 130 + rng.Intn(430)
			}
			lost := rng.Float64() < 0.017
			add(&Offer{
				User: sess.User, SessionID: sess.ID, SendT: t, ArrivalT: t + delay,
				Src: s.AddrAt(sess.User, t), Kind: "data", Size: 160 + rng.Intn(1080),
				Lost: lost, ReorderHint: reorder, MigrationID: s.migrationAtOrBefore(sess.User, t),
			})
			step := s.Config.PacketIntervalMS + rng.Intn(141) - 70
			if step < 120 {
				step = 120
			}
			t += step
		}
	}

	// Uploads are often the user-visible failure: a one-shot POST immediately
	// after the network change has no patience for a new handshake.
	for _, sw := range s.Switches {
		if rng.Float64() > 0.72 {
			continue
		}
		sess := s.SessionAt(sw.User, sw.T+300)
		if sess == nil || sw.T+900 >= sess.EndT {
			continue
		}
		count := 1 + rng.Intn(3)
		for k := 0; k < count; k++ {
			t := sw.T + 35 + rng.Intn(360) + k*(28+rng.Intn(70))
			if t >= sess.EndT {
				break
			}
			delay := 14 + rng.Intn(55)
			add(&Offer{
				User: sw.User, SessionID: sess.ID, SendT: t, ArrivalT: t + delay,
				Src: sw.To, Kind: "upload", Size: 420 + rng.Intn(900),
				Lost: rng.Float64() < 0.008, MigrationID: sw.ID,
			})
		}
	}

	sort.SliceStable(offers, func(i, j int) bool {
		if offers[i].SendT != offers[j].SendT {
			return offers[i].SendT < offers[j].SendT
		}
		return offers[i].SessionID < offers[j].SessionID
	})
	for i, o := range offers {
		o.ID = i + 1
	}

	bySession := map[string][]*Offer{}
	for _, o := range offers {
		bySession[o.SessionID] = append(bySession[o.SessionID], o)
	}
	for _, list := range bySession {
		sort.SliceStable(list, func(i, j int) bool { return list[i].SendT < list[j].SendT })
		for i, o := range list {
			o.Seq = i
		}
	}
	s.Offers = offers
}

func (s *Scenario) generateForgeries(rng *rand.Rand, codec *quicwire.CIDCodec) {
	attacker := quicwire.NewCIDCodec("attacker-guessed-secret", codec.KeyID())
	for i := 0; i < 30; i++ {
		t := 2500 + rng.Intn(s.Config.DurationMS-5000)
		claimed := uint32(1 + rng.Intn(9))
		var cid []byte
		if rng.Intn(2) == 0 {
			var nonce [7]byte
			for j := range nonce {
				nonce[j] = byte(rng.Intn(256))
			}
			cid, _ = attacker.Encode(claimed, nonce)
		} else {
			cid = randBytes(rng, quicwire.CIDLength)
			cid[0] = codec.KeyID()
		}
		s.Forgeries = append(s.Forgeries, &Forgery{
			T: t, Src: makeAddr(rng, "4G", 900+i), Claimed: claimed, CID: cid,
		})
	}
}

func (s *Scenario) planDrains(rng *rand.Rand, codec *quicwire.CIDCodec) {
	downOps := []*OpEvent{}
	for _, op := range s.Ops {
		if op.Kind == "backend_down" {
			downOps = append(downOps, op)
		}
	}

	// Choose drains one at a time. After each choice, recompute owners so no
	// session starting after a backend enters draining can be assigned to it.
	for _, op := range downOps {
		pick := s.chooseDrainTarget(op.T)
		if pick == nil {
			continue
		}
		op.Target = pick.ID
		pick.DrainT = op.T
		s.assignOwners()
	}
	s.encodeCIDs(rng, codec)

	for _, op := range downOps {
		plan := s.backendByID(op.Target)
		if plan == nil {
			continue
		}
		active, maxEnd := 0, op.T
		for _, sess := range s.Sessions {
			if sess.Owner == plan.N && sess.StartT <= op.T && sess.EndT > op.T {
				active++
				if sess.EndT > maxEnd {
					maxEnd = sess.EndT
				}
			}
		}
		removeT := op.T + 2500
		if active > 0 {
			removeT = maxEnd + 750
		}
		plan.RemoveT = removeT
		plan.DrainConns = active
		op.Title = fmt.Sprintf("后端缩容：%s 进入 draining", plan.ID)
		op.Detail = fmt.Sprintf(
			"停止把新连接分配给 %s；%d 条已有连接继续用原 CID 路由。最后一条连接结束后于 %s 完成排空并摘除。",
			plan.ID, active, formatMS(removeT),
		)
	}

	// Collapse the two low-level b-8/b-9 add events into one batch event.
	filtered := s.Ops[:0]
	for _, op := range s.Ops {
		if op.Kind == "backend_up" && (op.Target == "b-8" || op.Target == "b-9") {
			continue
		}
		filtered = append(filtered, op)
	}
	s.Ops = filtered
}

func (s *Scenario) chooseDrainTarget(at int) *BackendPlan {
	type choice struct {
		plan   *BackendPlan
		active int
		maxEnd int
	}
	var choices []choice
	for _, b := range s.Backends {
		if b.AddedT > at || b.DrainT != 0 {
			continue
		}
		active, maxEnd := 0, at
		for _, sess := range s.Sessions {
			if sess.Owner == b.N && sess.StartT <= at && sess.EndT > at {
				active++
				if sess.EndT > maxEnd {
					maxEnd = sess.EndT
				}
			}
		}
		choices = append(choices, choice{b, active, maxEnd})
	}
	if len(choices) == 0 {
		return nil
	}
	sort.Slice(choices, func(i, j int) bool {
		// Prefer several connections to make draining visible, but among
		// those choose the fleet that finishes soonest.
		if (choices[i].active >= 3) != (choices[j].active >= 3) {
			return choices[i].active >= 3
		}
		if choices[i].maxEnd != choices[j].maxEnd {
			return choices[i].maxEnd < choices[j].maxEnd
		}
		return choices[i].active > choices[j].active
	})
	return choices[0].plan
}

func (s *Scenario) assignOwners() {
	for _, sess := range s.Sessions {
		candidates := s.backendNsAt(sess.StartT, true)
		sess.Owner = initialCIDRoute(sess.InitialDCID, candidates)
	}
}

func (s *Scenario) encodeCIDs(rng *rand.Rand, codec *quicwire.CIDCodec) {
	for _, sess := range s.Sessions {
		// Final owners are known only after drain planning; mint fresh nonces
		// here so a nonce is never reused with a different plaintext backend.
		for i := range sess.CIDNonce {
			sess.CIDNonce[i] = byte(rng.Intn(256))
		}
		cid, err := codec.Encode(sess.Owner, sess.CIDNonce)
		if err != nil {
			panic(err)
		}
		sess.ServerCID = cid
	}
}

func (s *Scenario) backendByID(id string) *BackendPlan {
	for _, b := range s.Backends {
		if b.ID == id {
			return b
		}
	}
	return nil
}

func (s *Scenario) userByN(n int) *UserTrace {
	for _, u := range s.Users {
		if u.N == n {
			return u
		}
	}
	return nil
}

func (s *Scenario) SessionAt(user, t int) *Session {
	var best *Session
	for _, sess := range s.Sessions {
		if sess.User == user && sess.StartT <= t && t < sess.EndT {
			if best == nil || sess.StartT > best.StartT {
				best = sess
			}
		}
	}
	return best
}

func (s *Scenario) nextUsableSession(user, t int) *Session {
	var best *Session
	for _, sess := range s.Sessions {
		if sess.User != user {
			continue
		}
		if sess.EndT < t+6000 {
			continue
		}
		if best == nil || sess.StartT < best.StartT {
			best = sess
		}
	}
	return best
}

func (s *Scenario) migrationAtOrBefore(user, t int) string {
	id := ""
	latest := -1
	for _, sw := range s.Switches {
		if sw.User == user && sw.T <= t && sw.T > latest {
			latest = sw.T
			id = sw.ID
		}
	}
	return id
}

// AddrAt reconstructs the phone's current outer address.
func (s *Scenario) AddrAt(user, t int) Addr {
	u := s.userByN(user)
	fallback := Addr{}
	if u != nil {
		fallback = u.InitialAddr
	}
	latest := -1
	for _, sw := range s.Switches {
		if sw.User == user && sw.T <= t && sw.T > latest {
			latest = sw.T
			fallback = sw.To
		}
	}
	return fallback
}

func makeAddr(rng *rand.Rand, network string, user int) Addr {
	port := 10_000 + rng.Intn(52_000)
	if network == "Wi-Fi" {
		return Addr{
			Network: network,
			IP:      fmt.Sprintf("192.168.%d.%d", rng.Intn(4), 20+rng.Intn(220)),
			Port:    port,
		}
	}
	return Addr{
		Network: network,
		IP:      fmt.Sprintf("100.64.%d.%d", rng.Intn(16), 2+rng.Intn(250)),
		Port:    port,
	}
}

func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return b
}

func formatMS(t int) string {
	if t < 60_000 {
		return fmt.Sprintf("%.1fs", float64(t)/1000)
	}
	return fmt.Sprintf("%d:%04.1f", t/60000, float64(t%60000)/1000)
}
