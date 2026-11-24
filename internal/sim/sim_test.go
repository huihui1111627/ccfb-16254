package sim

import "testing"

func TestCIDRoutingSurvivesEveryMigration(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Users = 48
	result, err := Run(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := result.Report
	if r.CID.Stats.Misrouted != 0 {
		t.Fatalf("CID mode misrouted %d packets", r.CID.Stats.Misrouted)
	}
	if r.CID.Stats.ParseErrors != 0 {
		t.Fatalf("CID parser errors = %d", r.CID.Stats.ParseErrors)
	}
	if r.CID.Stats.Preserved != r.CID.Stats.Migrations {
		t.Fatalf("preserved %d of %d migrations", r.CID.Stats.Preserved, r.CID.Stats.Migrations)
	}
	for _, m := range r.Migrations {
		if !m.CID.Preserved || m.CID.Wrong != 0 {
			t.Fatalf("migration %s not preserved: %+v", m.ID, m.CID)
		}
		if m.SessionID == "" {
			t.Fatalf("migration %s was not placed in an active session", m.ID)
		}
	}
	if r.Security.ForgedRejected != r.Security.ForgedTotal || r.Security.ForgedAccepted != 0 {
		t.Fatalf("forged CID handling: %+v", r.Security)
	}
	if r.CID.Stats.LBDisagreements != 0 {
		t.Fatalf("LB instances disagreed on %d routes", r.CID.Stats.LBDisagreements)
	}
}

func TestLegacyAddressHashShowsMigrationDamage(t *testing.T) {
	result, err := Run(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	s := result.Report.Old.Stats
	if s.Misrouted == 0 || s.Rehandshakes == 0 || s.UploadFailed == 0 {
		t.Fatalf("expected legacy mode to show breakage, got %+v", s)
	}
	if s.Preserved >= s.Migrations {
		t.Fatalf("legacy mode unexpectedly preserved all %d migrations", s.Migrations)
	}
}

func TestDrainsExcludeNewSessionsButKeepOldOnes(t *testing.T) {
	sc, _, err := GenerateScenario(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	drains := 0
	for _, b := range sc.Backends {
		if b.DrainT == 0 {
			continue
		}
		drains++
		if b.RemoveT <= b.DrainT {
			t.Fatalf("backend %s has invalid drain window %d..%d", b.ID, b.DrainT, b.RemoveT)
		}
		for _, s := range sc.Sessions {
			if s.Owner != b.N {
				continue
			}
			if s.StartT >= b.DrainT {
				t.Fatalf("draining backend %s received new session %s at %d", b.ID, s.ID, s.StartT)
			}
		}
	}
	if drains != 2 {
		t.Fatalf("planned %d drain operations, want 2", drains)
	}
}

func TestPacketTraceLookup(t *testing.T) {
	result, err := Run(DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	trace := result.Report.CID.Connections[0].ID
	if packets := result.Packets("cid", trace); len(packets) == 0 {
		t.Fatal("expected CID packet trace")
	}
	if packets := result.Packets("old", trace); len(packets) == 0 {
		t.Fatal("expected legacy packet trace for same logical session")
	}
	if packets := result.Packets("old", trace+"#g2"); len(packets) == 0 {
		t.Fatal("generation trace lookup did not fall back to parent session")
	}
}
