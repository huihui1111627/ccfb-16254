package sim

import (
	"fmt"
	"strings"
)

// Config controls one deterministic local simulation run.
type Config struct {
	Seed             int64  `json:"seed"`
	Users            int    `json:"users"`
	DurationMS       int    `json:"durationMs"`
	PacketIntervalMS int    `json:"packetIntervalMs"`
	SharedSecret     string `json:"-"`
}

func DefaultConfig() Config {
	return Config{
		Seed:             20261125,
		Users:            96,
		DurationMS:       160_000,
		PacketIntervalMS: 430,
		SharedSecret:     "local-demo-shared-secret-rotate-me",
	}
}

// Addr is the simulated outer IP/UDP source address.
type Addr struct {
	Network string `json:"network"`
	IP      string `json:"ip"`
	Port    int    `json:"port"`
}

func (a Addr) String() string { return fmt.Sprintf("%s:%d", a.IP, a.Port) }
func (a Addr) Key() string    { return a.Network + "|" + a.String() }

// Switch is one phone network attachment change.
type Switch struct {
	ID     string `json:"id"`
	User   int    `json:"user"`
	T      int    `json:"t"`
	From   Addr   `json:"from"`
	To     Addr   `json:"to"`
	Reason string `json:"reason"`
}

// Session is a logical phone connection. In CID mode it is one QUIC
// connection; in legacy mode it may contain several rehandshake generations.
type Session struct {
	ID             string  `json:"id"`
	User           int     `json:"user"`
	Index          int     `json:"index"`
	StartT         int     `json:"startT"`
	EndT           int     `json:"endT"`
	InitialDCID    []byte  `json:"-"`
	ClientSCID     []byte  `json:"-"`
	CIDNonce       [7]byte `json:"-"`
	Owner          uint32  `json:"owner"`
	ServerCID      []byte  `json:"-"`
	LatestSwitchID string  `json:"-"`
}

// Offer is a simulated packet transmission opportunity. Loss and delay are
// chosen when the scenario is generated so both routing modes see identical
// network conditions.
type Offer struct {
	ID          int    `json:"id"`
	User        int    `json:"user"`
	SessionID   string `json:"sessionId"`
	Seq         int    `json:"seq"`
	SendT       int    `json:"sendT"`
	ArrivalT    int    `json:"arrivalT"`
	Src         Addr   `json:"src"`
	Kind        string `json:"kind"`
	Size        int    `json:"size"`
	Lost        bool   `json:"lost"`
	ReorderHint bool   `json:"reorderHint"`
	MigrationID string `json:"migrationId"`
}

// BackendPlan describes backend lifecycle shared by both comparisons.
type BackendPlan struct {
	N          uint32 `json:"n"`
	ID         string `json:"id"`
	Addr       string `json:"addr"`
	AddedT     int    `json:"addedT"`
	DrainT     int    `json:"drainT"`
	RemoveT    int    `json:"removeT"`
	DrainConns int    `json:"drainConns"`
}

// Restart windows model failure detection and process recovery.
type Restart struct {
	At           int `json:"at"`
	HealthDownT  int `json:"healthDownT"`
	ProcessBackT int `json:"processBackT"`
	HealthyT     int `json:"healthyT"`
}

// LBPlan is one stateless load-balancer instance.
type LBPlan struct {
	N        int       `json:"n"`
	ID       string    `json:"id"`
	AddedT   int       `json:"addedT"`
	RemovedT int       `json:"removedT"`
	Restarts []Restart `json:"restarts"`
}

// OpEvent is an infrastructure timeline annotation.
type OpEvent struct {
	T      int    `json:"t"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Tone   string `json:"tone"`
}

// Forgery is an active attempt to use a self-selected backend identity in a
// CID without knowing the MAC key.
type Forgery struct {
	T            int    `json:"t"`
	Src          Addr   `json:"src"`
	Claimed      uint32 `json:"claimed"`
	CID          []byte `json:"-"`
	UseOldSecret bool   `json:"useOldSecret"`
}

// Scenario is the deterministic input shared by both routing approaches.
type Scenario struct {
	Config    Config         `json:"config"`
	Users     []*UserTrace   `json:"users"`
	Switches  []*Switch      `json:"switches"`
	Sessions  []*Session     `json:"sessions"`
	Offers    []*Offer       `json:"offers"`
	Backends  []*BackendPlan `json:"backends"`
	LBs       []*LBPlan      `json:"lbs"`
	Ops       []*OpEvent     `json:"ops"`
	Forgeries []*Forgery     `json:"-"`
}

type UserTrace struct {
	ID          string   `json:"id"`
	N           int      `json:"n"`
	StartNet    string   `json:"startNet"`
	InitialAddr Addr     `json:"initialAddr"`
	SessionIDs  []string `json:"sessionIds"`
}

type Stats struct {
	Offered         int     `json:"offered"`
	Lost            int     `json:"lost"`
	Arrived         int     `json:"arrived"`
	Reordered       int     `json:"reordered"`
	ParseErrors     int     `json:"parseErrors"`
	Correct         int     `json:"correct"`
	Misrouted       int     `json:"misrouted"`
	Delivered       int     `json:"delivered"`
	LongPackets     int     `json:"longPackets"`
	ShortPackets    int     `json:"shortPackets"`
	VNPackets       int     `json:"vnPackets"`
	ResetPackets    int     `json:"resetPackets"`
	ForgedTotal     int     `json:"forgedTotal"`
	ForgedRejected  int     `json:"forgedRejected"`
	ForgedAccepted  int     `json:"forgedAccepted"`
	LBRestartDrops  int     `json:"lbRestartDrops"`
	Rehandshakes    int     `json:"rehandshakes"`
	Migrations      int     `json:"migrations"`
	Preserved       int     `json:"preserved"`
	Uploads         int     `json:"uploads"`
	UploadOK        int     `json:"uploadOk"`
	UploadFailed    int     `json:"uploadFailed"`
	TotalStallMS    int     `json:"totalStallMs"`
	BackendCV       float64 `json:"backendCv"`
	JainFairness    float64 `json:"jainFairness"`
	LBDisagreements int     `json:"lbDisagreements"`
}

type PacketRecord struct {
	ID          string `json:"id"`
	TraceID     string `json:"traceId"`
	User        int    `json:"user"`
	Gen         int    `json:"gen"`
	Seq         int    `json:"seq"`
	SendT       int    `json:"sendT"`
	T           int    `json:"t"`
	Kind        string `json:"kind"`
	Header      string `json:"header"`
	Src         Addr   `json:"src"`
	LB          string `json:"lb"`
	Expected    string `json:"expected"`
	Routed      string `json:"routed"`
	Correct     bool   `json:"correct"`
	Lost        bool   `json:"lost"`
	Reordered   bool   `json:"reordered"`
	MigrationID string `json:"migrationId,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

type ConnectionInfo struct {
	ID                string `json:"id"`
	User              int    `json:"user"`
	Gen               int    `json:"gen"`
	ParentID          string `json:"parentId,omitempty"`
	StartT            int    `json:"startT"`
	EndT              int    `json:"endT"`
	Owner             string `json:"owner"`
	SourceNetwork     string `json:"sourceNetwork,omitempty"`
	SourceAddr        string `json:"sourceAddr,omitempty"`
	CIDPreview        string `json:"cidPreview"`
	InitialCIDPreview string `json:"initialCidPreview,omitempty"`
	Packets           int    `json:"packets"`
	Wrong             int    `json:"wrong"`
	Preserved         *bool  `json:"preserved,omitempty"`
	Rehandshake       bool   `json:"rehandshake"`
	StallMS           int    `json:"stallMs"`
}

type RouteOutcome struct {
	BeforeBackend string `json:"beforeBackend"`
	AfterBackend  string `json:"afterBackend"`
	Preserved     bool   `json:"preserved"`
	Wrong         int    `json:"wrong"`
	Rehandshake   bool   `json:"rehandshake"`
	StallMS       int    `json:"stallMs"`
	UploadFailed  bool   `json:"uploadFailed"`
	RecoveryMS    int    `json:"recoveryMs"`
}

type Migration struct {
	ID        string       `json:"id"`
	User      int          `json:"user"`
	T         int          `json:"t"`
	From      Addr         `json:"from"`
	To        Addr         `json:"to"`
	Reason    string       `json:"reason"`
	SessionID string       `json:"sessionId"`
	LBBefore  string       `json:"lbBefore"`
	LBAfter   string       `json:"lbAfter"`
	LBChanged bool         `json:"lbChanged"`
	CID       RouteOutcome `json:"cid"`
	Old       RouteOutcome `json:"old"`
}

type BackendView struct {
	*BackendPlan
	CIDPackets int     `json:"cidPackets"`
	OldPackets int     `json:"oldPackets"`
	CIDConns   int     `json:"cidConns"`
	OldGens    int     `json:"oldGens"`
	CIDShare   float64 `json:"cidShare"`
	OldShare   float64 `json:"oldShare"`
}

type LoadPoint struct {
	T        int            `json:"t"`
	CID      map[string]int `json:"cid"`
	Old      map[string]int `json:"old"`
	CIDConns map[string]int `json:"cidConns"`
	OldConns map[string]int `json:"oldConns"`
}

type CIDExample struct {
	Backend string `json:"backend"`
	CID     string `json:"cid"`
}

type SecurityInfo struct {
	Algorithm      string `json:"algorithm"`
	AgreedLength   int    `json:"agreedLength"`
	ForgedTotal    int    `json:"forgedTotal"`
	ForgedRejected int    `json:"forgedRejected"`
	ForgedAccepted int    `json:"forgedAccepted"`
	WrongKeyReject bool   `json:"wrongKeyReject"`
}

type ModeReport struct {
	Mode        string           `json:"mode"`
	Label       string           `json:"label"`
	Description string           `json:"description"`
	Stats       Stats            `json:"stats"`
	Connections []ConnectionInfo `json:"connections"`
}

type Report struct {
	Config      Config         `json:"config"`
	CID         *ModeReport    `json:"cid"`
	Old         *ModeReport    `json:"old"`
	Migrations  []*Migration   `json:"migrations"`
	Users       []*UserTrace   `json:"users"`
	Ops         []*OpEvent     `json:"ops"`
	Backends    []*BackendView `json:"backends"`
	LBs         []*LBPlan      `json:"lbs"`
	LoadSeries  []LoadPoint    `json:"loadSeries"`
	CIDExamples []CIDExample   `json:"cidExamples"`
	Security    SecurityInfo   `json:"security"`
}

// Result keeps full packet traces out of the initial report payload while the
// web layer can still query them by connection.
type Result struct {
	Report     *Report
	cidPackets map[string][]PacketRecord
	oldPackets map[string][]PacketRecord
}

func (r *Result) Packets(mode, traceID string) []PacketRecord {
	// Connection generation IDs look like session#g2, while packet records are
	// stored under the parent logical session so the full handoff is visible.
	if i := strings.IndexByte(traceID, '#'); i >= 0 {
		traceID = traceID[:i]
	}
	if mode == "old" {
		return r.oldPackets[traceID]
	}
	return r.cidPackets[traceID]
}
