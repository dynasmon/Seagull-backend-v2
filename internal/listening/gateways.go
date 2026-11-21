package listening

import (
	"time"

	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

type heard struct {
	admitting bool
	every     time.Duration
	at        time.Time
}

// The newest beacon each gateway was heard to send, timed by when this reader
// heard it rather than by the gateway's own clock: a reader judges what it can
// observe, and two hosts' clocks need not agree.
type Gateways struct {
	newest map[string]heard
}

func NewGateways() *Gateways { return &Gateways{newest: map[string]heard{}} }

func (g *Gateways) Heard(beacon *platformv1.GatewayBeacon, at time.Time) {
	g.newest[beacon.GetGateway()] = heard{
		admitting: beacon.GetAdmitting(),
		every:     beacon.GetEvery().AsDuration(),
		at:        at,
	}
}

// How many gateways said they admit within Missed of their intervals. None is a
// platform nothing an agent sends can reach.
func (g *Gateways) Serving(now time.Time) int {
	serving := 0
	for _, last := range g.newest {
		if last.admitting && !now.Before(last.at) && now.Sub(last.at) <= Missed*last.every {
			serving++
		}
	}
	return serving
}
