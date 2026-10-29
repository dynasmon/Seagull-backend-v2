package broker

import (
	"errors"
	"fmt"
)

// What an acknowledgement from the backbone is worth. A production backbone
// keeps every record on three replicas and acknowledges one only once two hold
// it, so losing a broker loses nothing it acknowledged; anything less is a
// development backbone, and a deployment says so rather than inheriting it.
type Durability int

const (
	Production Durability = iota
	Development
)

const (
	productionReplicas = 3
	productionInSync   = 2

	durabilityKey = "SEAGULL_BACKBONE_DURABILITY"
)

func (d Durability) String() string {
	switch d {
	case Production:
		return "production"
	case Development:
		return "development"
	default:
		return fmt.Sprintf("durability(%d)", int(d))
	}
}

var ErrBelowProductionDurability = errors.New("below the durability a production backbone keeps")
