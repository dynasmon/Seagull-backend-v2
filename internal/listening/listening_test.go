package listening_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/dynasmon/Seagull-backend-v2/internal/event"
	"github.com/dynasmon/Seagull-backend-v2/internal/listening"
	platformv1 "github.com/dynasmon/Seagull-contracts/gen/go/seagull/platform/v1"
)

var noon = time.Date(2026, time.November, 21, 12, 0, 0, 0, time.UTC)

func TestABeaconIsHeldToWhatTheContractSays(t *testing.T) {
	if err := listening.Validate(listening.Beacon("gateway-1", noon, 5*time.Second, true)); err != nil {
		t.Fatalf("a beacon the gateway made was refused: %v", err)
	}
	for field, beacon := range map[string]*platformv1.GatewayBeacon{
		"beacon":         nil,
		"schema_version": {SchemaVersion: 2, Gateway: "gateway-1", At: listening.Beacon("g", noon, time.Second, true).At, Every: durationpb.New(time.Second)},
		"gateway":        listening.Beacon(strings.Repeat("g", listening.MaxGatewayLength+1), noon, 5*time.Second, true),
		"every":          listening.Beacon("gateway-1", noon, 2*time.Minute, true),
		"at":             {SchemaVersion: 1, Gateway: "gateway-1", Every: durationpb.New(time.Second)},
	} {
		var violation *event.Violation
		if err := listening.Validate(beacon); !errors.As(err, &violation) || violation.Field != field {
			t.Errorf("a beacon wrong in %s was answered %v", field, err)
		}
	}
}

func TestAGatewayServesWhileItsBeaconsSayItAdmitsAndKeepArriving(t *testing.T) {
	gateways := listening.NewGateways()
	if gateways.Serving(noon) != 0 {
		t.Fatal("a gateway nobody heard is serving")
	}

	gateways.Heard(listening.Beacon("gateway-1", noon, 5*time.Second, true), noon)
	gateways.Heard(listening.Beacon("gateway-2", noon, 5*time.Second, false), noon)
	if got := gateways.Serving(noon.Add(15 * time.Second)); got != 1 {
		t.Errorf("%d gateways serve, and one admits within three of its intervals", got)
	}
	if got := gateways.Serving(noon.Add(16 * time.Second)); got != 0 {
		t.Errorf("%d gateways serve after three intervals passed without a beacon", got)
	}
	if got := gateways.Serving(noon.Add(-time.Second)); got != 0 {
		t.Errorf("%d gateways serve before they were heard", got)
	}

	gateways.Heard(listening.Beacon("gateway-1", noon.Add(20*time.Second), 5*time.Second, false), noon.Add(20*time.Second))
	if got := gateways.Serving(noon.Add(21 * time.Second)); got != 0 {
		t.Errorf("%d gateways serve after the only one said it stopped admitting", got)
	}
}

func TestAStretchOfListeningEndsAtTheFirstMomentThePlatformWasNotListening(t *testing.T) {
	var stretch listening.Stretch
	if stretch.Lasted(noon, 0) {
		t.Fatal("a platform never seen listening has listened")
	}
	stretch.Mark(noon, true)
	stretch.Mark(noon.Add(time.Minute), true)
	if !stretch.Lasted(noon.Add(5*time.Minute), 5*time.Minute) || stretch.Lasted(noon.Add(5*time.Minute), 6*time.Minute) {
		t.Errorf("a stretch begun at noon lasted otherwise than five minutes by 12:05 (since %s)", stretch.Since())
	}

	stretch.Mark(noon.Add(6*time.Minute), false)
	stretch.Mark(noon.Add(7*time.Minute), true)
	if stretch.Lasted(noon.Add(11*time.Minute), 5*time.Minute) || !stretch.Since().Equal(noon.Add(7*time.Minute)) {
		t.Errorf("a stretch broken at 12:06 still counts from %s", stretch.Since())
	}
}
