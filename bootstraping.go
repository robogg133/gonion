package gonion

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/robogg133/gonion/pkg/common"
)

// nextConsensus will refresh the consensus when needed
func (circuit *Circuit) nextConsensus(ctx context.Context, cns *common.Consensus) {

	select {
	case <-ctx.Done():
		return
	default:
	}

	minutesBetweenFreshAndValid := (cns.FreshUntil.Hour() - cns.ValidAfter.Hour()) * 60

	minutes := (time.Duration(minutesBetweenFreshAndValid) / 4) * 3 * time.Minute
	start := cns.FreshUntil.Add(minutes)

	minutesBetweenFreshAndUnvalid := (cns.ValidUntil.Hour() - cns.FreshUntil.Hour()) * 60
	minutes = (time.Duration(minutesBetweenFreshAndUnvalid) / 8) * 7 * time.Minute
	end := cns.FreshUntil.Add(minutes)

	ns := start.Unix()
	ne := end.Unix()

	fetchTimestamp := rand.Int63n(ne-ns) + ns

	fetchTime := time.Unix(fetchTimestamp, 0).UTC()

	// Sleeping until new fetch
	if err := sleepCtx(ctx, time.Until(fetchTime)); err != nil {
		return
	}

	cnsPtr, err := circuit.GetConsensus()
	if err != nil {
		panic(err)
	}

	*cns = *cnsPtr

	go circuit.nextConsensus(ctx, cns)
}

// Bootstrap will get onion keys to make circuits, using 1 conn
func BootstrapOneConn(conn *Conn) error {

	circuit, err := conn.NewFastCircuit(1)
	if err != nil {
		return err
	}

	cns, err := circuit.GetConsensus()
	if err != nil {
		return err
	}

	var AlldigestsString []string
	for _, relay := range cns.RelayInformation {
		AlldigestsString = append(AlldigestsString, relay.MicrodescriptorDigest)
	}

	for i := 0; i < len(AlldigestsString); i += 91 {
		end := i + 91

		if end > len(AlldigestsString) {
			end = len(AlldigestsString)
		}

		chunk := AlldigestsString[i:end]
		if err := circuit.fetchAndApplyMicrodescriptors(cns, chunk, i); err != nil {
			return err
		}
	}
	return nil
}

func (circuit *Circuit) fetchAndApplyMicrodescriptors(cons *common.Consensus, digestsSlice []string, offest int) error {

	desc, err := circuit.GetMicrodescriptors(digestsSlice)
	if err != nil {
		return err
	}

	for i, v := range desc {
		if v == nil {
			continue
		}
		idx := offest + i
		if idx >= len(cons.RelayInformation) {
			return fmt.Errorf("fetchAndApplyMicrodescriptors: index out of bounds: %d", idx)
		}

		cons.RelayInformation[idx].OnionKey = v.OnionKey
		cons.RelayInformation[idx].NTorOnionKey = v.NTorOnionKey
		if v.ExitRules != nil {
			cons.RelayInformation[idx].Ports = *v.ExitRules
		}
		cons.RelayInformation[idx].Family = v.Family
		cons.RelayInformation[idx].Familys = v.Familys
		cons.RelayInformation[idx].IdEd25519 = v.IdEd25519
	}

	desc = nil

	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}

	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}

}
