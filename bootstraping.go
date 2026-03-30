package gonion

import (
	"fmt"

	"git.servidordomal.fun/robogg133/gonion/internal/common"
)

// Bootstrap will get onion keys to make circuits, using 1 conn
func BootstrapOneConn(conn *Conn) error {

	circuit, err := conn.NewFastCircuit(1)
	if err != nil {
		return err
	}
	fmt.Println("created circuit")

	cns, err := circuit.GetConsensus()
	if err != nil {
		return err
	}
	fmt.Println("got consensus")

	var AlldigestsString []string
	for _, relay := range cns.RelayInformation {
		AlldigestsString = append(AlldigestsString, relay.MicrodescriptorDigest)
	}

	for i := 0; i < len(AlldigestsString); i += 91 {
		end := i + 91
		if end > len(AlldigestsString) {
			end = len(AlldigestsString)
		}

		fmt.Println(i)
		chunk := AlldigestsString[i:end]
		if err := circuit.editConsensusKeys(cns, chunk); err != nil {
			return err
		}
	}
	return nil
}

func (circuit *Circuit) editConsensusKeys(cons *common.Consensus, digestsSlice []string) error {
	cons.Mu.Lock()
	defer cons.Mu.Unlock()

	fmt.Println("sending get microdescriptor order")
	desc, err := circuit.GetMicrodescriptors(digestsSlice)
	if err != nil {
		return err
	}

	for i, v := range desc {
		cons.RelayInformation[i].OnionKey = v.OnionKey
		cons.RelayInformation[i].NTorOnionKey = v.NTorOnionKey
		if v.ExitRules != nil {
			cons.RelayInformation[i].Ports = *v.ExitRules
		}
		cons.RelayInformation[i].Family = v.Family
		cons.RelayInformation[i].Familys = v.Familys
		cons.RelayInformation[i].IdEd25519 = v.IdEd25519
	}

	desc = nil

	return nil
}
