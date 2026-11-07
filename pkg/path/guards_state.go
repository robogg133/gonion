package path

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	"github.com/robogg133/gonion/pkg/common"
)

// Guard sampling uses guard-position weights only, not BEGIN_DIR multipliers.
func samplePublicGuard(sl *Selector, sampled map[[20]byte]bool) (*common.RouterStatus, error) {
	var total big.Int
	var values []value
	for i := range sl.list {
		r := &sl.list[i]
		if sampled[r.NodeID] || !guardValideFunc(*r) || !r.StatusFlags[common.FLAG_RUNNING] || !r.StatusFlags[common.FLAG_VALID] {
			continue
		}
		w := weightedBandwidth(r.BandWidth, guardWeightFunc(r.StatusFlags, sl.weight))
		if w <= 0 {
			continue
		}
		v := value{ptr: r}
		v.wb.SetInt64(w)
		total.Add(&total, &v.wb)
		values = append(values, v)
	}
	return selectRandom(&total, values)
}

// encoding/json otherwise accepts duplicate keys with last-value-wins semantics.
func rejectDuplicateGuardFields(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	var read func(int) error
	read = func(depth int) error {
		if depth > 8 {
			return fmt.Errorf("path: guard snapshot nesting limit")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if delim != '{' && delim != '[' {
			return fmt.Errorf("path: invalid guard snapshot delimiter")
		}
		seen := make(map[string]bool)
		for d.More() {
			if delim == '{' {
				token, err := d.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok || seen[key] {
					return fmt.Errorf("path: duplicate guard snapshot field")
				}
				seen[key] = true
			}
			if err := read(depth + 1); err != nil {
				return err
			}
		}
		_, err = d.Token()
		return err
	}
	if err := read(0); err != nil {
		return fmt.Errorf("path: invalid guard snapshot: %w", err)
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("path: trailing guard snapshot data")
	}
	return nil
}
