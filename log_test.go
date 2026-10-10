package gonion

import (
	"io"
	"sync"
	"testing"

	"github.com/rs/zerolog"
)

func TestConcurrentConnectionLoggers(t *testing.T) {
	// Service publication builds multiple channels while the application/HS
	// logger emits timestamps. Connection construction must not mutate zerolog's
	// process-global timestamp format underneath those other loggers.
	format := zerolog.TimeFieldFormat
	application := zerolog.New(io.Discard).With().Timestamp().Logger()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 100 {
				l := newLogger(io.Discard, false)
				l.Info().Msg("connection")
				application.Info().Msg("publication")
			}
		})
	}
	wg.Wait()
	if zerolog.TimeFieldFormat != format {
		t.Fatal("connection changed process-global logging configuration")
	}
}
