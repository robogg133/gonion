package gonion

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog"
)

func newLogger(out io.Writer, debug bool) zerolog.Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if out == nil {
		return zerolog.Nop()
	}

	if debug {
		return zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr}).
			Level(zerolog.DebugLevel).
			With().
			Timestamp().
			Logger()
	}
	return zerolog.New(out).
		Level(zerolog.InfoLevel).
		With().
		Timestamp().
		Logger()
}

func logger(ctx context.Context) *zerolog.Logger {
	return zerolog.Ctx(ctx)
}

func withLogger(ctx context.Context, l zerolog.Logger) context.Context {
	return l.WithContext(ctx)
}

// fail logs internal detail and returns a public sentinel-based error.
func fail(ctx context.Context, sentinel error, publicMsg string, err error) error {
	ev := logger(ctx).Error().Str("public", publicMsg)
	if err != nil {
		ev = ev.Err(err)
	}
	ev.Msg("error")
	return Public(sentinel, publicMsg)
}

func failf(ctx context.Context, sentinel error, err error, format string, args ...any) error {
	return fail(ctx, sentinel, fmt.Sprintf(format, args...), err)
}
