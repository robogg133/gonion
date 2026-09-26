# Consensus parser fixture provenance

These are fixed, package-owned **structural parser excerpts**, not authenticated
consensuses. They are embedded into the test binary and SHA-256 pinned before
parsing. No test writes these paths. The `.fixture` extension avoids the root
`.gitignore` rule `*.txt`. Do not regenerate them from live-test output as part
of a test run.

## Source and exact extraction

On 2026-09-26 the existing local captures had the following contents:

| Capture under `internal/tests/` | Valid-after (UTC) | Whole-file SHA-256 |
| --- | --- | --- |
| `consensus.txt` | 2026-09-20 13:00:00 | `d892c089e433e6edb818a0289a242b87c98e5229bb5454bdc3ac182455b8846d` |
| `consensus-microdesc.txt` | 2026-08-22 17:00:00 | `324a5cb551d3b777eeda849a74860fed709bcaf57e64a59bf4647e5434938e4e` |

The fixtures concatenate these inclusive, one-based source line ranges without
changing any retained byte (including final newlines):

- `ns.fixture`: `consensus.txt` lines 1–6, 45–57, 61826–61836.
- `microdesc.fixture`: `consensus-microdesc.txt` lines 1–6, 45–57, 66142–66152.

Each retains the initial header, two complete router entries, footer/weights,
and the first signature block. Other headers, routers and signatures are omitted.
The retained signatures therefore **cannot authenticate the excerpts**. Their
purpose here is signature-block framing only. These tests must never mark the
parsed model authenticated or feed it into traffic selection.

Fixture SHA-256:

- ns: `311f5cce0d5ce24fe80c3078eeb6d298efd5c408da407182b3a20b3d8c655d04`
- microdesc: `4dfe402182196b7cb45bdff63df7560b1393ec1223c70d1ea06d869649d49fa9`

Extraction was independently checked using Python byte-range concatenation,
not Gonion's parser. Router field counts and base64-decoded digest sizes were
also checked independently against `torspec/dir-spec.txt` sections 3.4.1
(lines 2300–2318) and 3.9.2 (lines 3387–3420): ns has the server-descriptor digest
in the fourth `r` token; microdesc omits that token and has a SHA-256 digest on
its `m` line. The fixed expected values in the test are transcribed from those
source fields, not computed by the parser under test.

No original acquisition log or authority-certificate bundle was found for these
captures; neither is tracked and neither has Git history. The valid-after is a
document field, not proof of acquisition time. This records local byte provenance
and structural checks, **not authority-signature validation** or a claim that an
independent archive confirmed the original capture. The previous expected ns
value `Iq19MK4LeunyQchPVZ4KzQTlKdI` has no recoverable source in the inspected
repository history; no input was fabricated to reproduce that value.

## Failure and writer inventory

Before isolation,
`go test ./pkg/parsers/usual -run '^TestCapturedFlavors/ns$' -count=1 -v`
failed with `usual_test.go:36: wrong digest`. The current capture's first router
contains `BO/3BB69q10vySM69aT/SGdv50k`, not the old expected digest above.
`common.parseRouter` copies that fourth token directly into `DescriptorDigest`.
There was no evidence of a parser digest-computation defect.

Repository source searches for both capture basenames and filesystem writes
found one capture writer: `internal/tests/consensus_test.go:65`, `TestConsensus`,
which writes the response to `/tor/status-vote/current/consensus` to the relative
path `consensus.txt`. That test runs in parallel when opted in via
`GONION_NETWORK_TESTS=1` (see `internal/tests/helpers_test.go`). It does not check
the write error. It can refresh the capture that previously served as this unit
test's supposedly fixed input. No repository writer for `consensus-microdesc.txt`
was found. This establishes the overwrite mechanism, not which historical run
last wrote the file; external/manual writers cannot be ruled out.

Other references are readers in `pkg/storage/storages/tor/tor_test.go`; that
package's writes use temporary storage paths, not these input captures. The
parser tests now read only their own embedded fixtures, including malformed-input
and weight cases. The original captures and the live writer are unchanged.

The regression checks cover both routers' fixed digests, empty other-flavor
digest fields, fixed relay count, first-router address/port layout, byte-exact
formatting, absence of authentication, and effective malformed-input mutations.
This isolates the baseline without weakening the digest assertion or changing
production parser behavior. It does not replace full-document authentication or
large-consensus coverage elsewhere.
