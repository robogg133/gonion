# gonion-net.py - checked-in Chutney topology for internal/tests/chutney_test.go.
#
# Used by TestChutneyLongRunningService (opt-in via GONION_TEST_CHUTNEY=1).
# Do not edit the adaptations below without updating the test's setup comments.
#
# Pinned versions (recorded for reproducibility):
#   Chutney: git commit dbc640bf4863d4e3d6cb1ad9879b41f9f5862c4e
#   C Tor: 0.4.9.11 (supported stable release; Ubuntu package tor 0.4.9.11)
#
# Topology is basic-min with two required adaptations for Gonion:
#   - one IPv4 /16 per node, because Gonion enforces path-spec subnet diversity
#     and basic-min puts every node on 127.0.0.1, which makes all circuit
#     candidates conflict;
#   - a plain non-exit relay instead of an exit relay, because a consensus from
#     only these authorities gives a Guard+Exit relay guard weight Wgd=0, which
#     Gonion's public guard manager cannot sample. Onion client and service
#     circuits never need an exit relay.

Authority = Node(tag="a", authority=1, relay=1)
NonExitRelay = Node(tag="r", relay=1)
Client = Node(tag="c", client=1)
ConfigureNodes([
    Node(tag="a", authority=1, relay=1, ip="127.0.0.1"),
    Node(tag="a", authority=1, relay=1, ip="127.1.0.1"),
    Node(tag="a", authority=1, relay=1, ip="127.2.0.1"),
    Node(tag="a", authority=1, relay=1, ip="127.3.0.1"),
    Node(tag="r", relay=1, ip="127.4.0.1"),
    Node(tag="c", client=1, ip="127.5.0.1"),
])
