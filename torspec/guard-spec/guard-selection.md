<a id="guard-spec.txt-3"></a>

# Circuit Creation, Entry Guard Selection (1000 foot view) {#1000-foot}

A circuit in Tor is a path through the network connecting a client to
its destination. At a high-level, a three-hop exit circuit will look
like this:

Client \<-> Entry Guard \<-> Middle Node \<-> Exit Node \<-> Destination

Entry guards are the only nodes which a client will connect to
directly. Exit relays are the nodes by which traffic exits the
Tor network in order to connect to an external destination.

## Path selection

For any multi-hop circuit, at least one entry guard and middle node(s) are
required. An exit node is required if traffic will exit the Tor
network. Depending on its configuration, a relay listed in a
consensus could be used for any of these roles. However, this
specification defines how entry guards specifically should be selected and
managed, as opposed to middle or exit nodes.

### Managing entry guards

At a high level, a relay listed in a consensus will move through the
following states in the process from initial selection to eventual
usage as an entry guard:

```text
      relays listed in consensus
                 |
               sampled
               |     |
         confirmed   filtered
               |     |      |
               primary      usable_filtered
```

Relays listed in the latest consensus can be sampled for guard usage
if they have the "Guard" flag. Sampling is random but weighted by
a measured bandwidth multiplied by bandwidth-weights (Wgg if guard only,
Wgd if guard+exit flagged).

Once a path is built and a circuit established using this guard, it
is marked as confirmed. Until this point, guards are first sampled
and then filtered based on information such as our current
configuration (see SAMPLED and FILTERED sections) and later marked as
usable_filtered if the guard is not primary but can be reached.

It is always preferable to use a primary guard when building a new
circuit in order to reduce guard churn; only on failure to connect to
existing primary guards will new guards be used.

### Middle and exit node selection

Middle nodes are selected at random from relays listed in the latest
consensus, weighted by bandwidth and bandwidth-weights. Exit nodes are
chosen similarly but restricted to relays with a sufficiently permissive
exit policy.

## Circuit Building

Once a path is chosen, Tor will use this path to build a new circuit.

If the circuit is built successfully, Tor will either use it
immediately, or Tor will wait for a circuit with a more preferred
guard if there's a good chance that it will be able to make one.

If the circuit fails in a way that makes us conclude that a guard
is not reachable, the guard is marked as unreachable, the circuit is
closed, and waiting circuits are updated.
