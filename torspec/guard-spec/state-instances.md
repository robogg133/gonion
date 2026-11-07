<a id="guard-spec.txt-2"></a>

# State instances

In the algorithm below, we describe a set of persistent and
non-persistent state variables.  These variables should be
treated as an object, of which multiple instances can exist.

In particular, we specify the use of three particular instances:

A. UseBridges

```text
      If UseBridges is set, then we replace the {GUARDS} set in
      [Sec:GUARDS] below with the list of configured
      bridges.  We maintain a separate persistent instance of
      {SAMPLED_GUARDS} and {CONFIRMED_GUARDS} and other derived
      values for the UseBridges case.

      In this case, we impose no upper limit on the sample size.

    B. EntryNodes / ExcludeNodes / Reachable*Addresses /
        FascistFirewall / ClientUseIPv4=0

      If one of the above options is set, and UseBridges is not,
      then we compare the fraction of usable guards in the consensus
      to the total number of guards in the consensus.

      If this fraction is less than {MEANINGFUL_RESTRICTION_FRAC},
      we use a separate instance of the state.

      (While Tor is running, we do not change back and forth between
      the separate instance of the state and the default instance
      unless the fraction of usable guards is 5% higher than, or 5%
      lower than, {MEANINGFUL_RESTRICTION_FRAC}.  This prevents us
      from flapping back and forth between instances if we happen to
      hit {MEANINGFUL_RESTRICTION_FRAC} exactly.

      If this fraction is less than {EXTREME_RESTRICTION_FRAC}, we use a
      separate instance of the state, and warn the user.

      [TODO: should we have a different instance for each set of heavily
      restricted options?]

   C. Default

      If neither of the above variant-state instances is used,
      we use a default instance.
```
