<a id="guard-spec.txt-A"></a>

# Appendices

<a id="guard-spec.txt-A.0"></a>

## Acknowledgements

This research was supported in part by NSF grants CNS-1111539,
CNS-1314637, CNS-1526306, CNS-1619454, and CNS-1640548.

<a id="guard-spec.txt-A.1"></a>

## Parameters with suggested values. {#PARAM_VALS}

(All suggested values chosen arbitrarily)

{param:MAX_SAMPLE_THRESHOLD} -- 20%

{param:MAX_SAMPLE_SIZE} -- 60

{param:GUARD_LIFETIME} -- 120 days

```text
   {param:REMOVE_UNLISTED_GUARDS_AFTER} -- 20 days
     [previously ENTRY_GUARD_REMOVE_AFTER]

   {param:MIN_FILTERED_SAMPLE} -- 20

   {param:N_PRIMARY_GUARDS} -- 3

   {param:PRIMARY_GUARDS_RETRY_SCHED}

      We recommend the following schedule, which is the one
      used in Arti:

      -- Use the "decorrelated-jitter" algorithm from "dir-spec.txt"
         section 5.5 where `base_delay` is 30 seconds and `cap`
         is 6 hours.

      This legacy schedule is the one used in C tor:

      -- every 10 minutes for the first six hours,
      -- every 90 minutes for the next 90 hours,
      -- every 4 hours for the next 3 days,
      -- every 9 hours thereafter.

   {param:GUARDS_RETRY_SCHED} --

      We recommend the following schedule, which is the one
      used in Arti:

      -- Use the "decorrelated-jitter" algorithm from "dir-spec.txt"
         section 5.5 where `base_delay` is 10 minutes and `cap`
         is 36 hours.

      This legacy schedule is the one used in C tor:

      -- every hour for the first six hours,
      -- every 4 hours for the 90 hours,
      -- every 18 hours for the next 3 days,
      -- every 36 hours thereafter.

   {param:INTERNET_LIKELY_DOWN_INTERVAL} -- 10 minutes

   {param:NONPRIMARY_GUARD_CONNECT_TIMEOUT} -- 15 seconds

   {param:NONPRIMARY_GUARD_IDLE_TIMEOUT} -- 10 minutes

   {param:MEANINGFUL_RESTRICTION_FRAC} -- .2

   {param:EXTREME_RESTRICTION_FRAC} -- .01

   {param:GUARD_CONFIRMED_MIN_LIFETIME} -- 60 days

   {param:NUM_USABLE_PRIMARY_GUARDS} -- 1

   {param:NUM_USABLE_PRIMARY_DIRECTORY_GUARDS} -- 3
```

<a id="guard-spec.txt-A.2"></a>

## Random values {#RANDOM}

Frequently, we want to randomize the expiration time of something
so that it's not easy for an observer to match it to its start
time. We do this by randomizing its start date a little, so that
we only need to remember a fixed expiration interval.

By RAND(now, INTERVAL) we mean a time between now and INTERVAL in
the past, chosen uniformly at random.

<a id="guard-spec.txt-A.5"></a>

## Persistent state format {#persistent-state}

The persistent state format doesn't need to be part of this
specification, since different implementations can do it
differently. Nonetheless, here's the one Tor uses:

The "state" file contains one Guard entry for each sampled guard
in each instance of the guard state (see section 2).  The value
of this Guard entry is a set of space-separated K=V entries,
where K contains any nonspace character except =, and V contains
any nonspace characters.

Implementations must retain any unrecognized K=V entries for a
sampled guard when they regenerate the state file.

The order of K=V entries is not allowed to matter.

Recognized fields (values of K) are:

```text
        "in" -- the name of the guard state instance that this
        sampled guard is in.  If a sampled guard is in two guard
        states instances, it appears twice, with a different "in"
        field each time. Required.

        "rsa_id" -- the RSA id digest for this guard, encoded in
        hex. Required.

        "bridge_addr" -- If the guard is a bridge, its configured address and
        port (this can be the ORPort or a pluggable transport port). Optional.

        "nickname" -- the guard's nickname, if any. Optional.

        "sampled_on" -- the date when the guard was sampled. Required.

        "sampled_by" -- the Tor version that sampled this guard.
        Optional.

        "unlisted_since" -- the date since which the guard has been
        unlisted. Optional.

        "listed" -- 0 if the guard is not listed; 1 if it is. Required.

        "confirmed_on" -- date when the guard was
        confirmed. Optional.

        "confirmed_idx" -- position of the guard in the confirmed
        list. Optional.

        "pb_use_attempts", "pb_use_successes", "pb_circ_attempts",
        "pb_circ_successes", "pb_successful_circuits_closed",
        "pb_collapsed_circuits", "pb_unusable_circuits",
        "pb_timeouts" -- state for the circuit path bias algorithm,
        given in decimal fractions. Optional.
```

All dates here are given as a [DateTime] in
UTC (e.g., 2016-11-29T19:39:31).

[DateTime]: ../intro/conventions.md#datetime
