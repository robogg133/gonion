# Tor Guard Specification

<a id="guard-spec.txt-1"></a>

## Introduction and motivation

Tor uses entry guards to prevent an attacker who controls some
fraction of the network from observing a fraction of every user's
traffic. If users chose their entries and exits uniformly at
random from the list of servers every time they build a circuit,
then an adversary who had (k/N) of the network would deanonymize
F=(k/N)^2 of all circuits... and after a given user had built C
circuits, the attacker would see them at least once with
probability 1-(1-F)^C.  With large C, the attacker would get a
sample of every user's traffic with probability 1.

To prevent this from happening, Tor clients choose a small number
of guard nodes (e.g. 3).  These guard nodes are the only
nodes that the client will connect to directly.  If they are not
compromised, the user's paths are not compromised.

This specification outlines Tor's guard housekeeping algorithm,
which tries to meet the following goals:

* Heuristics and algorithms for determining how and which guards
  are chosen should be kept as simple and easy to understand as
  possible.
* Clients in censored regions or who are behind a fascist
  firewall who connect to the Tor network should not experience
  any significant disadvantage in terms of reachability or
  usability.
* Tor should make a best attempt at discovering the most
  appropriate behavior, with as little user input and
  configuration as possible.
* Tor clients should discover usable guards without too much
  delay.
* Tor clients should resist (to the extent possible) attacks
  that try to force them onto compromised guards.
* Should maintain the load-balancing offered by the path selection
  algorithm.
