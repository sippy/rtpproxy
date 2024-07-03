## About

The `ice_lite` module provides functionality necessary to establish and support
ICE sessions using the lite variant of the ICE protocol as defined in RFC5245
and related RFCs. For convenience, it also implements RTCP multiplexing and
de-multiplexing.

## Command Protocol

The module supports 5 basic commands. These can be combined with the respective
`U` or `L` command with sub-command extension (`&&`) and module index:instance
(e.g., `&& M5:1` for the case of a single instance loaded).

- `S`

  Generate an ICE offer to an ICE-enabled UA. The command takes no arguments,
  allocates an ICE endpoint if needed, and returns the local `ice-ufrag`,
  `ice-pwd`, and a set of ICE candidates (URL-encoded).

- `A ice-ufrag ice-pwd`

  Process an ICE offer received from the ICE-enabled UA. The command allocates
  an ICE endpoint if needed. Returns no extra value unless an error occurs, in
  which case `-1` is returned.

- `C CANDIDATE`

  Register a single ICE candidate received from the ICE-enabled UA. Requires an
  existing ICE endpoint. Returns no extra value unless an error occurs, in which
  case `-1` is returned.

  The command can be repeated multiple times to supply the full set of
  candidates.

- `D`

  Detach and destroy the ICE context in the forward direction.

- `U`

  Detach and destroy the ICE context in the reverse direction.

## Supported Scenarios with Examples:

1. Incoming INVITE with the ICE offer.

```
 -> U [...] && M5:1 A [ice-ufrag] [ice-pwd] && M5:1 C [ice-candidate1] && M5:1 C [ice-candidate2]
 <- [.U response.]
```

 - 183/200 with SDP answer.

```
 -> L [...] && M5:1 S
 <- [.L response.] && [ice-ufrag] [ice-pwd] c:[ice-candidate1]
```

2. Outbound INVITE with the ICE offer.

```
 -> U [...] && M5:1 S
 <- [.U response.] && [ice-ufrag] [ice-pwd] c:[ice-candidate1]
```

 - 183/200 with SDP answer.

```
 -> L [...] && M5:1 A [ice-ufrag] [ice-pwd] && M5:1 C [ice-candidate1] && M5:1 C [ice-candidate2]
 <- [.L response.]
```

## TODO

- Implement full ICE
- Separate RTCP mux/demux into its own module

## Acknowledgements

We thank Alfred E. Heggestad and the baresip project for their excellent ICE
support code.
