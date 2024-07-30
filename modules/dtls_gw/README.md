## About

The dtls_gw module provides a functionality necessary to gateway between
plain unencrypted RTP channels (aka RTP/AVP) into DTLS/SRTP channels (aka
UDP/TLS/RTP/SAVP). It takes care of the certificate validation, encryption
key negotiation and SRTP encryption/decryption.

## Command Protocol

The module supports 5 basic commands, those can be combined with the
respective U or L command with sub-command extension (&&) and module
index:instance (e.g. " && M4:1" for the case of just a single instance
loaded).

 - `S`

   Request/response from "plain" to "enctypted". The command takes no
   arguments, allocates DTLS endpoint if needed and returns session
   mode and key fingerprint.

 - `A DIGEST-ALG CERT-FINGERPRINT [SSRC]`

   Create or configure existing DTLS endpoint to operate according to the
   remote end being 'active' or 'actpass' mode. Returns no extra value unless
   error has occured. In which case -1 is returned.

   SSRC verification is enabled according to the [SSRC] value provided.

 - `P DIGEST-ALG CERT-FINGERPRINT [SSRC]`

   Create or configure existing DTLS endpoint to operate according to the
   remote end accepting 'passive' mode. Returns no extra value unless
   error has occured. In which case -1 is returned.

   SSRC verification is enabled according to the [SSRC] value provided.

 - `D`

   Detach and destroy DTLS context created by the `A` or `P` command.

 - `U`

   Detach and destroy DTLS context created by the `S` command.

## Supported Scenarios with examples:

1. Incoming INVITE with the RTP/AVP. 183/200 OK with UDP/TLS/RTP/SAVP.

```
 -> U [...] && M4:1 S
 <- [.U response.] && actpass SHA-256 [...]
```

 a. Destination is passive.

```
 -> L [...] && M4:1 P SHA-256 [...]
 <- [.L response.]
```

 b. Destination is active.

```
 -> L [...] && M4:1 A SHA-256 [...]
 <- [.L response.]
```

2. Incoming INVITE with the UDP/TLS/RTP/SAVP. 183/200 OK with RTP/AVP.

 a. Us willing to accept in the passive role:

```
 -> U [...] && M4:1 A SHA-256 [...]
 <- [.U response.]

 -> L [...] && M4:1 S
 <- [.L response.] && passive SHA-256 [...]
```

 b. Us willing to accept in the active role:

```
 -> U [...] && M4:1 P SHA-256 [...]
 <- [.U response.]

 -> L [...] && M4:1 S
 <- [.L response.] && active SHA-256 [...]
```


## TODO

 o Session teardown upon DTLS setup and/or key verification failure

## Acknowledgements

We thank Alfred E. Heggestad and baresip project for the good code for
DTLS session and key generation.
