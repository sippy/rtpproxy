# RTP Scenario Script

## Table of Contents

1. [Introduction](#introduction)
2. [Overview](#overview)
3. [Requirements](#requirements)
4. [Execution](#execution)
5. [Notes](#notes)

## Introduction

This script utilizes the command line interface (CLI) of RTPProxy for the
purpose of simulating several RTP (Real-Time Transport Protocol) generation,
forwarding, DTLS (Datagram Transport Layer Security) encryption, and
recording scenarios.

## Overview

The script performs the following steps:

1. **Session setup:** Establishes sessions by interfacing with Unix domain
   sockets and setting parameters such as codecs, call identifiers, IP
   addresses, and ports. It also configures routing for RTP and RTCP packets.

2. **Recording initiation:** Begins the recording of RTP streams from the
   gena and geno sockets.

3. **Stream initiation:** Initiates the streaming of RTP packets from both
   gena and geno to the corresponding ports defined during session setup.

4. **Session stats collection:** Gathers transmission statistics such as the
   number of packets sent, received, dropped, and relayed.

5. **DTLS enabling:** Alters the session parameters to implement DTLS
   encryption on the gena side. This requires routing alteration for a
   secure port and setting relevant DTLS parameters.

6. **DTLS-encrypted session initiation:** Begins another streaming session
   with DTLS-encrypted packets.

7. **DTLS-encrypted session stats collection:** Gathers statistics for the
   DTLS-encrypted session.

8. **DTLS disabling:** Disables DTLS encryption and reverts session
   parameters to their original configuration.

9. **Non-encrypted session initiation:** Begins another streaming session
   with the original, non-encrypted settings.

10. **Non-encrypted session stats collection:** Gathers final session
    statistics for the non-encrypted session.

## Requirements

The execution environment must have RTPProxy installed and correctly
configured. Unix domain sockets utilized by the script must be correctly
set up.

## Execution

The script is executed via command line and does not require arguments.
Ensure proper permissions to execute the script and access the necessary
sockets and ports. Monitor the output for error messages or warnings, which
may indicate issues with the RTP sessions or network configuration.

## Notes

The script showcases how RTPProxy's CLI can be utilized for simulating
various RTP and RTCP scenarios, including DTLS encryption. It demonstrates
the dynamic modification of RTP parameters, statistics collection, and the
configuration of secure and non-secure sessions.
