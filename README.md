## HEPConnector

This project provides an HEPv3 client implementation intended for use in other
C-based projects. Loosely based on hep-c reference implementation.

## What is HEP?

<b>HEP/EEP Encapsulation Protocol</b>

EEP/HEP: Extensible Encapsulation protocol provides a method to duplicate an IP
datagram to a collector by encapsulating the original datagram and its relative header properties 
(as payload, in form of concatenated chunks) within a new IP datagram transmitted over UDP/TCP/SCTP
connections for remote collection. Encapsulation allows for the original content to be transmitted 
without altering the original IP datagram and header contents and provides flexible allocation of
additional chunks containing additional arbitrary data.
