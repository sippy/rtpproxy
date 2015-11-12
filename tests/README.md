# Integration Tests

This directory contains a suite of tests that exercises the RTPProxy
command channel, and various aspects of the RTPProxy operation. 

Running `make check` in the root RTPProxy directory will run these tests.
The RTPProxy repository is hooked up to a continuous integration services
(travis or drone.io) that will automatically run all tests.

## RTPProxy payload conventions

The tests make use of prerecorded files that are encoded in various
formats (payloads). Each file has a numeric suffix that represents the
payload type as defined in [rfc3551 Section 6. Payload Type
Definitions)][0]

## Adding new tests

To add additional tests, create a Bourne shell script, and turn on the
executable file bit. If your test requires supporting files, such files
should use the same name as the test script, and use a suffix that
reasonably describes its purpose.

[0]: http://tools.ietf.org/html/rfc3551#section-6

