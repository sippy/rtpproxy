# RTPProxy Testing Language (RPTL)

## Table of Contents

1. [Introduction](#introduction)
2. [Language Description](#language-description)
   - [Script Structure](#script-structure)
   - [Sockets](#sockets)
   - [Commands](#commands)
   - [Variables and Output](#variables-and-output)
   - [Transformation Functions](#transformation-functions)
   - [Built-ins](#built-ins)
   - [External Commands](#external-commands)
3. [Running RPTL Scripts](#running-rptl-scripts)
4. [Example](#example)
5. [More Examples](#more-examples)

## Introduction

RTPProxy Testing Language (RPTL) is a domain-specific language for writing
tests for RTP packet forwarding and processing services such as RTPProxy.
A script defines control sockets, sends raw RTPProxy commands over them,
checks the replies, and drives external tools such as traffic generators
and recording analyzers.

Since a script can start its own rtpproxy instances and pass whatever ports
they allocate on to subsequent commands and tools, tests written in RPTL do
not need any pre-determined ports and can safely run in parallel.

## Language Description

### Script Structure

A script is a sequence of statements, one per line:

```
# comment
socket NAME: ADDRESS [PARAMS ...] [-> LOGFILE]
NAME: ACTION [-> OUTPUT]
```

Statements are executed strictly in order. A command sent to rtpproxy is
not followed by the next statement until its reply has been received,
which fails the script if it does not arrive within the number of seconds
given by the `CMD_TIMEOUT` variable (2 by default). The variable is looked
up for each command, so the limit can be changed in the middle of a script.
Any failure (an error from the rtpproxy client, a failed check, a non-zero
exit code of an external command, a timeout) stops the script and fails it.

Lines starting with `#` are comments. The sequence `->` separates an action
from its output specification, so it cannot appear inside the action itself.

### Sockets

A socket is a named control connection to an rtpproxy instance, optionally
logging every reply received into `LOGFILE`:

```
socket gena: cunix:/tmp/forwarding3.sock -> gena.rout
```

`ADDRESS` is anything accepted by the sippy `Rtp_proxy_client`, e.g.
`unix:/path`, `cunix:/path`, `udp:host:port` or `tcp:host:port`.

The special address `stdio:` makes RPTL start a managed rtpproxy instance
of its own, connected via a socket pair, with `PARAMS` passed as extra
command line arguments:

```
.eval: ../src/rtpproxy_debug -> RTPPROXY_BIN
.eval: alice.rlog -> RTPPROXY_STDERR
.eval: -d dbug -p /dev/null -l 127.0.0.1 -> RTPPROXY_ARGS
socket alice: stdio: %%RTPPROXY_ARGS%% -> alice.rout
```

The binary is taken from the `RTPPROXY_BIN` variable (`rtpproxy` if not set)
and is invoked as `RTPPROXY_BIN -f -s stdio: PARAMS...`. If `RTPPROXY_STDERR`
is set, rtpproxy stderr is written into that file, otherwise it is inherited
from the RPTL runner. Both variables are looked up when the socket statement
is executed, so they can be changed between sockets. `PARAMS` are split
shell-style after variable expansion, so one variable can carry several
arguments.

The addresses `udp:`, `udp6:`, `tcp:`, `tcp6:`, `unix:` and `cunix:`,
with nothing after the type, also start a managed instance, using a control
socket of that type instead. RPTL creates the socket, bound to an ephemeral
port on the loopback address (or to a path in a temporary directory for the
UNIX domain ones), passes it to rtpproxy as `-s fd:N` and connects to it, so
no port needs to be chosen in advance:

```
socket bob: udp6: -d dbug -T10 -> bob.rout
```

A managed instance runs until its socket is closed with `.close:` or the
script ends. Closing a `stdio:` socket makes rtpproxy exit on its own; if it
has not done so within 5 seconds it is terminated. Instances using other
types of control socket are terminated right away. A non-zero exit code of a
managed instance (e.g. a memory leak detected by a debug build) fails the
script.

Defining a socket with a name that is already in use shuts down the old one
first.

### Commands

A command sends `ACTION`, after variable expansion, to the rtpproxy behind
the named socket:

```
gena: Uc%%CODEC%% %%CALLID_A%% 127.0.0.1 %%TRASH_PORT%% %%FT%%
```

Here a "U" command is sent over the "gena" socket, with the codec, Call-ID,
port and from-tag taken from the CODEC, CALLID_A, TRASH_PORT and FT
variables. Several rtpproxy commands can be combined into one action with
`&&` in the usual way, the reply then contains the results separated by
`&&` as well.

Names starting with a dot (`.eval:`, `.exec:` and so on) are built-ins,
which are executed by the RPTL runner itself, see [Built-ins](#built-ins).

The socket name can also be given as a variable, e.g. `%%R%%: V`, which
allows the same included script to be run against several instances.

### Variables and Output

Variables are referenced as `%%NAME%%` anywhere in an action, a socket
address, socket parameters or a socket log file name, and are replaced with
their values when the statement is executed. Referencing an undefined
variable fails the script. Expansion is not recursive: a value containing
`%%` is inserted as is.

Variables are set with `.eval:`, from the command line (`-D NAME=VALUE`, see
[Running RPTL Scripts](#running-rptl-scripts)), or by capturing the result
of a command with `-> NAME`:

```
.eval: 38322 -> TRASH_PORT
gena: Lz60 %%CALLID_A%% 127.0.0.1 %%TRASH_PORT%% %%FT%% %%TT%% -> PORTA
```

Each socket also provides read-only attributes, referenced as
`%%SOCKET.ATTR%%`, both in expansions and as function arguments:

| Attribute | Description |
|-----------|-------------|
| `CTRL` | Control socket address, in the form accepted by the `socket` statement and other tools, e.g. `udp:127.0.0.1:41873` for a managed instance. |
| `CTRL_HOST`, `CTRL_PORT` | Address and port of the control socket of a managed instance using a network socket. |
| `PID` | Process ID of a managed instance. |

For example, to query a managed instance with an external tool:

```
socket r1: udp: -d dbug
.exec: echo V | python3 rtpp_query.py -s %%r1.CTRL%% -i - -> str_compare(PROTO_VER)
```

Referencing an attribute of a socket that does not exist, or has been
closed, fails the script.

A variable name to set, or to pass to a function, can itself contain
variable references, e.g. `-> PORT_%%K%%`, which allows keeping a set of
values indexed by a loop variable. Use `deref()` to read them back.

Instead of a variable name, the output can be passed to one of the
transformation functions below, which can check it and/or split it into
several variables.

### Transformation Functions

```
fwd: U %%CALLID_F%% 127.0.0.1 %%PORTA%% %%FT%% && M4:1 S -> str_split(&&, PORT1_IPv4, DTLS_PARAMS)
.eval: %%DTLS_PARAMS%% -> str_split( , DTLS_MODE, DTLS_DIGALG, DTLS_DIGSUM)
.eval: %%PORT1_IPv4%% -> validate_port(_)
```

| Function | Description |
|----------|-------------|
| `str_split(SEP, VAR1, VAR2, ...)` | Split the value at `SEP` and assign the pieces, with surrounding whitespace stripped, to `VAR1`, `VAR2`, ... in order. Fails if there are fewer pieces than variables; anything left after the last variable is dropped, so `str_split(\n, FIRST)` takes the first line. `SEP` is taken verbatim (`str_split( , ...)` splits at spaces), may not contain `,` or `)`, and can use backslash escapes such as `\n`. |
| `str_compare(VAR)` | Fail unless the value is exactly equal to the value of `VAR`. |
| `deref(VAR)` | Treat the value as a name of a variable and copy that variable into `VAR`, e.g. `.eval: PORT_%%K%% -> deref(PORT)`. |
| `validate_port(VAR)` | Fail unless the value is an integer in the 1-65535 range, then assign it to `VAR`. `_` is commonly used when the value is not needed. |

To compare a result against a constant, put the constant into a variable
first:

```
.eval: 0 -> RES_OK
alice: R call_ab_alice alice_to alice_from -> str_compare(RES_OK)
```

### Built-ins

| Built-in | Description |
|----------|-------------|
| `.eval: VALUE -> OUTPUT` | Assign `VALUE` to a variable or pass it to a function. |
| `.echo: TEXT` | Print `TEXT` to stderr. |
| `.sleep: SECONDS` | Pause the script; fractional values are allowed. |
| `.foreach: VAR in VALUE... do FILE` | Execute statements from `FILE` (resolved like with `.include:`) once for each `VALUE`, with `VAR` set to it. The values are split at whitespace after variable expansion, so a variable can provide the list. |
| `.include: FILE` | Execute statements from `FILE` at this point. A relative `FILE` is resolved against the directory of the script containing the `.include:`. The file is read when the statement is reached, so its name can contain variables; included statements share all variables and sockets with the rest of the script. |
| `.close: SOCKET` | Shut down `SOCKET`. For a `stdio:` socket this waits for the managed rtpproxy to exit and fails if its exit code is non-zero, which is useful to make it flush and close its recordings before they are examined. |
| `.exec:`, `.spawn:`, `.readline:`, `.wait:`, `.kill:` | Run external commands, see below. |

### External Commands

Scripts can run external programs, e.g. to generate traffic into the ports
allocated by rtpproxy, or to examine recordings it has produced. Command
lines are executed via `/bin/sh -c` after variable expansion, so shell
syntax (environment assignments, redirections, `$((...))`, etc.) is
available. Each process runs in its own process group with stdin connected
to `/dev/null` and stderr inherited from the RPTL runner.

| Built-in | Description |
|----------|-------------|
| `.exec: CMDLINE [-> OUTPUT]` | Run `CMDLINE` and wait for it to exit. A non-zero exit code fails the script. Its stdout, with leading and trailing whitespace stripped, is the result; without `-> OUTPUT` it is printed to stderr. |
| `.spawn: CMDLINE -> NAME` | Start `CMDLINE` in background under handle `NAME` and continue right away. The `NAME` variable is set to its PID. Like other output names, `NAME` can contain variable references, e.g. `-> CAP_%%K%%`, to keep several processes running at once. |
| `.readline: NAME [TIMEOUT] [-> OUTPUT]` | Wait for the next line printed by the spawned process `NAME`. Output is buffered from the moment the process is started, so no lines are lost. Fails if the process exits without printing another line, or on timeout. |
| `.wait: NAME [TIMEOUT] [-> OUTPUT]` | Wait for the spawned process `NAME` to exit and release its handle, so `NAME` can be reused. A non-zero exit code fails the script unless it is captured with `-> OUTPUT` (a negative value means it was killed by that signal). Fails on timeout. |
| `.kill: NAME [SIGNAL]` | Send `SIGNAL` (name such as `TERM`, `SIGUSR1`, or number; `TERM` by default) to the process group of `NAME`. Does nothing if it has already exited; use `.wait:` afterwards to collect it. |

`TIMEOUT` is in seconds; without it `.readline:` and `.wait:` wait forever.

Every spawned process must be collected with `.wait:`. Processes still
running when the script ends, or when it fails, are terminated, and if the
script has otherwise succeeded it fails.

The shell stays the parent of the command line unless told otherwise, so
for a process that is going to be signalled, start it with `exec` to make
sure that its own exit code is the one reported:

```
.spawn: exec python3 udp_sink.py 127.0.0.1 -> SINK
.readline: SINK 10 -> validate_port(SINK_PORT)
...
.kill: SINK
.wait: SINK 10
```

`.exec:` is also handy for simple calculations:

```
.exec: expr %%PORT_A%% + 1 -> PORT_A_RTCP
```

## Running RPTL Scripts

```
python3 rptl_run.py -s script.rptl [-D NAME=VALUE ...] [-S sippy_path]
```

| Option | Description |
|--------|-------------|
| `-s script.rptl` | Script to run. |
| `-D NAME=VALUE` | Define variable `NAME` before the script starts. Can be repeated. Useful to pass paths and other parameters from a wrapper shell script. |
| `-S sippy_path` | Directory to load the sippy library from instead of the default module search path. |

RPTL requires the `parsimonious` and `sippy` Python modules.

On success the runner prints all variables to stdout and exits with code 0.
On failure it prints the failed statement as written and as expanded to
stderr, followed by the error, and exits with a non-zero code.

## Example

Start an rtpproxy, create a session, replay a capture into the port it has
allocated and check the stats:

```
.eval: ../src/rtpproxy_debug -> RTPPROXY_BIN
.eval: rtpa_nsent=300 rtpa_nrcvd=300 -> STATS_EXP
socket rtpp: stdio: -d dbug -T2 -W2 -> rtpp.rout

rtpp: U call1 127.0.0.1 12345 from_tag_1 -> validate_port(PORT_A)
rtpp: L call1 127.0.0.1 54321 from_tag_1 to_tag_1 -> validate_port(PORT_O)

.exec: tcprewrite --dstipmap=0.0.0.0/0:127.0.0.1 --portmap=2280:%%PORT_O%% -i in.pcap -o out.pcap
.spawn: exec udpreplay out.pcap -> REPLAY
.wait: REPLAY 60
.sleep: 0.5

rtpp: Qv call1 to_tag_1 from_tag_1 rtpa_nsent rtpa_nrcvd -> str_compare(STATS_EXP)
.close: rtpp
```

## More Examples

- [tests/recording/basic](../../tests/recording/basic) runs a set of
  recording tests, one script per sub-test
  (`tests/recording/basic.*.rptl`), sharing common setup and replay steps
  via `.include:` and using `.exec:`/`.spawn:` to replay traffic, receive
  remote recordings and verify recorded files.
- [tests/recording/src_srs.rptl](../../tests/recording/src_srs.rptl) chains
  four managed rtpproxy instances together, with DTLS and recording.
- [examples/dtls.rptl](./examples/dtls.rptl) talks to externally started
  rtpproxy instances over Unix domain sockets to exercise forwarding and DTLS
  encryption, see its [README](./examples/README.md).
