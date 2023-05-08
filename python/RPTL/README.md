# RTPProxy Testing Language (RPTL)

## Table of Contents

1. [Introduction](#introduction)
2. [Purpose](#purpose)
3. [Language Description](#language-description)
   - [Sockets](#sockets)
   - [Commands](#commands)
   - [Variables and Output](#variables-and-output)
   - [Functions and Transformations](#functions-and-transformations)
   - [Built-in Functions](#built-in-functions)
4. [RPTL Implementation](#rptl-implementation)
5. [Example](#example)
6. [More Examples](#examples)

## Introduction

RTPProxy Testing Language (RPTL) is a domain-specific language designed to
facilitate the testing and evaluation of RTP packet forwarding and processing
services such as RTPProxy. RPTL provides a concise and readable syntax for
defining communication sockets, executing commands, and analyzing the output.
By using RPTL, developers can quickly create and execute test scripts to ensure
the performance, reliability, and functionality of their RTP packet forwarding
and processing services.

## Purpose

The main purpose of RPTL is to streamline the testing process of RTP packet
forwarding and processing services. It allows developers to easily create and
modify test scripts without having to deal with the complexities of low-level
programming languages. This language is tailored specifically for testing
scenarios, focusing on aspects crucial for RTP packet forwarding and processing
services, such as IPv4 and IPv6 support, handling codecs, testing encryption,
recording, stream forking, and monitoring statistics.

## Language Description

RPTL is designed with simplicity and readability in mind, making it easy to
understand and write test scripts. The language is composed of two main parts:
socket definitions and command execution.

### Sockets

Sockets in RPTL represent named communication endpoints used to connect to the
RTP packet forwarding and processing services being tested. Each socket
definition consists of a name (e.g., "gena"), a communication socket
(e.g., "cunix:/tmp/forwarding3.sock") to connect to the RTPProxy instance, and
an optional log file (e.g., "gena.rout") for recording activity.

Example:

```
socket gena: cunix:/tmp/forwarding3.sock -> gena.rout
```

In this example, a socket named "gena" is defined to connect to the RTPProxy
instance using the communication socket "cunix:/tmp/forwarding3.sock", and the
activity is logged to the file "gena.rout".

### Commands

Commands in RPTL define a sequence of raw RTPProxy commands to be sent to the
associated RTPProxy instance or executed locally. These commands can include
creating or destroying sessions, starting or stopping the streaming of RTP
packets, setting up encryption and decryption of streams, and recording or
forking streams. Commands are associated with a specific socket and may include
output specifications for processing results.

Example:

```
gena: Uc%%CODEC%% %%CALLID_A%% 127.0.0.1 %%TRASH_PORT%% %%FT%%
```

In this example, a command "U" is sent to the RTPProxy using the "gena" socket,
creating a session on 127.0.0.1 with codecs defined by the CODEC environment
variable, Call-ID by CALLID_A, port number by TRASH_PORT, and from-tag by FT.

### Variables and Output

RPTL allows the use of variables to store and reuse information throughout the
script. Variables can be set explicitly using the `.eval:` directive or by
capturing the output of a command. To use the value of a variable in a command,
enclose the variable name with double percentage signs (%%). The variable will
be replaced with its value when the command is executed.

Example:

```
.eval: 38322 -> TRASH_PORT
gena: Uc%%CODEC%% %%CALLID_A%% 127.0.0.1 %%TRASH_PORT%% %%FT%%
```

In this example, the variable TRASH_PORT is set to the value 38322. When the
"gena" command is executed, the %%TRASH_PORT%% placeholder is replaced with the
value of the TRASH_PORT variable (38322).

Output specifications can be added to commands to capture the result of a
command into a variable for later use or inspection. To do this, add `->` and
the variable name after the command.

Example:

```
gena: Lz60 %%CALLID_A%% 127.0.0.1 %%TRASH_PORT%% %%FT%% %%TT%% -> PORTA
```

In this example, the "L" command is executed, and the resulting output is
captured into the PORTA variable.

Variables can be helpful for dynamically building commands based on previous
results or for storing intermediate values for later inspection upon script
completion.

### Functions and Transformations

RPTL allows the use of functions to transform and manipulate variables and
command outputs. Functions are applied to variables or command outputs by
appending the function name and its arguments within parentheses.

Example:

```
fwd: U %%CALLID_F%% 127.0.0.1 %%PORTA%% %%FT%% && M4:1 S -> str_split(&&, PORT1_IPv4, DTLS_PARAMS)
.eval: %%DTLS_PARAMS%% -> str_split( , DTLS_MODE, DTLS_DIGALG, DTLS_DIGSUM)
```

In this example, the `str_split` function is used to split the output of the
"fwd" command at each occurrence of the specified delimiter `&&`. The resulting
values are assigned to the PORT1_IPv4 and DTLS_PARAMS variables. The
`str_split` function is then used again to split the DTLS_PARAMS variable at
each space, assigning the resulting values to the DTLS_MODE, DTLS_DIGALG, and
DTLS_DIGSUM variables.

Functions can be helpful for processing and manipulating command outputs or
variables for use in subsequent commands or for inspecting results upon script
completion.

Remember to consider the specific syntax of the function when using it, as the
format may vary between functions.

### Built-in Functions

RPTL includes some built-in functions that can be executed locally, allowing
the test script to interact with the system or perform additional processing.

Example:

```
.sleep: 1
```

In this example, the `.sleep:` built-in function causes the script to pause
execution for 1 second before continuing. This can be useful for simulating
various network conditions or for allowing time for RTP streams to be
established, modified, or terminated.

Built-in functions provide a way to incorporate simple interactions and
processing tasks within the RPTL script, without the need for external tools or
scripts.

## Running RPTL Scripts

The RPTL implementation includes a Python script named `rptl_run.py` that allows
you to execute RPTL test scripts. The script takes a single command-line
parameter `-s` to specify the path to the RPTL script file that you want to run.
Upon completion, the script displays the set of internal variables used during
the test.

### Usage

To run an RPTL script, execute the `rptl_run.py` script with the `-s` parameter
followed by the path to the script file:

```bash
python rptl_run.py -s /path/to/your/script.rptl
```

Upon completion, the script will output the internal variables used during the
test. This output can help you verify the correctness of the test script and
analyze the results.

## Example

Here's an example of a complete RPTL script that demonstrates defining sockets,
executing commands, and working with variables and output:

```
socket gena: cunix:/tmp/forwarding3.sock -> gena.rout

gena: Uc%%CODEC%% %%CALLID_A%% 127.0.0.1 %%TRASH_PORT%% %%FT%%
gena: Lz60 %%CALLID_A%% 127.0.0.1 %%TRASH_PORT%% %%FT%% %%TT%% -> PORTA

.sleep: 1

gena: P%%NTIMES%% %%CALLID_A%% forwarding1 session %%FT%% %%TT%%

.sleep: 25

gena: Qv %%CALLID_F%% %%FT%% %%TT%% %%G_STATS%% -> G_STATS
```

In this script, a socket is defined, several commands are executed, and the
are captured in variables for further use or inspection.

## More Examples

For more practical insight into using RPTL, refer to the
[examples](./examples) directory in the  repository. Here, you will find a set
of scripts demonstrating the capabilities  and use-cases of RPTL.

One particular example is the [dtls.rptl](./examples/dtls.rptl) script, which
simulates various RTP generation, forwarding, and encryption scenarios using
RTPProxy's command-line interface.

The script demonstrates the dynamic modification of session parameters, the
collection of transmission statistics, and the setting of secure and non-secure
sessions. For a detailed understanding of the script, visit the
[README](./examples/README.md) in the examples directory.
