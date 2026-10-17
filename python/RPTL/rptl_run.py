import sys, os, getopt, shlex, signal
from collections import deque
from threading import Thread
from socket import socketpair, AF_UNIX
from subprocess import Popen, TimeoutExpired, DEVNULL, PIPE

from parsimonious.grammar import Grammar
from parsimonious.nodes import Node, NodeVisitor
from sippy.Rtp_proxy.Client.stream import Rtp_proxy_client_stream
from sippy.Rtp_proxy.Client.Worker.internal import RTPPLWorker_internal

# Define the grammar for the DSL syntax
grammar = Grammar(
    r"""
    program = ws? stmt (ws stmt)* ws?
    stmt = comment / socket / command
    comment = ~r"#[^\r\n]*"
    socket = "socket" ws name ":" ws address (ws1 socket_params)? (ws1 arr ws logfile)?
    command = name ":" ws action (ws output_spec)?
    name = ~r"[.]?\w+"
    output_spec = arr ws (trans_spec / var_name)
    var_name = ~r"\w+"
    trans_spec = func_name obra func_arg (comm ws func_arg)* cbra
    func_arg = ~r"[^,)]+"
    func_name = ~r"\w+"
    socket_params = param (ws1 param)*
    param = ~r"(?!->)\S+"
    address = ~r"\S+"
    logfile = ~r"\S+"
    action = ~r"(.(?!->))*"
    ws = ~r"\s*"
    ws1 = ~r"[ \t]+"
    arr = "->"
    comm = ","
    obra = "("
    cbra = ")"
    """
)

class CommandRunner():
    rc = None
    name: str
    spath: str
    outfile: str
    proc = None

    def __init__(self, instance_name, socket_name, outfile, params, variables):
        from sippy.Rtp_proxy.client import Rtp_proxy_client
        self.name = instance_name
        if socket_name == 'stdio:':
            rtpproxy_bin = variables.get('RTPPROXY_BIN', 'rtpproxy')
            rtpproxy_stderr = variables.get('RTPPROXY_STDERR')
            self.rc = StdioRtpProxyClient(params, rtpproxy_bin = rtpproxy_bin,
              rtpproxy_stderr = rtpproxy_stderr, instance_name = self.name)
            self.proc = self.rc.proc
        else:
            self.rc = Rtp_proxy_client({'_sip_address': '127.0.0.1'}, spath = socket_name,
              nworkers = 4, no_version_check = True)
        self.spath = socket_name
        self.outfile = outfile
        if outfile:
            self._outfd = open(outfile, 'w')

    def log(self, response):
        if not self.outfile:
            return
        self._outfd.write(response + '\n')
        self._outfd.flush()

    def shutdown(self):
        if self.rc is None:
            return
        if hasattr(self.rc, 'shutdown'):
            self.rc.shutdown()
        self.rc = None

class StdioRtpProxyClient(Rtp_proxy_client_stream):
    def __init__(self, extra_args, nworkers = 1, rtpproxy_bin = None,
      rtpproxy_stderr = None, instance_name = None):
        if rtpproxy_bin is None:
            rtpproxy_bin = 'rtpproxy'
        self.instance_name = instance_name
        self.worker_class = RTPPLWorker_internal
        cmd = [rtpproxy_bin, '-f', '-s', 'stdio:'] + list(extra_args)
        parent_sock, child_sock = socketpair()
        self._stdio_sock = parent_sock
        self._stderr = None
        try:
            if rtpproxy_stderr is not None:
                self._stderr = open(rtpproxy_stderr, 'w')
            self.proc = Popen(cmd, stdin = child_sock, stdout = child_sock,
              stderr = self._stderr, close_fds = True)
            child_sock.close()
            super().__init__({'_sip_address': '127.0.0.1'}, address = parent_sock,
              bind_address = None, nworkers = nworkers, family = AF_UNIX)
        except Exception:
            parent_sock.close()
            child_sock.close()
            if hasattr(self, 'proc') and self.proc is not None and self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait()
            if self._stderr is not None:
                self._stderr.close()
                self._stderr = None
            raise

    def shutdown(self):
        proc_rc = None
        if self._stdio_sock is not None:
            self._stdio_sock.close()
            self._stdio_sock = None
        try:
            super().shutdown()
        finally:
            if self.proc is not None:
                try:
                    # EOF on the control socket makes rtpproxy exit by itself
                    proc_rc = self.proc.wait(timeout = 5.0)
                except TimeoutExpired:
                    self.proc.terminate()
                    try:
                        proc_rc = self.proc.wait(timeout = 2.0)
                    except TimeoutExpired:
                        self.proc.kill()
                        proc_rc = self.proc.wait()
                self.proc = None
            if self._stderr is not None:
                self._stderr.close()
                self._stderr = None
        if proc_rc is not None and proc_rc != 0:
            raise RuntimeError(
              F'managed rtpproxy instance "{self.instance_name}" exited with return code {proc_rc}')

class ManagedProcess():
    # External command run via "/bin/sh -c" in its own process group, its
    # stdout is collected line by line and delivered to the main thread
    name: str
    cmdline: str
    lines: deque
    rc = None
    on_update = None

    def __init__(self, name, cmdline):
        self.name = name
        self.cmdline = cmdline
        self.lines = deque()
        self.proc = Popen(['/bin/sh', '-c', cmdline], stdin = DEVNULL,
          stdout = PIPE, close_fds = True, start_new_session = True)
        self.pid = self.proc.pid
        self._reader = Thread(target = self._read_output, daemon = True)
        self._reader.start()

    def _read_output(self):
        from sippy.Core.EventDispatcher import ED2
        for line in self.proc.stdout:
            line = line.decode(errors = 'replace').rstrip('\r\n')
            ED2.callFromThread(self._got_line, line)
        self.proc.stdout.close()
        rc = self.proc.wait()
        ED2.callFromThread(self._got_exit, rc)

    def _got_line(self, line):
        self.lines.append(line)
        self._notify()

    def _got_exit(self, rc):
        self.rc = rc
        self._notify()

    def _notify(self):
        if self.on_update is not None:
            self.on_update()

    def signal(self, signum):
        if self.proc.returncode is not None:
            return
        try:
            os.killpg(self.pid, signum)
        except ProcessLookupError:
            pass

    def stop(self):
        self.signal(signal.SIGTERM)
        self._reader.join(2.0)
        if self._reader.is_alive():
            self.signal(signal.SIGKILL)
            self._reader.join()

class TransFunction():
    name: str
    args: tuple
    def __init__(self, name, args):
        handlers = {
          'str_split':self.str_split,
          'validate_port':self.validate_port,
          'str_compare':self.str_compare,
        }
        self.name = name
        self.args = tuple(args)
        self.handler = handlers[name]

    def str_split(self, srun, res):
        spat, *evars = self.args
        if '\\' in spat:
            spat = spat.encode().decode('unicode_escape')
        res = res.split(spat, len(evars))
        for i, var in enumerate(evars):
            srun.variables[var] = res[i].strip()

    def str_compare(self, srun, res):
        assert(len(self.args) == 1)
        if res != srun.variables[self.args[0]]:
            raise AssertionError(F'"{res}" != "{srun.variables[self.args[0]]}"')

    def validate_port(self, srun, res):
        ires = int(res)
        assert(ires > 0 and ires <= 65535)
        assert(len(self.args) == 1)
        srun.variables[self.args[0]] = res

class ExceptionInfo():
    exception: Exception
    cmd: CommandRunner
    command: str

class ScriptRunner():
    i_command = 0
    sockets: dict
    procs: dict
    commands: list
    variables: dict
    internal_ops: dict
    ex_info: ExceptionInfo = None
    cur_cmd = None
    cur_command = None

    def __init__(self, commands, variables = None):
        from sippy.Time.Timeout import Timeout
        self.sockets = {}
        self.procs = {}
        self.commands = commands
        self.variables = dict(variables) if variables is not None else {}
        self.internal_ops = {
          '.eval':self.handle_eval,
          '.sleep':self.handle_sleep,
          '.echo':self.handle_echo,
          '.include':self.handle_include,
          '.exec':self.handle_exec,
          '.spawn':self.handle_spawn,
          '.readline':self.handle_readline,
          '.wait':self.handle_wait,
          '.kill':self.handle_kill,
          '.close':self.handle_close,
        }
        # Start once the event loop is running, so that breakLoop() works
        Timeout(self.issue_next_cmd, 0.0)

    def fail(self, ex):
        from sippy.Core.EventDispatcher import ED2
        if self.ex_info is not None:
            return
        ei = ExceptionInfo()
        ei.exception = ex
        ei.cmd = self.cur_cmd
        ei.command = self.cur_command
        self.ex_info = ei
        ED2.breakLoop()

    def guarded(self, func, *args):
        if self.ex_info is not None:
            return
        try:
            func(*args)
        except Exception as ex:
            self.fail(ex)

    def issue_next_cmd(self):
        self.guarded(self._issue_next_cmd)

    def _issue_next_cmd(self):
        from sippy.Core.EventDispatcher import ED2
        while True:
            if self.i_command == len(self.commands):
                ED2.breakLoop()
                return
            cmd = self.commands[self.i_command]
            self.i_command += 1
            self.cur_cmd = cmd
            self.cur_command = None
            if isinstance(cmd, SocketSpec):
                address = self.expand_vars(cmd.address)
                params = []
                for raw_param in cmd.params:
                    params.extend(shlex.split(self.expand_vars(raw_param)))
                outfile = self.expand_vars(cmd.outfile) if cmd.outfile else None
                if cmd.name in self.sockets:
                    self.sockets[cmd.name].shutdown()
                self.sockets[cmd.name] = CommandRunner(cmd.name, address, outfile,
                  params, self.variables)
                continue
            break
        command = self.expand_vars(cmd.action)
        self.cur_command = command
        if cmd.socket_name.startswith('.'):
            if cmd.socket_name not in self.internal_ops:
                raise Exception(F'{cmd.socket_name}: unknown built-in')
            self.internal_ops[cmd.socket_name](cmd, command)
            return
        socket = self.sockets[cmd.socket_name]
        socket.rc.send_command(command, self.got_result, cmd, command, socket)

    def got_result(self, result, cmd, command, socket, ex=None):
        if result is None or ex is not None:
            if ex is None:
                ex = Exception(F'None returned by the proxy "{cmd.socket_name}@{socket.spath}" when executing "{cmd.action}"')
            self.fail(ex)
            return
        self.guarded(self._got_result, result, cmd, socket)

    def _got_result(self, result, cmd, socket):
        socket.log(result)
        if cmd.output_var != None:
            self.setvar(cmd.output_var, result)
        self.issue_next_cmd()

    def expand_vars(self, command):
        orig_command = command
        rval = ''
        while command:
            spos = command.find('%%')
            if spos == -1:
                rval += command
                break
            rval += command[:spos]
            command = command[spos + 2:]
            epos = command.find('%%')
            if epos == -1:
                raise Exception(F'{orig_command}:unbalanced "%%"')
            varname = command[:epos]
            rval += self.variables[varname]
            command = command[epos + 2:]
        return rval

    def handle_eval(self, cmd, command):
        self.setvar(cmd.output_var, command)
        self.issue_next_cmd()

    def handle_sleep(self, cmd, command):
        from sippy.Time.Timeout import Timeout
        Timeout(self.issue_next_cmd, float(command))

    def handle_include(self, cmd, command):
        # Paths are relative to the directory of the including script
        spath = os.path.join(cmd.srcdir, command.strip())
        self.commands[self.i_command:self.i_command] = load_script(spath)
        self.issue_next_cmd()

    def _wait_proc(self, mp, check, timeout, what):
        # Call check() each time the process produces a line or exits, until
        # it returns True; fail if timeout expires first. Note that check()
        # proceeds to the next command, which may start waiting on the same
        # process again, so the handler is re-armed only if check() says so.
        from sippy.Time.Timeout import Timeout
        if check():
            return
        tmo = None
        def on_update():
            mp.on_update = None
            done = True
            try:
                done = check()
            finally:
                if not done:
                    mp.on_update = updater
                elif tmo is not None:
                    tmo.cancel()
        def on_timeout():
            mp.on_update = None
            self.fail(TimeoutError(F'timeout waiting for {what} of "{mp.cmdline}"'))
        updater = lambda: self.guarded(on_update)
        mp.on_update = updater
        if timeout is not None:
            tmo = Timeout(on_timeout, timeout)

    def _getproc(self, name):
        if name not in self.procs:
            raise Exception(F'{name}: no such spawned process')
        return self.procs[name]

    def _parse_proc_args(self, command):
        args = command.split()
        if len(args) not in (1, 2):
            raise Exception(F'"{command}": NAME [TIMEOUT] expected')
        timeout = float(args[1]) if len(args) == 2 else None
        return (self._getproc(args[0]), timeout)

    def handle_exec(self, cmd, command):
        mp = ManagedProcess(None, command)
        def check():
            if mp.rc is None:
                return False
            if mp.rc != 0:
                for line in mp.lines:
                    sys.stderr.write(line + '\n')
                raise Exception(F'"{command}" exited with return code {mp.rc}')
            output = '\n'.join(mp.lines).strip()
            if cmd.output_var is None:
                if output:
                    sys.stderr.write(output + '\n')
                    sys.stderr.flush()
            else:
                self.setvar(cmd.output_var, output)
            self.issue_next_cmd()
            return True
        self._wait_proc(mp, check, None, 'completion')

    def handle_spawn(self, cmd, command):
        name = cmd.output_var
        if not isinstance(name, str):
            raise Exception('.spawn requires "-> NAME" to be specified')
        if name in self.procs:
            raise Exception(F'{name}: process has been spawned already')
        mp = ManagedProcess(name, command)
        self.procs[name] = mp
        self.variables[name] = str(mp.pid)
        self.issue_next_cmd()

    def handle_readline(self, cmd, command):
        mp, timeout = self._parse_proc_args(command)
        def check():
            if len(mp.lines) == 0:
                if mp.rc is not None:
                    raise Exception(F'{mp.name}: exited with return code {mp.rc} before printing a line')
                return False
            line = mp.lines.popleft()
            if cmd.output_var is not None:
                self.setvar(cmd.output_var, line)
            self.issue_next_cmd()
            return True
        self._wait_proc(mp, check, timeout, 'output')

    def handle_wait(self, cmd, command):
        mp, timeout = self._parse_proc_args(command)
        def check():
            if mp.rc is None:
                return False
            del self.procs[mp.name]
            if cmd.output_var is not None:
                self.setvar(cmd.output_var, str(mp.rc))
            elif mp.rc != 0:
                raise Exception(F'{mp.name}: "{mp.cmdline}" exited with return code {mp.rc}')
            self.issue_next_cmd()
            return True
        self._wait_proc(mp, check, timeout, 'exit')

    def handle_kill(self, cmd, command):
        args = command.split()
        if len(args) not in (1, 2):
            raise Exception(F'"{command}": NAME [SIGNAL] expected')
        mp = self._getproc(args[0])
        signum = signal.SIGTERM
        if len(args) == 2:
            sname = args[1].upper()
            if sname.isdigit():
                signum = int(sname)
            else:
                signum = signal.Signals[sname if sname.startswith('SIG') else 'SIG' + sname]
        mp.signal(signum)
        self.issue_next_cmd()

    def handle_close(self, cmd, command):
        name = command.strip()
        if name not in self.sockets:
            raise Exception(F'{name}: no such socket')
        self.sockets.pop(name).shutdown()
        self.issue_next_cmd()

    def stop_procs(self):
        leftover = sorted(self.procs.keys())
        for mp in self.procs.values():
            mp.stop()
        self.procs = {}
        return leftover

    def setvar(self, output_var, value):
        if not isinstance(output_var, TransFunction):
            self.variables[output_var] = value
        else:
            try:
                output_var.handler(self, value)
            except Exception as ex:
                raise Exception(F'"{value}" -> {output_var.name}{output_var.args}: failed') from ex

    def handle_echo(self, cmd, command):
        sys.stderr.write(command + '\n')
        sys.stderr.flush()
        self.issue_next_cmd()

class Command():
    socket_name: str
    action: str
    output_var: str = None
    srcdir: str = '.'

    def __str__(self):
        return F'{self.socket_name}: {self.action}'

class SocketSpec():
    name: str
    address: str
    params: list
    outfile: str

    def __init__(self, name, address, params, outfile):
        self.name = name
        self.address = address
        self.params = params
        self.outfile = outfile

    def __str__(self):
        return F'socket {self.name}: {self.address}'

# Define a class to visit the nodes in the parse tree
class DSLVisitor(NodeVisitor):
    def __init__(self, srcdir = '.'):
        self.rules = []
        self.srcdir = srcdir

    def visit_socket(self, node, children):
        _, _, name, _, _, address, params_group, log_group = children
        params = []
        if not isinstance(params_group, Node) and len(params_group) > 0:
            params = self._find_params(params_group) or []
        outfile = None
        if not isinstance(log_group, Node) and len(log_group) > 0:
            outfile = self._find_logfile(log_group)
        self.rules.append(SocketSpec(name.text, address.text, params, outfile))

    def visit_socket_params(self, node, children):
        return node.text.split()

    def _find_params(self, obj):
        if isinstance(obj, list):
            if obj and all(isinstance(x, str) for x in obj):
                return obj
            for item in obj:
                found = self._find_params(item)
                if found is not None:
                    return found
        return None

    def _find_logfile(self, obj):
        if isinstance(obj, Node) and obj.expr_name == 'logfile':
            return obj.text
        if isinstance(obj, list):
            for item in obj:
                found = self._find_logfile(item)
                if found is not None:
                    return found
        return None

    def visit_command(self, node, children):
        cmd = Command()
        socket_name, _, _, action, rest = children
        cmd.socket_name = socket_name.text
        cmd.action = action.text
        cmd.srcdir = self.srcdir
        #print('visit_command', type(rest))
        #print(f"rest: {rest}")

        if not isinstance(rest, Node): # and len(rest) > 0:
            output_spec = rest[0][1]

            var_spec = output_spec[2][0]

            if isinstance(var_spec, TransFunction):
                cmd.output_var = var_spec
            else:
                assert(var_spec.expr_name == 'var_name')
                cmd.output_var = var_spec.text

        self.rules.append(cmd)

    def visit_trans_spec(self, node, children):
        func_name, _, func_arg, *rest = children
        func_args = [func_arg.text]
        if rest:
            for arg_group in rest[0]:
                func_args.append(arg_group[-1].text)
        #print(F'TransFunction({func_name.text}, {func_args})')
        return TransFunction(func_name.text, func_args)

    def generic_visit(self, node, children):
        return children or node

# Define a function to parse the DSL code and return the parse tree
def parse_dsl(dsl_code):
    return grammar.parse(dsl_code)

# Define a function to visit the nodes in the parse tree and execute the DSL commands
def execute_dsl(parse_tree, srcdir = '.'):
    visitor = DSLVisitor(srcdir)
    visitor.visit(parse_tree)
    return visitor.rules

def load_script(spath):
    with open(spath) as f:
        dsl_text = f.read()
    return execute_dsl(parse_dsl(dsl_text), os.path.dirname(spath))

test_dsl = """socket ALICE: /tmp/abc.sock
socket BOB: udp:192.168.221.1:38282
socket CHARLIE: tcp:127.0.0.1:32323 -> CHARLIE.rout
.eval: --CALLID-- -> CALLID
.eval: 0.01 -> ICD
ALICE: U %%CALLID%% 127.0.0.1 12345 from_tag_1 -> PORT
ALICE: U %%CALLID%% 127.0.0.1 12345 from_tag_1 -> str_split(aa, PORT, FOO)
.sleep: %%ICD%%
BOB: U %%CALLID%% 127.0.0.1 54321 from_tag_1 -> PORT_A
.sleep: %%ICD%%
BOB: P[...] %%PORT%% [...]
.sleep: %%ICD%%
BOB: R[...]
.sleep: %%ICD%%
ALICE: L[...] %%PORT_A%% [...] -> PORT
.sleep: %%ICD%%
CHARLIE: U[...] -> PORT_O"""

#ALICE: U %%CALLID%% 127.0.0.1 12345 from_tag_1 -| str_split(aa, PORT, FOO)

def usage(rc = 0):
    sys.stderr.write('usage: rptl_run.py [-s script.rptl] [-S sippy_path] [-D NAME=VALUE ...]\n')
    sys.stderr.flush()
    sys.exit(rc)

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:S:D:h')
    except getopt.GetoptError:
        usage(2)

    spath = None
    sippy_path = None
    variables = {}
    for o, a in opts:
        if o == '-s':
            spath = a.strip()
            continue
        if o == '-S':
            sippy_path = a.strip()
            continue
        if o == '-D':
            name, sep, value = a.partition('=')
            if not sep or not name:
                usage(2)
            variables[name] = value
            continue
        if o == '-h':
            usage(0)

    if sippy_path != None:
        sys.path.insert(0, sippy_path)

    if spath is not None:
        rs = load_script(spath)
    else:
        rs = execute_dsl(parse_dsl(test_dsl))

    from sippy.Core.EventDispatcher import ED2

    srun = ScriptRunner(rs, variables)
    try:
        ED2.loop()
    finally:
        leftover = srun.stop_procs()
        for socket in srun.sockets.values():
            socket.shutdown()
    if srun.ex_info:
        m = F'Failed action: "{srun.ex_info.cmd}"\n\texpanded: "{srun.ex_info.command}"\n'
        sys.stderr.write(m)
        sys.stderr.flush()
        raise srun.ex_info.exception
    if leftover:
        raise Exception(F'spawned process(es) {", ".join(leftover)} not waited for')
    print(srun.variables)
