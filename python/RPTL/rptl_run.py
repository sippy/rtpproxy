import sys, getopt
from time import sleep

from parsimonious.grammar import Grammar
from parsimonious.nodes import Node, NodeVisitor
from sippy.Rtp_proxy.Client.stream import Rtp_proxy_client_stream
from sippy.Rtp_proxy.Client.Worker.internal import RTPPLWorker_internal

# Define the grammar for the DSL syntax
grammar = Grammar(
    r"""
    program = ws? stmt (ws stmt)* ws?
    stmt = socket / command
    socket = "socket" ws name ":" ws address (ws1 socket_params)? (ws1 arr ws logfile)?
    command = name ":" ws action (ws output_spec)?
    name = ~r"[.]?\w+"
    output_spec = arr ws (trans_spec / var_name)
    var_name = ~r"\w+"
    trans_spec = func_name obra func_arg (comm ws func_arg)* cbra
    func_arg = ~"[^,)]+"
    func_name = ~"\w+"
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
    spath: str
    outfile: str
    proc = None

    def __init__(self, socket_name, outfile, params, variables):
        from sippy.Rtp_proxy.client import Rtp_proxy_client
        if socket_name == 'stdio:':
            rtpproxy_bin = variables.get('RTPPROXY_BIN', 'rtpproxy')
            self.rc = StdioRtpProxyClient(params, rtpproxy_bin = rtpproxy_bin)
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
    def __init__(self, extra_args, nworkers = 1, rtpproxy_bin = None):
        import socket
        import subprocess
        if rtpproxy_bin is None:
            rtpproxy_bin = 'rtpproxy'
        self.worker_class = RTPPLWorker_internal
        cmd = [rtpproxy_bin, '-f', '-s', 'stdio:'] + list(extra_args)
        parent_sock, child_sock = socket.socketpair()
        self._stdio_sock = parent_sock
        self.proc = subprocess.Popen(cmd, stdin = child_sock, stdout = child_sock,
          stderr = None, close_fds = True)
        child_sock.close()
        super().__init__({'_sip_address': '127.0.0.1'}, address = parent_sock,
          bind_address = None, nworkers = nworkers, family = socket.AF_UNIX)

    def shutdown(self):
        super().shutdown()
        if self._stdio_sock is not None:
            self._stdio_sock.close()
            self._stdio_sock = None
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout = 2.0)
            except Exception:
                self.proc.kill()
        self.proc = None

class TransFunction():
    name: str
    args: list
    def __init__(self, name, args):
        handlers = {
          'str_split':self.str_split,
          'validate_port':self.validate_port,
          'str_compare':self.str_compare,
        }
        self.name = name
        self.args = args
        self.handler = handlers[name]

    def str_split(self, srun, res):
        spat, *evars = self.args
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
    commands: list
    variables: dict
    internal_ops: dict
    ex_info: ExceptionInfo = None

    def __init__(self, commands):
        self.sockets = {}
        self.commands = commands
        self.variables = {}
        self.internal_ops = {
          '.eval':self.handle_eval,
          '.sleep':self.handle_sleep,
          '.echo':self.handle_echo,
        }
        self.issue_next_cmd()

    def issue_next_cmd(self):
        from sippy.Core.EventDispatcher import ED2
        while True:
            if self.i_command == len(self.commands):
                ED2.breakLoop()
                return
            cmd = self.commands[self.i_command]
            self.i_command += 1
            if isinstance(cmd, SocketSpec):
                self.sockets[cmd.name] = CommandRunner(cmd.address, cmd.outfile,
                  cmd.params, self.variables)
                continue
            break
        command = self.expand_vars(cmd.action)
        if cmd.socket_name.startswith('.'):
            self.internal_ops[cmd.socket_name](cmd, command)
            return
        socket = self.sockets[cmd.socket_name]
        socket.rc.send_command(command, self.got_result, cmd, command, socket)

    def got_result(self, result, cmd, command, socket, ex=None):
        if result is None or ex is not None:
            from sippy.Core.EventDispatcher import ED2
            ei = ExceptionInfo()
            if ex is None:
                ei.exception = Exception(F'None returned by the proxy "{cmd.socket_name}@{socket.spath}" when executing "{cmd.action}"')
            else:
                ei.exception = ex
            ei.cmd = cmd
            ei.command = command
            self.ex_info = ei
            ED2.breakLoop()
            return
        try:
            socket.log(result)
            if cmd.output_var != None:
                self.setvar(cmd.output_var, result)
            self.issue_next_cmd()
        except Exception as ex:
            from sippy.Core.EventDispatcher import ED2
            ei = ExceptionInfo()
            ei.exception = ex
            ei.cmd = cmd
            ei.command = command
            self.ex_info = ei
            ED2.breakLoop()
            return

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

    def setvar(self, output_var, value):
        if not isinstance(output_var, TransFunction):
            self.variables[output_var] = value
        else:
            output_var.handler(self, value)

    def handle_echo(self, cmd, command):
        sys.stderr.write(command + '\n')
        sys.stderr.flush()
        self.issue_next_cmd()

class Command():
    socket_name: str
    action: str
    output_var: str = None

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

# Define a class to visit the nodes in the parse tree
class DSLVisitor(NodeVisitor):
    def __init__(self):
        self.rules = []

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
def execute_dsl(parse_tree):
    visitor = DSLVisitor()
    visitor.visit(parse_tree)
    return visitor.rules

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
    sys.stderr.write('usage: rptl_run.py [-s script.rptl] [-S sippy_path]\n')
    sys.stderr.flush()
    sys.exit(rc)

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:S:h')
    except getopt.GetoptError:
        usage(2)

    dsl_text = test_dsl
    sippy_path = None
    for o, a in opts:
        if o == '-s':
            spath = a.strip()
            dsl_text = open(spath).read()
        if o == '-S':
            sippy_path = a.strip()
            continue
        if o == '-h':
            usage(0)

    if sippy_path != None:
        sys.path.insert(0, sippy_path)

    tree = parse_dsl(dsl_text)
    #print(tree)
    rs = execute_dsl(tree)
    #for r in rs:
    #    print(F'socket = "socket = {ss[r.socket_name]}", action = "{r.action}", output_var = "{r.output_var}"')

    from sippy.Core.EventDispatcher import ED2

    srun = ScriptRunner(rs)
    try:
        ED2.loop()
    finally:
        for socket in srun.sockets.values():
            socket.shutdown()
    if srun.ex_info:
        m = F'Failed action: "{srun.ex_info.cmd.action}"\n\texpanded: "{srun.ex_info.command}"\n'
        sys.stderr.write(m)
        sys.stderr.flush()
        raise srun.ex_info.exception
    print(srun.variables)
