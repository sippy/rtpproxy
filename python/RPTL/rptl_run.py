import sys, getopt
from time import sleep

from parsimonious.grammar import Grammar
from parsimonious.nodes import Node, NodeVisitor

# Define the grammar for the DSL syntax
grammar = Grammar(
    r"""
    program = (socket ws)+ (command ws?)+
    socket = "socket" ws name ":" ws address (ws arr ws logfile)?
    command = name ":" ws action (ws output_spec)?
    name = ~r"[.]?\w+"
    output_spec = arr ws (trans_spec / var_name)
    var_name = ~r"\w+"
    trans_spec = func_name obra func_arg (comm ws func_arg)* cbra
    func_arg = ~"[^,)]+"
    func_name = ~"\w+"
    address = ~r"\S+"
    logfile = ~r"\S+"
    action = ~r"(.(?!->))*"
    ws = ~r"\s*"
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

    def __init__(self, socket_name, outfile):
        from sippy.Rtp_proxy.client import Rtp_proxy_client
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

    def __init__(self, sockets, commands):
        self.sockets = sockets
        self.commands = commands
        self.variables = {}
        self.internal_ops = {
          '.eval':self.handle_eval,
          '.sleep':self.handle_sleep,
          '.echo':self.handle_echo,
        }
        self.issue_next_cmd()

    def issue_next_cmd(self):
        if self.i_command == len(self.commands):
            from sippy.Core.EventDispatcher import ED2
            ED2.breakLoop()
            return
        cmd = self.commands[self.i_command]
        self.i_command += 1
        command = self.expand_vars(cmd.action)
        if cmd.socket_name.startswith('.'):
            self.internal_ops[cmd.socket_name](cmd, command)
            return
        socket = self.sockets[cmd.socket_name]
        socket.rc.send_command(command, self.got_result, cmd, command, socket)

    def got_result(self, result, cmd, command, socket):
        if result == None:
            from sippy.Core.EventDispatcher import ED2
            ei = ExceptionInfo()
            ei.exception = Exception(F'None returned by the proxy "{cmd.socket_name}@{socket.spath}" when executing "{cmd.action}"')
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

# Define a class to visit the nodes in the parse tree
class DSLVisitor(NodeVisitor):
    def __init__(self):
        self.sockets = {}
        self.rules = []

    def visit_socket(self, node, children):
        _, _, name, _, _, address, rest = children
        outfile = None
        if not isinstance(rest, Node) and len(rest) > 0:
            assert(len(rest) == 1)
            _, _, _, _outfile = rest[0]
            outfile = _outfile.text
        self.sockets[name.text] = CommandRunner(address.text, outfile)

    def visit_command_old(self, node, children):
        cmd = Command()
        socket_name, _, _, action, rest = children
        cmd.socket_name = socket_name.text
        cmd.action = action.text
        if not isinstance(rest, Node) and len(rest) > 0:
            assert(len(rest) == 1)
            _, _, _, var_name = rest[0]
            cmd.output_var = var_name.text
        self.rules.append(cmd)

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
    return visitor.sockets, visitor.rules

test_dsl = """socket ALICE: /tmp/abc.sock
socket BOB: udp:192.168.221.1:38282
socket CHARLIE: tcp:127.0.0.1:32323 -> CHARLIE.rout
.set: --CALLID-- -> CALLID
.set: 0.01 -> ICD
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

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], 's:S:')
    except getopt.GetoptError:
        usage()

    dsl_text = test_dsl
    sippy_path = None
    for o, a in opts:
        if o == '-s':
            spath = a.strip()
            dsl_text = open(spath).read()
        if o == '-S':
            sippy_path = a.strip()
            continue

    if sippy_path != None:
        sys.path.insert(0, sippy_path)

    tree = parse_dsl(dsl_text)
    #print(tree)
    ss, rs = execute_dsl(tree)
    #for r in rs:
    #    print(F'socket = "socket = {ss[r.socket_name]}", action = "{r.action}", output_var = "{r.output_var}"')

    from sippy.Core.EventDispatcher import ED2

    srun = ScriptRunner(ss, rs)
    ED2.loop()
    if srun.ex_info:
        m = F'Failed action: "{srun.ex_info.cmd.action}"\n\texpanded: "{srun.ex_info.command}"\n'
        sys.stderr.write(m)
        sys.stderr.flush()
        raise srun.ex_info.exception
    print(srun.variables)
