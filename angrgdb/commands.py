import gdb

'''try:
    import IPython
    has_shell = True
except:
    has_shell = False'''

from angrgdb import *

import sys
if sys.version_info >= (3, 0):
    long = int
    raw_input = input
else:
    long
    bytes = str


BANNER = " >>"

class AngrGDBError(RuntimeError):
    pass


def _to_int(x):
    try:
        return int(gdb.parse_and_eval(x).cast(gdb.lookup_type("long")))
    except BaseException as e:
        print (e)
        return None

def _prepare_args(args):
    return args.replace("\\", "\\\\").replace("\"", "\\\"")

def _prepare_shell(loc):
    sm = StateManager(StateShot(sync_brk=False))
    for k in _ctx.symbolics:
        if _ctx.symbolics[k] is None:
            sm.sim(k)
        else:
            sm.sim(k, _ctx.symbolics[k])
    loc["sm"] = sm
    loc["m"] = sm.simulation_manager()
    
    loc["find"] = _ctx.find
    loc["avoid"] = _ctx.avoid


class CommandsContext(object):
    def __init__(self):
        self.symbolics = {}
        self.find = []
        self.avoid = []


_ctx = CommandsContext()


class AngrGDBCommand(gdb.Command):
    '''
    Symbolic execution in GDB with angrdbg
    '''

    def __init__(self):
        super(AngrGDBCommand, self).__init__("angrgdb", gdb.COMMAND_USER, gdb.COMPLETE_NONE, True)


class AngrGDBShellCommand(gdb.Command):
    '''
    Open a python shell with a StateManager instance
    '''

    def __init__(self):
        super(AngrGDBShellCommand, self).__init__("angrgdb shell", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global _ctx
        self.dont_repeat()
        
        if not from_tty:
            raise AngrGDBError("The angrgdb shell can be launched only from the tty")
                
        print (BANNER + " sm is a StateManager instance created from the current GDB state")
        print (BANNER + " m is a SimulationManager based on the sm state")
        print (BANNER + " find and avoid are the list of addresses")
        print (BANNER + " to find:", ", ".join(map(lambda x: "0x%x" % x, _ctx.find)))
        print (BANNER + " to avoid:", ", ".join(map(lambda x: "0x%x" % x, _ctx.avoid)))
                
        gdb.execute("py from angrgdb.commands import _prepare_shell; _prepare_shell(locals()); gdb.execute('pi')")


class AngrGDBResetCommand(gdb.Command):
    '''
    Reset the context fo angrgdb
    '''

    def __init__(self):
        super(
            AngrGDBResetCommand, self).__init__("angrgdb reset", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global _ctx
        self.dont_repeat()

        _ctx = CommandsContext()


class AngrGDBSimCommand(gdb.Command):
    '''
    Set a memory/register as symbolic

    Usage: angrgdb sim <register name> [size]
           angrgdb sim <expression> [size]
    '''

    def __init__(self):
        super(
            AngrGDBSimCommand,
            self).__init__(
            "angrgdb sim",
            gdb.COMMAND_DATA)

    def _process_argv0(self, x):
        r = _to_int(x)
        if r:
            return r
        if x in load_project().arch.registers:
            return x
        raise AngrGDBError(
            "angrdbg sim: the first parameter is not an address or a register")

    def invoke(self, arg, from_tty):
        global _ctx
        self.dont_repeat()

        argv = gdb.string_to_argv(_prepare_args(arg))
        if len(argv) == 0:
            raise AngrGDBError("angrdbg sim: at least a parameter is needed")
        elif len(argv) == 1:
            _ctx.symbolics[self._process_argv0(argv[0])] = None
        else:
            siz = _to_int(argv[1])
            if siz is None:
                raise AngrGDBError(
                    "angrdbg sim: the second parameter (length) must be a number")
            _ctx.symbolics[self._process_argv0(argv[0])] = siz


class AngrGDBListCommand(gdb.Command):
    '''
    List all items that you setted as symbolic
    '''

    def __init__(self):
        super(
            AngrGDBListCommand,
            self).__init__(
            "angrgdb list",
            gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        global _ctx
        self.dont_repeat()

        for k in _ctx.symbolics:
            out = k
            if isinstance(k, int):
                out = "0x%x" % k
            if _ctx.symbolics[k] is not None:
                out += " " * (20 - len(out)) + "<%d>" % _ctx.symbolics[k]
            print (out)


class AngrGDBFindCommand(gdb.Command):
    '''
    Set the list of find targets

    Usage: angrgdb find <address0> <address1> ... <addressN>
    '''

    def __init__(self):
        super(
            AngrGDBFindCommand,
            self).__init__(
            "angrgdb find",
            gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        global _ctx
        self.dont_repeat()

        argv = gdb.string_to_argv(_prepare_args(arg))
        if len(argv) == 0:
            raise AngrGDBError("angrdbg find: at least a parameter is needed")

        _ctx.find = []
        for a in argv:
            addr = _to_int(a)
            if addr is None:
                raise AngrGDBError(
                    "angrdbg find: failed to convert '%s' to int" %
                    a)
            _ctx.find.append(addr)


class AngrGDBAvoidCommand(gdb.Command):
    '''
    Set the list of avoid targets

    Usage: angrgdb avoid <address0> <address1> ... <addressN>
    '''

    def __init__(self):
        super(
            AngrGDBAvoidCommand,
            self).__init__(
            "angrgdb avoid",
            gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        global _ctx
        self.dont_repeat()

        argv = gdb.string_to_argv(_prepare_args(arg))
        if len(argv) == 0:
            raise AngrGDBError("angrdbg avoid: at least a parameter is needed")

        _ctx.avoid = []
        for a in argv:
            addr = _to_int(a)
            if addr is None:
                raise AngrGDBError(
                    "angrdbg avoid: failed to convert '%s' to int" %
                    a)
            _ctx.avoid.append(addr)


class AngrGDBRunCommand(gdb.Command):
    '''
    Generate a state from the debugger state and run the exploration
    '''

    def __init__(self):
        super(
            AngrGDBRunCommand,
            self).__init__(
            "angrgdb run",
            gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        global _ctx
        self.dont_repeat()

        if len(_ctx.find) == 0:
            raise AngrGDBError("angrdbg run: the find list can't be empty")

        print (BANNER + " to find:", ", ".join(map(lambda x: "0x%x" % x, _ctx.find)))
        print (BANNER + " to avoid:", ", ".join(map(lambda x: "0x%x" % x, _ctx.avoid)))

        sm = StateManager(StateShot(sync_brk=False))
        for k in _ctx.symbolics:
            if _ctx.symbolics[k] is None:
                sm.sim(k)
            else:
                sm.sim(k, _ctx.symbolics[k])
        m = sm.simulation_manager()

        print (BANNER + " running the exploration...")
        m.explore(find=_ctx.find, avoid=_ctx.avoid)
        if len(m.found) == 0:
            raise AngrGDBError(
                "angrdbg run: valid state not found after exploration")

        conc = sm.concretize(m.found[0])
        print (BANNER + " results:\n")
        for k in _ctx.symbolics:
            out = k
            if isinstance(k, int):
                out = "0x%x" % k
            if _ctx.symbolics[k] is not None:
                out += " " * (20 - len(out)) + "<%d>" % _ctx.symbolics[k]
            print (out)
            out = conc[k]
            if isinstance(out, (int, long)):
                print ("   ==> 0x%x" % out)
            else:
                ro = repr(out)
                print ("   ==> %s" % ro[1:] if ro.startswith("b") else ro)
            print ()

        r = raw_input(BANNER + " do you want to write-back the results in GDB? [Y, n] ")
        r = r.strip().upper()
        if r == "Y" or r == "":
            print (BANNER + " syncing results with debugger...")
            sm.to_dbg(m.found[0])


AngrGDBCommand()
AngrGDBShellCommand()
AngrGDBResetCommand()
AngrGDBSimCommand()
AngrGDBListCommand()
AngrGDBFindCommand()
AngrGDBAvoidCommand()
AngrGDBRunCommand()
