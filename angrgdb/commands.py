import gdb
import IPython

import angrdbg
import angrgdb
from angrgdb import *

class AngrGDBCommand(gdb.Command):
    def __init__(self):
        super(AngrGDBCommand, self).__init__("angrgdb", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        self.dont_repeat()
        if arg == "":
            if from_tty:
                sm = StateManager()
                IPython.embed(
                    banner1="[angrgdb]: sm is a StateManager instance created from the current GDB state\n", 
                    banner2="",
                    exit_msg="",
                    use_ns={"sm": sm}
                )
            else:
                raise RuntimeError("The ipython shell can be launched only from the tty")
        else:
            raise RuntimeError("Unrecognized angrgdb argument '%s'" % arg)


AngrGDBCommand()


