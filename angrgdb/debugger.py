import sys
import struct
import re

try:
    import gdb
except ImportError:
    print("angrgdb: fatal error: not running inside GDB")
    exit(1)

if sys.version_info >= (3, 0):
    long = int
else:
    long
    bytes = str

from angrdbg import *


class GDBDebugger(Debugger):
    def __init__(self):
        self.inferior = gdb.selected_inferior()
        self.pid = self.inferior.pid
        self.base_addr = None
        self.efl_map = {}
        self.efl_map['CF'] = 1 << 0
        self.efl_map['PF'] = 1 << 2
        self.efl_map['AF'] = 1 << 4
        self.efl_map['ZF'] = 1 << 6
        self.efl_map['SF'] = 1 << 7
        self.efl_map['TF'] = 1 << 8
        self.efl_map['IF'] = 1 << 9
        self.efl_map['DF'] = 1 << 10
        self.efl_map['OF'] = 1 << 11

    def _get_vmmap(self):
        maps = []
        if self.pid == 0:
            self.pid = self.inferior.pid
        mpath = "/proc/%s/maps" % self.pid
        # 00400000-0040b000 r-xp 00000000 08:02 538840  /path/to/file
        pattern = re.compile(
            "([0-9a-f]*)-([0-9a-f]*) ([rwxps-]*)(?: [^ ]*){3} *(.*)")

        out = open(mpath).read()

        matches = pattern.findall(out)
        if matches:
            for (start, end, perm, mapname) in matches:
                start = int(("0x%s" % start), 0)
                end = int(("0x%s" % end), 0)
                if mapname == "":
                    mapname = "mapped"
                mapperm = 0
                if "r" in perm:
                    mapperm |= SEG_PROT_R
                if "w" in perm:
                    mapperm |= SEG_PROT_W
                if "x" in perm:
                    mapperm |= SEG_PROT_X
                maps += [(start, end, mapperm, mapname)]
        return maps

    def _get_sections(self):
        base = self.image_base()
        info = gdb.execute("info file", to_string=True)
        # 0x0000000000000238 - 0x0000000000000254 is .interp
        pattern = re.compile("0x([0-9a-f]*) - 0x([0-9a-f]*) is (.*)")

        matches = pattern.findall(info)
        # don't get sections of shared libs
        matches = filter(lambda x: " in " not in x[2], matches)
        return map(lambda x: (int(x[0], 16), int(x[1], 16), x[2]), matches)

    # -------------------------------------
    def before_stateshot(self):
        self.vmmap = self._get_vmmap()
        self.base_addr = self.vmmap[0][0]
        sections = self._get_sections()

        for start, end, name in sections:
            if name == load_project().arch.got_section_name:
                self.got = (start, end)
            elif name == ".plt":
                self.plt = (start, end)
            elif name == ".idata":
                self.plt = (start, end)
        self.long_type = gdb.lookup_type("long")

    def after_stateshot(self, state):
        pass
    # -------------------------------------

    def is_active(self):
        return gdb.selected_thread() is not None

    # -------------------------------------
    def input_file(self):
        return open(gdb.current_progspace().filename, "rb")

    def image_base(self):
        return self.base_addr

    # -------------------------------------
    def get_byte(self, addr):
        try:
            return int(self.inferior.read_memory(addr, 1).tobytes()[0])
        except BaseException:
            return None

    def get_word(self, addr):
        try:
            return struct.unpack(
                "<H", self.inferior.read_memory(addr, 2).tobytes())[0]
        except BaseException:
            return None

    def get_dword(self, addr):
        try:
            return struct.unpack(
                "<I", self.inferior.read_memory(addr, 4).tobytes())[0]
        except BaseException:
            return None

    def get_qword(self, addr):
        try:
            return struct.unpack("<Q", self.inferior.read_memory(addr, 8).tobytes())[0]
        except BaseException:
            return None

    def get_bytes(self, addr, size):
        try:
            return self.inferior.read_memory(addr, size).tobytes()
        except BaseException:
            return None

    def put_byte(self, addr, value):
        self.inferior.write_memory(addr, chr(value))

    def put_word(self, addr, value):
        self.inferior.write_memory(addr, struct.pack("<H", value))

    def put_dword(self, addr, value):
        self.inferior.write_memory(addr, struct.pack("<I", value))

    def put_qword(self, addr, value):
        self.inferior.write_memory(addr, struct.pack("<Q", value))

    def put_bytes(self, addr, value):
        self.inferior.write_memory(addr, value)

    # -------------------------------------
    def get_reg(self, name):
        if name == "efl" or name == "eflags":
            value = 0
            for f in self.efl_map:
                if f in str(gdb.parse_and_eval("$eflags")):
                    value |= self.efl_map[f]
            return value
        else:
            return int(gdb.parse_and_eval("$" + name).cast(self.long_type))

    def set_reg(self, name, value):
        if name == "efl":
            name = "eflags"
        gdb.execute("set $%s = %d" % (name, value))

    # -------------------------------------
    def step_into(self):
        gdb.execute("stepi", to_string=True)

    def run(self):
        gdb.execute("continue")

    def wait_ready(self):
        pass

    def refresh_memory(self):
        pass

    # -------------------------------------
    def seg_by_name(self, name):
        for start, end, perms, mname in self.vmmap:
            if name == mname:
                return Segment(name, start, end, perms)
        return None

    def seg_by_addr(self, addr):
        for start, end, perms, name in self.vmmap:
            if addr >= start and addr < end:
                return Segment(name, start, end, perms)
        return None

    def get_got(self):  # return tuple(start_addr, end_addr)
        return self.got

    def get_plt(self):  # return tuple(start_addr, end_addr)
        return self.plt
    
    def get_idata(self):  # return tuple(start_addr, end_addr)
        return self.idata

    # -------------------------------------
    def resolve_name(self, name):  # return None on fail
        try:
            res = gdb.execute("info address " + name, to_string=True)
            a = res.find(" is at 0x")
            b = res.find(" ", a + len(" is at 0x"))
            return int(res[a + len(" is at 0x"):b], 16)
        except BaseException:
            return None


register_debugger(GDBDebugger())
