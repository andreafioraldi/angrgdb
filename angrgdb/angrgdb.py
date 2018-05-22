import sys
import struct
import re

if sys.version_info >= (3, 0):
    print("angrgdb: fatal error: i need python 2")
    exit(1)

try:
    import gdb
except ImportError:
    print("angrgdb: fatal error: not running inside GDB")
    exit(1)

from angrdbg import *

class GDBDebugger(Debugger):
    def __init__(self):
        self.inferior = gdb.selected_inferior()
        self.base_addr = None
        self.long_type = gdb.lookup_type("long")
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
        pid = int(self.inferior.pid)
        maps = []
        mpath = "/proc/%s/maps" % pid
        # 00400000-0040b000 r-xp 00000000 08:02 538840  /path/to/file
        pattern = re.compile("([0-9a-f]*)-([0-9a-f]*) ([rwxps-]*)(?: [^ ]*){3} *(.*)")

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
        matches = filter(lambda x: " in " not in x[2], matches) #don't get sections of shared libs
        return map(lambda x: (int(x[0], 16), int(x[1], 16), x[2]), matches)
    
    #-------------------------------------
    def before_stateshot(self):
        vmmap = self._get_vmmap()
        sections = self._get_sections()
        self.segments = {}
        yet = []
        
        for start, end, name in sections:
            for mstart, mend, perms, mname in vmmap:
                if start >= mstart and start < mend:
                    self.segments[name] = Segment(name, start, end, perms)
                    yet.append(start)
                    break
        
        for mstart, mend, perms, mname in vmmap:
            if mstart not in yet:
                self.segments[mname] = Segment(mname, mstart, mend, perms)
        
        
    def after_stateshot(self, state):
        pass
    #-------------------------------------
    def is_active(self):
        return gdb.selected_thread() is not None
    
    #-------------------------------------
    def input_file_path(self):
        return gdb.current_progspace().filename
    
    def image_base(self):
        if self.base_addr is None:
            mappings = gdb.execute("info proc mappings", to_string=True)
            first_num_pos = mappings.find("0x")
            self.base_addr = int(mappings[first_num_pos: mappings.find(" ", first_num_pos)], 16)
        return self.base_addr
    
    #-------------------------------------
    def get_byte(self, addr):
        try:
            return ord(str(self.inferior.read_memory(addr, 1)))
        except: return None
    
    def get_word(self, addr):
        try:
            return struct.unpack("<H", str(self.inferior.read_memory(addr, 2)))
        except: return None
    
    def get_dword(self, addr):
        try:
            return struct.unpack("<I", str(self.inferior.read_memory(addr, 4)))
        except: return None
    
    def get_qword(self, addr):
        try:
            return struct.unpack("<Q", str(self.inferior.read_memory(addr, 8)))
        except: return None
    
    def get_bytes(self, addr, size):
        try:
            return str(self.inferior.read_memory(addr, size))
        except: return None
    
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
    
    #-------------------------------------
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
    
    #-------------------------------------
    def step_into(self):
        gdb.execute("stepi")
    
    def run(self):
        gdb.execute("continue")
    
    def wait_ready(self):
        pass
    
    def refresh_memory(self):
        pass
    
    #-------------------------------------
    def seg_by_name(self, name):
        return self.segments.get(name, None)

    def seg_by_addr(self, addr):
        r = filter(lambda n: addr >= self.segments[n].start and addr < self.segments[n].end, self.segments.keys())
        if len(r) == 0:
            return None
        return self.segments[r[-1]]
    
    def seg_is_got(self, seg):
        return seg.name == load_project().arch.got_section_name

    #-------------------------------------
    def resolve_name(self, name): #return None on fail
        try:
            res = gdb.execute("info address " + name, to_string=True)
            a = res.find(" is at 0x")
            b = res.find(" ", a + len(" is at 0x"))
            return int(res[a + len(" is at 0x"):b], 16)
        except:
            return None


register_debugger(GDBDebugger())


