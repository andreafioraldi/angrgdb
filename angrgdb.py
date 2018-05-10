import sys
import struct

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
        self.segments = None
    
    #-------------------------------------
    def is_active(self):
        return gdb.selected_thread() is not None
    
    #-------------------------------------
    def input_file_path(self):
        return gdb.current_progspace().filename
    
    def image_base(self):
        mappings = gdb.execute("info procs mappings", to_string=True)
        first_num_pos = mappings.find("0x")
        return int(mappings[first_num_pos: mappings.find(" ", first_num_pos)], 16)
    
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
        return int(gdb.parse_and_eval("$" + name))
    
    def set_reg(self, name, value):
        gdb.execute("set $%s = %d" % (name, value))
    
    #-------------------------------------
    def step_into(self):
        gdb.execute("stepi")
    
    def run(self):
        gdb.execute("continue")
    
    def wait_ready(self):
        pass
    
    def resfresh_memory(self):
        pass
    
    #-------------------------------------
    def _get_segs(self):
        info = gdb.execute("info file", to_string=True)
        entry_pos = info.find("Entry point: ")
        map_pos = info.find("\n", entry_pos) +1
        
        self.segments = {}
        for line in info[map_pos:].split("\n"):
            is_pos = line.find("is")
            addresses = line[:is_pos].split("-")
            start, end = map(lambda x: int(x.strip(), 16), addresses)
            name = line[is_pos + 2:].lstrip()
            seg = Segment(name, start, end, SEG_PROT_R | SEG_PROT_W | SEG_PROT_X) #rwx bleah!
            self.segments[name] = seg
    
    def seg_by_name(self, name):
        if self.segments == None:
            self._get_segs()
        return self.segments.get(name, None)

    def seg_by_addr(self, addr):
        r = filter(lambda n: addr in xrange(self.segments[n].start, self.segments[n].end), self.segments.keys())
        if len(r) == 0:
            return Segment("", addr, addr +1, SEG_PROT_R | SEG_PROT_W | SEG_PROT_X) #rwx bleah!
        return self.segments[r[0]]

    #-------------------------------------
    def resolve_name(self, name): #return None on fail
        raise NotImplementedError()



register_debugger(GDBDebugger())


