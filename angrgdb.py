try:
    import gdb
except ImportError:
    print "angrgdb: fatal error: not running inside GDB"
    exit(1)

import angrdbg

class GDBDebugger(angrdbg.Debugger):
    def __init__(self):
        self.inferior = None
    
    #-------------------------------------
    def is_active(self):
        return gdb.selected_thread() is not None
    
    #-------------------------------------
    def input_file_path(self):
        raise NotImplementedError()
    
    def image_base(self):
        raise NotImplementedError()
    
    #-------------------------------------
    def get_byte(self, addr):
        raise NotImplementedError()
    
    def get_word(self, addr):
        raise NotImplementedError()
    
    def get_dword(self, addr):
        raise NotImplementedError()
    
    def get_qword(self, addr):
        raise NotImplementedError()
    
    def get_bytes(self, addr, size):
        raise NotImplementedError()
    
    def put_byte(self, addr, value):
        raise NotImplementedError()
    
    def put_word(self, addr, value):
        raise NotImplementedError()
    
    def put_dword(self, addr, value):
        raise NotImplementedError()
    
    def put_qword(self, addr, value):
        raise NotImplementedError()
    
    def put_bytes(self, addr, value):
        raise NotImplementedError()
    
    #-------------------------------------
    def get_reg(self, name):
        raise NotImplementedError()
    
    def set_reg(self, name, value):
        raise NotImplementedError()
    
    #-------------------------------------
    def step_into(self):
        raise NotImplementedError()
    
    def run(self):
        raise NotImplementedError()
    
    def wait_ready(self):
        raise NotImplementedError()
    
    def resfresh_memory(self):
        raise NotImplementedError()
    
    #-------------------------------------
    def seg_by_name(self, name):
        raise NotImplementedError()

    def seg_by_addr(self, name):
        raise NotImplementedError()

    #-------------------------------------
    def resolve_name(self, name): #return None on fail
        raise NotImplementedError()



angrdbg.register_debugger(GDBDebugger())


