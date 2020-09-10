from angrgdb import *

gdb.execute("b *0x004005f9")
gdb.execute("r aaaaaaaa")

sm = StateManager()
sm.sim(sm["rax"], 100)

m = sm.simulation_manager()
m.explore(find=0x00400607, avoid=0x00400613)

sm.to_dbg(m.found[0]) #write input to GDB

gdb.execute("x/s $rax")
#0x7fffffffe768:	"ais3{I_tak3_g00d_n0t3s}"
gdb.execute("c")
#Correct! that is the secret key!
