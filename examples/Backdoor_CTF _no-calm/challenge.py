from angrgdb import *

gdb.execute("b *0x40085e")
gdb.execute("r 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0")

sm = StateManager()
sm.sim(sm["rbp"]-64, 64)

m = sm.simulation_manager()
m.explore(find=0x4007b6, avoid=0x4007cc)
sm.to_dbg(m.found[0]) #write input to GDB
#show memory
gdb.execute("x/64s $rbp-64")

