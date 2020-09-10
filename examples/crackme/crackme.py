from angrgdb import *

gdb.execute("b *0x400C96")
gdb.execute("r")
# !!! Note:
# still have to enter this by hand:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
sm = StateManager()
sm.sim(sm["rbp"]-0x50, 0x40)

m = sm.simulation_manager()
m.explore(find=0x400DAC, avoid=0x400DC8)
sm.to_dbg(m.found[0]) #write input to GDB
#show memory
gdb.execute("x/30s $rbp-0x60")


