# angrgdb
Use angr inside GDB. Create an angr state from the current debugger state.

## WARNING
Use gdb compiled with python 2!

You can download precompiled DEB packeges [here](https://github.com/andreafioraldi/gdb-py2-builds)

## Usage

angrgdb implements the [angrdbg](https://github.com/andreafioraldi/angrdbg) API in GDB.

```
(gdb) b *0x004005f9
Breakpoint 1 at 0x4005f9
(gdb) r aaaaaaaa
Starting program: /ais3_crackme aaaaaaaa

Breakpoint 1, 0x00000000004005f9 in main ()
(gdb) i r rax
rax            0x7fffffffe767	140737488349031
(gdb) x/s $rax
0x7fffffffe767:	"aaaaaaaa"
(gdb) pi
>>> from angrgdb import *
>>> s = StateManager() 
 >> creating angr project...
 >> done.
>>> s["rip"]
<BV64 0x4005f9>
>>> s[s["rax"]].string
<string_t <BV64 0x6161616161616161> at 0x7fffffffe767>
>>> s.sim(s["rax"], 100)
>>> m = s.simulation_manager()
>>> m.explore(find=0x00400607, avoid=0x00400613)
<SimulationManager with 3 active, 1 found, 46 avoid>
>>> s.concretize(m.found[0])
{140737488349031L: 'ais3{I_tak3_g00d_n0t3s}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'}
>>> s.to_dbg(m.found[0])
>>> 
(gdb) x/s $rax
0x7fffffffe767:	"ais3{I_tak3_g00d_n0t3s}"
(gdb) c
Continuing.

Breakpoint 1, 0x00000000004005f9 in main ()
(gdb) c
Continuing.
Correct! that is the secret key!
[Inferior 1 (process 3228) exited normally]
(gdb) q
```
