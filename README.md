# angrgdb

Use angr inside GDB. Create an angr state from the current debugger state.

The project is very naive at the moment, PR are welcome.

## Install

```
pip install angrgdb
echo "python import angrgdb.commands" >> ~/.gdbinit
```

### WARNING

angrgdb needs gdb compiled with python 2!

You can download the precompiled DEB packeges [here](https://github.com/andreafioraldi/gdb-py2-builds)

## Usage

You can use angrgdb commands directly in GDB for simple stuffs.

Look here for an example:

[![asciicast](https://asciinema.org/a/6KOKIBESiG68iPdesXQTjYJvR.png)](https://asciinema.org/a/6KOKIBESiG68iPdesXQTjYJvR)

angrgdb implements the [angrdbg](https://github.com/andreafioraldi/angrdbg) API in GDB.

You can use it with the `angrgdb shell` command.

```
(gdb) b *0x004005f9
Breakpoint 1 at 0x4005f9
(gdb) r aaaaaaaa
Starting program: /ais3_crackme aaaaaaaa

Breakpoint 1, 0x00000000004005f9 in main ()
(gdb) x/s $rax
0x7fffffffe768:	"aaaaaaaa"
(gdb) angrgdb shell
 >> creating angr project...
 >> done.
[angrgdb]: sm is a StateManager instance created from the current GDB state

In [1]: sm["rip"]
Out[1]: <BV64 0x4005f9>

In [2]: sm[sm["rax"]].string
Out[2]: <string_t <BV64 0x6161616161616161> at 0x7fffffffe768>

In [3]: sm.sim(sm["rax"], 100)

In [4]: m = sm.simulation_manager()

In [5]: m.explore(find=0x00400607, avoid=0x00400613)
Out[5]: <SimulationManager with 3 active, 1 found, 46 avoid>

In [6]: sm.concretize(m.found[0])
Out[6]: {140737488349032L: 'ais3{I_tak3_g00d_n0t3s}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'}

In [7]: sm.to_dbg(m.found[0])

In [8]: exit()

(gdb) x/s $rax
0x7fffffffe768:	"ais3{I_tak3_g00d_n0t3s}"
(gdb) c
Continuing.

Breakpoint 1, 0x00000000004005f9 in main ()
(gdb) c
Continuing.
Correct! that is the secret key!
[Inferior 1 (process 5284) exited normally]
(gdb) q
```

## TODO

+ add remote angrdbg like in IDAngr

