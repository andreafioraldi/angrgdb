# angrgdb

Use angr inside GDB. Create an angr state from the current debugger state.

## Install

```
pip install angrgdb
echo "python import angrgdb.commands" >> ~/.gdbinit
```

## Usage

angrgdb implements the [angrdbg](https://github.com/andreafioraldi/angrdbg) API in GDB.

You can use it in scripts like this:

```python
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
```

You can also use angrgdb commands directly in GDB for simple stuffs:

+ `angrgdb sim <register name> [size]` Symbolize a register
+ `angrgdb sim <address> [size]` Symbolize a memory area
+ `angrgdb list` List all items that you setted as symbolic
+ `angrgdb find <address0> <address1> ... <addressN>` Set the list of find targets
+ `angrgdb avoid <address0> <address1> ... <addressN>` Set the list of avoid targets
+ `angrgdb reset` Reset the context (symbolic values and targets)
+ `angrgdb run` Generate a state from the debugger state and run the exploration
+ `angrgdb shell` Open an shell with a StateManager instance created from the current GDB state

An example crackme solve using angrgdb+GEF+[idb2gdb](https://github.com/andreafioraldi/idb2gdb):

[![asciicast](https://asciinema.org/a/207571.png)](https://asciinema.org/a/207571)

### Loading scripts in GDB

This is a tip if you don't want to use angrgdb from the cli but you want to use a python script.
To load a script in GDB use `source script.py`.

## TODO

+ add remote angrdbg like in IDAngr

