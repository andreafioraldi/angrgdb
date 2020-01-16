Some of the content of this example was taken this site:
https://github.com/andreafioraldi/angrgdb
which is an older version of the github page for angrgdb, but the commands don't work with the current version.

The executable is one of the standard angr executables available here:
https://github.com/angr/angr-doc/tree/master/examples/ais3_crackme

Commands to run this example:
```
# Break AFTER all that setup and exception catching is done
b *0x004005f9
# Start it up, give it a buffer of "a"s
r  aaaaaaaa
# Tell angr to find the solution and avoid the failures
angrgdb find 0x00400607
angrgdb avoid 0x00400613
# Tell angr to mark our 64 bytes as symbolic
angrgdb sim $rax 100
# Run!
angrgdb run
```
Like this:
```
$ gdb ./ais3_crackme 
GNU gdb (Ubuntu 8.3-0ubuntu1) 8.3
Copyright (C) 2019 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./ais3_crackme...
(No debugging symbols found in ./ais3_crackme)
(gdb) b *0x004005f9
Breakpoint 1 at 0x4005f9
(gdb) r  aaaaaaaa
Starting program: /home/jan/Downloads/ais3_crackme aaaaaaaa

Breakpoint 1, 0x00000000004005f9 in main ()
(gdb) angrgdb sim $rax 100
WARNING | 2020-01-15 23:21:16,672 | angr.project | Disabling IRSB translation cache because support for self-modifying code is enabled.
(gdb) angrgdb find 0x00400607
(gdb) angrgdb avoid 0x00400613
(gdb) angrgdb run
 >> to find: 0x400607
 >> to avoid: 0x400613
 >> running the exploration...
WARNING | 2020-01-15 23:22:14,215 | angr.engines.vex.lifter | Self-modifying code is not always correctly optimized by PyVEX. To guarantee correctness, VEX optimizations have been disabled.
 >> results:

0x7fffffffe3d8      <100>
   ==> 'ais3{I_tak3_g00d_n0t3s}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


 >> do you want to write-back the results in GDB? [Y, n]  >> syncing results with debugger...
(gdb) c
Continuing.
Correct! that is the secret key!
[Inferior 1 (process 27979) exited normally]
(gdb) 

```

you can use the python example by calling 

```source ais3_crackme.py```

like this:

```
gdb ais3_crackme 
GNU gdb (Ubuntu 8.3-0ubuntu1) 8.3
Copyright (C) 2019 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ais3_crackme...
(No debugging symbols found in ais3_crackme)
(gdb) source ais3_crackme.py 
Breakpoint 1 at 0x4005f9

Breakpoint 1, 0x00000000004005f9 in main ()
0x0000000000400002 in ?? ()
0x7fffffffe3b6:	"ais3{I_tak3_g00d_n0t3s}"

Breakpoint 1, 0x00000000004005f9 in main ()
(gdb) 

```

