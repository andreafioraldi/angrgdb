On the main page for this project, there is an example in the form of an asciinema. The executable for that example comes from [BackdoorCTF 2017]

Commands to run this example:
```
# Break AFTER all that setup and exception catching is done
b *0x40085e
# Start it up, give it a buffer of "0"s
r 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
# Tell angr to find the solution and avoid the failures
angrgdb find 0x4007b6
angrgdb avoid 0x4007cc
# Tell angr to mark 30 bytes as symbolic
angrgdb sim ($rbp-0x30) 30 
# Run!
angrgdb run
```
Like this:
```
/Downloads/Backdoor_CTF _no-calm$ gdb ./challenge 
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
Reading symbols from ./challenge...
(No debugging symbols found in ./challenge)
(gdb) b *0x40085e
Breakpoint 1 at 0x40085e
(gdb) r 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
Starting program: /home/jan/Downloads/Backdoor_CTF _no-calm/challenge 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

Breakpoint 1, 0x000000000040085e in main ()
(gdb) angrgdb sim ($rbp-0x30) 30 
WARNING | 2020-01-15 23:49:06,569 | angr.project | Disabling IRSB translation cache because support for self-modifying code is enabled.
(gdb) angrgdb find 0x4007b6
(gdb) angrgdb avoid 0x4007cc
(gdb) angrgdb run
 >> to find: 0x4007b6
 >> to avoid: 0x4007cc
 >> running the exploration...
WARNING | 2020-01-15 23:50:58,613 | angr.engines.vex.lifter | Self-modifying code is not always correctly optimized by PyVEX. To guarantee correctness, VEX optimizations have been disabled.
 >> results:

0x7fffffffde10      <30>
   ==> 'CTF{Now_th1s_1s_t0_g3t_ANGRyy}'


 >> do you want to write-back the results in GDB? [Y, n]  >> syncing results with debugger...
(gdb) c
Continuing.
hacked[Inferior 1 (process 6036) exited normally]
(gdb) 

```

