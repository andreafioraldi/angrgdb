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
you can use the python example by calling

```source ais3_crackme.py```

like this:
```
$ gdb challenge 
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
Reading symbols from challenge...
(No debugging symbols found in challenge)
(gdb) source challenge.py 
Breakpoint 1 at 0x40085e

Breakpoint 1, 0x000000000040085e in main ()
0x0000000000400002 in ?? ()
WARNING | 2020-01-16 06:16:59,305 | angrdbg.page | map_page received address and length combination which contained mapped page
WARNING | 2020-01-16 06:16:59,305 | angrdbg.core | failed to sychronize brk
0x7fffffffde00:	""
0x7fffffffde01:	""
0x7fffffffde02:	""
0x7fffffffde03:	""
0x7fffffffde04:	""
0x7fffffffde05:	""
0x7fffffffde06:	""
0x7fffffffde07:	""
0x7fffffffde08:	""
0x7fffffffde09:	""
0x7fffffffde0a:	""
0x7fffffffde0b:	""
0x7fffffffde0c:	""
0x7fffffffde0d:	""
0x7fffffffde0e:	""
0x7fffffffde0f:	""
0x7fffffffde10:	"CTF{Now_th1s_1s_t0_g3t_ANGRyy}"
0x7fffffffde2f:	""
0x7fffffffde30:	""
0x7fffffffde31:	""
0x7fffffffde32:	""
0x7fffffffde33:	""
0x7fffffffde34:	""
0x7fffffffde35:	""
0x7fffffffde36:	""
0x7fffffffde37:	""
0x7fffffffde38:	""
0x7fffffffde39:	""
0x7fffffffde3a:	""
0x7fffffffde3b:	""
0x7fffffffde3c:	""
0x7fffffffde3d:	""
0x7fffffffde3e:	""
0x7fffffffde3f:	""
0x7fffffffde40:	"\340\r@"
0x7fffffffde44:	""
0x7fffffffde45:	""
0x7fffffffde46:	""
0x7fffffffde47:	""
--Type <RET> for more, q to quit, c to continue without paging--
0x7fffffffde48:	"\343\021\300\367\377\177"
0x7fffffffde4f:	""
0x7fffffffde50:	""
0x7fffffffde51:	""
0x7fffffffde52:	""
0x7fffffffde53:	""
0x7fffffffde54:	""
0x7fffffffde55:	""
0x7fffffffde56:	""
0x7fffffffde57:	""
0x7fffffffde58:	"(\337\377\377\377\177"
0x7fffffffde5f:	""
0x7fffffffde60:	""
0x7fffffffde61:	""
0x7fffffffde62:	""
0x7fffffffde63:	""
0x7fffffffde64:	"\037"
0x7fffffffde66:	""
0x7fffffffde67:	""
0x7fffffffde68:	"\342\a@"
0x7fffffffde6c:	""
0x7fffffffde6d:	""
0x7fffffffde6e:	""
0x7fffffffde6f:	""
0x7fffffffde70:	""
(gdb) 

```
