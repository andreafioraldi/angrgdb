This crackme and procedure is taken from this site:
https://bannsecurity.com/index.php/home/10-ctf-writeups/51-utctf-2019-crackme
The only difference is that I already patched out the ptrace test, since this example is just to show the functionality of angrgdb

Commands to run this example:
```
# Break AFTER all that setup and exception catching is done
break *0x400C96
# Start it up
r
# Give it a buffer of 63 "A"s
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
# Tell angr to find the solution and avoid the failures
angrgdb find 0x400DAC
angrgdb avoid 0x400DC8
# Tell angr to mark our 64 bytes as symbolic
angrgdb sim $rbp-0x50 0x40
# Run!
angrgdb run
```
Like this:
```
$ gdb ./crackmenoptrace 
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
Reading symbols from ./crackmenoptrace...
(No debugging symbols found in ./crackmenoptrace)
(gdb) break *0x400C96
Breakpoint 1 at 0x400c96
(gdb) r
Starting program: /home/jan/Downloads/crackmenoptrace 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Please enter the correct password.
>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, 0x0000000000400c96 in main ()
(gdb) 
(gdb) angrgdb find 0x400DAC
(gdb) angrgdb avoid 0x400DC8
(gdb) angrgdb sim $rbp-0x50 0x40
WARNING | 2020-01-15 07:29:06,778 | cle.backends.externs | Symbol was allocated without a known size; emulation will fail if it is used non-opaquely: _ZTIi
WARNING | 2020-01-15 07:29:06,780 | cle.loader | For more information about "Symbol was allocated without a known size", see https://docs.angr.io/extending-angr/environment#simdata
WARNING | 2020-01-15 07:29:06,823 | cle.backends.externs | Symbol was allocated without a known size; emulation will fail if it is used non-opaquely: _ZTIi
WARNING | 2020-01-15 07:29:06,824 | cle.loader | For more information about "Symbol was allocated without a known size", see https://docs.angr.io/extending-angr/environment#simdata
WARNING | 2020-01-15 07:29:06,824 | angr.project | Disabling IRSB translation cache because support for self-modifying code is enabled.
(gdb) angrgdb run
 >> to find: 0x400dac
 >> to avoid: 0x400dc8
 >> running the exploration...
WARNING | 2020-01-15 07:29:13,557 | angr.engines.vex.lifter | Self-modifying code is not always correctly optimized by PyVEX. To guarantee correctness, VEX optimizations have been disabled.
 >> results:

0x7fffffffde30      <64>
   ==> '1_hav3_1nf0rmat10n_that_w1ll_lead_t0_th3_arr3st\x1b0f_cspp3rstick6\x00'


 >> do you want to write-back the results in GDB? [Y, n]  >> syncing results with debugger...
(gdb) 

```
Thanks to Michael Bann!

