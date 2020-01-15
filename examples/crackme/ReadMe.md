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

Thanks to Michael Bann!

