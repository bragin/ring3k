
#Ring 3 Kernel

###Copyright (C) 2006-2009 Mike McCormack

##About

This project aims to load the userspace of an NT system
into a user space controlled by a usermode kernel.

##Why?

There are several aims for this project:

* understand how the Windows kernel-userland interface works
* provide an alternate method of virtualization
* reduce the scope of reimplementation as compared to Wine
* make application's address space indistinguishable from native Windows
* move closed and non-free code out of ring 0

##Requirements

* A Linux (tm) 2.6.x kernel patches applied.
* A Windows 2000 (tm) CD
* libSDL 1.2
* the mingw cross compiler (for tests)
* glibc with the NPTL version of pthreads
* gcc, g++ 4.2.1 or so
* libxml2 (for registry code)
* libqt4-dev (for regedit)
* cabextract (extract windows cab files)
* isoinfo from http://cdrecord.berlios.de (read the CD)
* On x86-64, the compiler should be able to generate 32-bit code
  (Debian users should install gcc-multilib, g++-multilib, ia32-libs)
* Increased number of file descriptors (e.g. https://underyx.me/2015/05/18/raising-the-maximum-number-of-file-descriptors)


##Instructions

To run winlogon.exe, from the top level directory, do:
```
./configure
make
ln -s /path/to/your/win2k.iso
make test
./ring3k
```
To run a test (for example the semaphore test):
`./runtest sema`

To run all the working tests, do:
`make test`

To run another executable please edit `./ring3k script`

##Debugging ring3k using gdb

As ring3k uses ptrace, it interferes with gdb.  You can still debug 
ring3k coredumps as follows:
```
 $ ulimit -c unlimited
 # echo "core-%p" > /proc/sys/kernel/core_pattern 
 # echo "1" > /proc/sys/kernel/core_uses_pid 
 $ ring3k --trace=core
```
If ring3k crashes, two core files will be generated, one for ring3k-client
and one for ring3k-bin.  You can load them alternately into gdb as follows:
```
 $ gdb --core=core-1234
 (gdb) symbol-file kernel/ring3k-bin
```

##Debug Logs

Logging system is very similar to Wine's one. Use R3KDEBUG env var to control
your debug options.
Syntax of R3KDEBUG variable:

`R3KDEBUG=[class]+xxx,[class]-yyy,...`

Example: `WINEDEBUG=+all,warn-heap`
turns on all messages except warning heap messages

##Silenced debug messages

Some messages are too annoying and unimportant so they have been downgraded
from FIXME to TRACE. Please keep list of those places here.
```
 "fixme: no access check\n" in OBJECT::AccessAllowed, object.cpp
 NtLockFile and NtUnlockFile in file.cpp
 NtFlushInstructionCache in ntcall.cpp
 NtProtectVirtualMemory in mem.cpp
```

##Files

kernel/     - implementation of the userspace kernel

libudis86/  - the udis86 disassembler

libmspack/  - code to extract files from the windows install disk

tests/      - test cases that run on both NT and the loader

tools/      - a collection of windows executables

documents/  - a few notes

##Development

Development of new code and bug fixes should be done with test cases.
The test case should show how Windows functions, and should test the code
that has been written as much as possible.

##Coding style for kernel C++

```c++
class CLASS_NAME
{
	ULONG m_Member;
	VOID InitializeSomeData();
}
```

In case the class name conflicts with the Win32/NT typename, then the name should be prefixed with C, like CBITMAP


##Using QEMU to run tests

Optionally, install kqemu

One time setup:

1. Create a 2G sparse disk image:
    `dd if=/dev/null of=win2k.img bs=1024 seek=2M`

2  Install Windows 2000:
    `qemu -hda win2k.img -cdrom win2k.iso -boot d -m 64`

3. Run QEMU:

	`make qemu`

   OR

	`qemu -hda win2k.img -cdrom nttest.iso -m 64`

4. To run a test, login and start cmd.exe.  To run the thread test, type:

	`d:
	hostnt thread.exe`

5. If you wish to rebuild a test case, do:

	`make
	make cdrom`

   To use the new ISO in QEMU, press <ALT><CTRL>2, to switch to the QEMU
   console and type:

	`eject cdrom`

   You need to make windows notice that there's no disk in the drive first by.
   Do this by pressing <ALT><CTRL>1, and try run the test case by up arrowing
   to hostnt thread.exe then pressing <ENTER>.  When you get a message box
   saying "There is no disk in drive...", switch back to the console using
   <ALT><CTRL>2, and type:

	`change cdrom nttest.iso`

   Then <ALT><CTRL>1 back to Windows and select "Try Again"
   by up arrowing twice on the dialog and pressing enter.


##Starting minitris.exe or pixels.exe on a Windows 2000 QEMU image


Assume you have a windows 2000 install on QEMU in a file named win2k.img,
you can copy minitris.exe over the winlogon.exe on there and it will run
when the image is booted.

Mount the Windows 2000 disk image (as root):

    `mount -o loop,offset=32256 win2k.img /mnt/`

Backup winlogon.exe:

    `cp -i /mnt/winnt/system32/winlogon.exe /mnt/winnt/system32/_winlogon.exe`

Replace winlogon.exe:

    `cp -i ring3k/tools/minitris.exe /mnt/winnt/system32/winlogon.exe`

Unmount the Windows 2000 disk image:

    `umount /mnt`

Run QEMU (as user, making sure you have umount'ed the image first!)

    `qemu -hda win2k.img`


##Winlogon debugging
----------------------------------------------------------------

Add the following to win.ini to enable Winlogon/GINA debug messages (https://technet.microsoft.com/en-US/aa374744):

`; empty
[WinlogonDebug]
DebugFlags=Error,Init,Notify,SAS,State,Timeout,Trace,Warning,Verbose,WAPI,Helpers,RefMon,Scav,Cred,Neg,LPC,SAM,LSA,Special,Queue,Handles,NegLock,EFS

[LsaDs]
DebugFlags=Error,Init,Notify,SAS,State,Timeout,Trace,Warning,Verbose,WAPI,Helpers,RefMon,Scav,Cred,Neg,LPC,SAM,LSA,Special,Queue,Handles,NegLock,EFS

[DsRole]
DebugFlags=Error,Init,Notify,SAS,State,Timeout,Trace,Warning,Verbose,WAPI,Helpers,RefMon,Scav,Cred,Neg,LPC,SAM,LSA,Special,Queue,Handles,NegLock,EFS

[SPM]
DebugFlags=Error,Init,Notify,SAS,State,Timeout,Trace,Warning,Verbose,WAPI,Helpers,RefMon,Scav,Cred,Neg,LPC,SAM,LSA,Special,Queue,Handles,NegLock,EFS

[DSysDebug]
LsaDs=Error,Init,Notify,SAS,State,Timeout,Trace,Warning,Verbose,WAPI,Helpers,RefMon,Scav,Cred,Neg,LPC,SAM,LSA,Special,Queue,Handles,NegLock,EFS
DsRole=Error,Init,Notify,SAS,State,Timeout,Trace,Warning,Verbose,WAPI,Helpers,RefMon,Scav,Cred,Neg,LPC,SAM,LSA,Special,Queue,Handles,NegLock,EFS
SPM=Error,Init,Notify,SAS,State,Timeout,Trace,Warning,Verbose,WAPI,Helpers,RefMon,Scav,Cred,Neg,LPC,SAM,LSA,Special,Queue,Handles,NegLock,EFS
DebugFlags=Error,Init,Notify,SAS,State,Timeout,Trace,Warning,Verbose,WAPI,Helpers,RefMon,Scav,Cred,Neg,LPC,SAM,LSA,Special,Queue,Handles,NegLock,EFS`

Don't forget to use checked build binaries for that!
