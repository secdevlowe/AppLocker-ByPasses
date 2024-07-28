# AppLocker-ByPasses
Techniques used to bypass Microsoft Windows AppLocker Security application (https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/applocker-overview).

* [Common-ApplockerByPasses](https://github.com/secdevlowe/AppLocker-ByPasses/blob/main/Common-AppLockerByPasses.md)
* [Confirmed-DefaultConfigByPasses](https://github.com/secdevlowe/AppLocker-ByPasses/blob/main/Confirmed-DefaultConfigByPasses.md)
* [DLLExecution-ByPasses](https://github.com/secdevlowe/AppLocker-ByPasses/blob/main/DLLExecution-ByPasses.md)

# AppLocker-ByPasses-Patching/Hardening
Included AppBlocker rules will cover the discussed bypass techniques and additional items from this information provided by Microsoft - https://docs.microsoft.com/nb-no/windows/security/threat-protection/device-guard/steps-to-deploy-windows-defender-application-control

The provided AppLocker rules are not confirmed to be vetted/tested in a live environment. These rules can break things that you have deployed and use normally. The ruleset will block access/usability to PowerShell and Command Prompt.

These rules can be found in separate .xml files within the AppBlocker-BlockPolicies folder. I am not responsibility for systems that do not work/break when utilizing the provided AppBlocker rules.
