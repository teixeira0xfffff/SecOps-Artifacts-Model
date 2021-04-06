
SecOps (OSCP/OSCE Road) Documento DEMO

 By[ Seu Nome](https:/SUA_URL/xxxxxxxxxxxxxxxxxxxxxxxx)

![](imagem_do_header.jpg)


Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum. 

```javascript
*Note: due to the size of the registry artifacts retrieved they will not be listed in this paper. Registry dumps for HKEY\_LOCAL\_MACHINE, HKEY\_CURRENT\_CONFIG, HKEY\_CLASSES\_ROOT, HKEY\_USERS, and HKEY\_CURRENT\_USER can be viewed on my GitHub.* 
```

[*https://github.com/D3VI5H4/Antivirus-Artifacts/tree/main/Registry%20Data](https://github.com/D3VI5H4/Antivirus-Artifacts/tree/main/Registry%20Data)* Summary of Antivirus Artifacts I: 

The most common method to determine if an anti-virus product or EDR system is in place is using the [WMIC](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic) and performing a basic query against the [Windows Security Center namespace](https://docs.microsoft.com/en-us/windows/win32/api/wscapi/). 

```javascript
wmic /node:localhost /namespace:\\root\SecurityCenter2 path AntiVirusProduct Get DisplayName | findstr /V /B /C:displayName || echo No Antivirus installed 
```

*courtesy of [Sam Denty](https://stackoverflow.com/users/5269570/sam-denty) from [StackOverflow](https://stackoverflow.com/questions/42472336/is-there-a-command-to-check-if-there-was-any-antivirus-installed)* 

Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.  

## Summary of Antivirus Artifacts II: 

This release is to act *as an amendment* to the original paper by diving deeper into antivirus products and their operations by documenting drivers loaded into the Windows kernel as well as listing the[ file system filters](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts) in place. 

*Note:* *all data listed and found is the result of a clean installation with default configuration. As data from the antivirus were discovered there were fluctuations in web traffic. All web traffic listed was discovered from the antivirus at run-time. In the event you decide to review any of the products listed in this paper note you may get different results based on your geographical location or activity being performed by the antivirus product.* 

## Avira



|Parent Directory |
| - |
|C:\Program Files (x86)\Avira\ |
Binaries present: 



|Name |Description |Sub directory |
| - | - | - |
|Avira.ServiceHost.exe |Avira Service Host |Launcher |
|Avira.Systray.exe |Avira |Launcher |
|Avira.OptimizerHost.exe |Avira Optimizer Host |Optimizer Host |
|Avira.VpnService.exe |VpnService |VPN |
|Avira.SoftwareUpdater.ServiceHost.exe |Avira Updater Service Host |Software Updater |
|Avira.Spotlight.Service.exe |Avira Security |Launcher |
|avguard.exe |Antivirus Host Framework Service |Antivirus |
|avshadow.exe |Anti vir Shadow copy Service |Antivirus |
|protectedservice.exe |Avira Protected Antimalware Service |Antivirus |
|avipbb.sys |Avira Driver for Security Enhancement |C:\Windows\System32\Drivers\ |
|avkmgr.sys |Avira Manager Driver |C:\Windows\System32\Drivers\ |
|avgntflt.sys |Avira Minifilter Driver |C:\Windows\System32\Drivers\ |
|avdevprot.sys |Avira USB Feature Driver |C:\Windows\System32\Drivers\ |
|avusbflt.sys |Avira USB Filter Driver |C:\Windows\System32\Drivers\ |
|avnetflt.sys |Avira WFP Network Driver |C:\Windows\System32\Drivers\ |
In-memory modules present: 



|Name |Description |Sub Directory |
| - | - | - |
|Avira.SystemSpeedUp.UI.ShellExtension.dll |Avira.SystemSpeedUp.UI.ShellExtension.dll |System SpeedUp |
Functions Hooked: 



|N/A |N/A |N/A |
| - | - | - |
Minifilters Present: 



|Driver |Altitude |Type |
| - | - | - |
|avipbb.sys|[367600](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#360000---389999-fsfilter-activity-monitor)|FSFilter Activity Monitor |
|avgntflt.sys|[320500](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus)|FSFilter Anti-Virus |



|Antivirus Driver |Request |
| - | - |
|avgntflt.sys |[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|avgntflt.sys |[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-cleanup) |
|avgntflt.sys |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|avgntflt.sys |[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|avgntflt.sys |[IRP_MJ_SET_SECURITY](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-security) |
|avgntflt.sys |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
|avgntflt.sys |[IRP_MJ_FLUSH_BUFFERS](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-flush-buffers) |
|avgntflt.sys |[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control) |


## Web Traffic: 



|Protocol |Remote Address |Local Port |Remote Port |
| - | - | - | - |
|TCP |35.157.123.32 |64359 |443 |
|TCP |18.196.164.37 |64546 |443 |
|TCP |35.186241.51 |64536 |443 |
|TCP |18.157.205.1 |64540 |80 |
|TCP |18.157.205.1 |64541 |443 |
|TCP |104.19.148.8 |64542 |443 |
|TCP |172.217.167.232 |64543 |443 |
|TCP |13.35.221.216 |64544 |443 |
|TCP |13.35.221.216 |64545 |443 |
|TCP |172.217.167.206 |64547 |443 |
|TCP |52.86.179.151 |64548 |443 |
|TCP |74.125.24.157 |64549 |443 |
|TCP |172.217.167.196 |64550 |443 |
|TCP |172.217.167.195 |64551 |443 |

## Services: 



|Name |Description |Startup Type |Path |
| - | - | - | - |
|Avira Service Host |Hosts multiple Avira Services within one Windows service. |Automatic |\Launcher\Avira.ServiceHos t.exe |
|Avira Optimizer Host |Hosts multiple Avira optimization services within one Windows service. |Automatic |\Optimizer Host\Avira.OptimizerHost.e xe |
|AviraPhantomVPN |Avira Phantom VPN |Automatic |\VPN\Avira.VpnService.exe |
|Avira Updater Service |Support service for Avira Software Updater |Automatic |\SoftwareUpdater\Avira.Sof twareUpdater.ServiceHost.e xe |
|Avira Security |Avira Security |Automatic |\Security\Avira.Spotlight.Se rvice.exe |
|Avira Mail Protection |Offers permanent protection against viruses and malware for email clients with the Avira search engine. |Automatic |\Antivirus\avmailc7.exe |
|Avira Protected Service |Launch Avira's anti-malware service as a protected service. |Automatic |\Antivirus\ProtectedService. exe |
|Avira Real Time Protection |Offers permanent protection against viruses and malware with the Avira search engine. |Automatic |\Antivirus\avguard.exe |
|Avira Scheduler |<p>Service to schedule Avira Antivirus jobs </p><p>- updates </p>|Automatic |\Antivirus\sched.exe |
|Avira Web Protection  |Offers permanent protection against viruses & malware for web browsers with the Avira Search Engine  |Automatic |\Antivirus\avwebg7.exe |
FSecure 






## Conclusion: 

Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum. 

Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum. 

## UML diagrams

Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.

```mermaid
graph LR
A[Square Rect] -- Link text --> B((Circle))
A --> C(Round Rect)
B --> D{Rhombus}
C --> D
