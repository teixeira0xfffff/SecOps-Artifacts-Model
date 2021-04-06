
ANTI-VIRUS ARTIFACTS 

III

// By[ Devisha Rochlani](https://twitter.com/DevishaRochlani)

![](Aspose.Words.c11649cf-0992-4348-b51e-fef399b2c725.001.jpeg)

Table of Contents 



|Topic |Page |
| - | - |
|Introduction |3 |
|Avira |4 - 7 |
|F-Secure |8 - 10 |
|Norton |11 - 15 |
|TrendMicro |16 - 18 |
|WebRoot |19 - 22 |
|BitDefender |23 - 27 |
|MalwareBytes |28 - 30 |
|Adaware |31 - 32 |
|AVAST |33 - 37 |
|Dr. Web |38 - 40 |
|Kaspersky |41 - 43 |
|Conclusion |44 |
Welcome to Antivirus Artifacts III. ![](Aspose.Words.c11649cf-0992-4348-b51e-fef399b2c725.002.png)

The Antivirus Artifacts series so far has focused exclusively on mnemonic artifacts: drivers, API hooks, or processes which may be present. This third entry identifies registry artifacts from the AV product as well as services. New AVs have been added to the collection: Adaware, Dr. Web, AVAST , Kaspersky. 

*Note: due to the size of the registry artifacts retrieved they will not be listed in this paper. Registry dumps for HKEY\_LOCAL\_MACHINE, HKEY\_CURRENT\_CONFIG, HKEY\_CLASSES\_ROOT, HKEY\_USERS, and HKEY\_CURRENT\_USER can be viewed on my GitHub.* 

[*https://github.com/D3VI5H4/Antivirus-Artifacts/tree/main/Registry%20Data](https://github.com/D3VI5H4/Antivirus-Artifacts/tree/main/Registry%20Data)* Summary of Antivirus Artifacts I: 

The most common method to determine if an anti-virus product or EDR system is in place is using the [WMIC](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic) and performing a basic query against the [Windows Security Center namespace](https://docs.microsoft.com/en-us/windows/win32/api/wscapi/). 

wmic /node:localhost /namespace:\\root\SecurityCenter2 path AntiVirusProduct Get DisplayName | findstr /V /B /C:displayName || echo No Antivirus installed 

*courtesy of [Sam Denty](https://stackoverflow.com/users/5269570/sam-denty) from [StackOverflow](https://stackoverflow.com/questions/42472336/is-there-a-command-to-check-if-there-was-any-antivirus-installed)* 

This method will work in most scenarios. The problem presented here is that this will only return a string if the anti-virus product, or the EDR system, has chosen to register itself in the Windows Security Center namespace. If the product has not registered itself this query will fail. Knowing we are dependent on a security product to register itself I have decided to go down a different path.  

Summary of Antivirus Artifacts II: 

This release is to act *as an amendment* to the original paper by diving deeper into antivirus products and their operations by documenting drivers loaded into the Windows kernel as well as listing the[ file system filters](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/filter-manager-concepts) in place. 

*Note:* *all data listed and found is the result of a clean installation with default configuration. As data from the antivirus were discovered there were fluctuations in web traffic. All web traffic listed was discovered from the antivirus at run-time. In the event you decide to review any of the products listed in this paper note you may get different results based on your geographical location or activity being performed by the antivirus product.* 

Avira



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

[continued below] 

Web Traffic: 



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
[continued below] 

Services: 



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



|Parent Directory |
| - |
|C:\Program Files(x86)\F-Secure\Anti-Virus\ |
Binaries present: 



|Name |Description |Sub directory |
| - | - | - |
|fshs.sys |DG 64-bit kernel module |Ultralight\ulcore\%ld\ |
|fsulgk.sys |F-Secure Gatekeeper 64 bit |Ultralight\ulcore\%ld\ |
|nif2s64.sys |F-Secure NIF2 Core Driver |N/A |
|fshoster32.exe |F-Secure plugin hosting service |N/A |
|fsorsp64.exe |F-Secure ORSP Service 32-bit (Release) |Ultralight\ulcore\%ld\ |
|fshoster64.exe |F-Secure plugin hosting service |Ultralight\ulcore\%ld\ |
|fsulprothoster.exe |F-Secure plugin hosting service |Ultralight\ulcore\%ld\ |
In-memory modules present: 



|Name |Description |Sub Directory |
| - | - | - |
|spapi64.dll |F-Secure Scanning API 64-bit |Ultralight\ulcore\%ld\ |
|fsamsi64.dll |F-Secure AMSI Client |Ultralight\ulcore\%ld\ |
|fs\_ccf\_ipc\_64.dll |Inter-process communication library |Ultralight\ulcore\%ld\ |
Functions Hooked: 



|N/A |N/A |N/A |
| - | - | - |
Minifilters Present: 



|Driver |Altitude |Type |
| - | - | - |
|fshs.sys|[388222](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#360000---389999-fsfilter-activity-monitor)|FSFilter Activity Monitor |
|fshs.sys|[388221](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#360000---389999-fsfilter-activity-monitor)|FSFilter Activity Monitor |
|fsatp.sys|[388220](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#360000---389999-fsfilter-activity-monitor)|FSFilter Activity Monitor |
|fsgk.sys|[322000](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus)|FSFilter Anti-Virus |



|Antivirus Driver |Request |
| - | - |
|fsulgk.sys |[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|fsulgk.sys |[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-cleanup) |
|fsulgk.sys |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|fsulgk.sys |[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|fsulgk.sys |[IRP_MJ_SET_SECURITY](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-security) |
|fsulgk.sys |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |

Web Traffic: 



|Protocol |Remote Address |Local Port |Remote Port |
| - | - | - | - |
|TCP |34.240.57.157 |50256 |443 |
|TCP |23.199.50.97 |50264 |443 |
|TCP |18.210.194.134 |50310 |80 |
|TCP |18.210.194.134 |50311 |80 |

` `PAGE8 Antivirus Artifacts III 
Services: 


|Name |Description |Startup Type |Path |
| - | - | - | - |
|F-Secure Hoster |F-Secure DLL Hoster Service |Automatic |\Anti-Virus\fshoster3 2.exe |
|F-Secure Hoster Restricted |F-Secure DLL Hoster Service |Automatic |\Anti-Virus\fshoster3 2.exe --service --namespace default --id 2 |
|F-Secure UltraLight Hoster |F-Secure UltraLight Hoster |Automatic |\Ultralight\ulcore\16 07432682\fshoster64 .exe  --service --namespace ul\_default |
|F-Secure UltraLight Network Hoster |- |Automatic |\Ultralight\ulcore\16 07432682\fshoster64 .exe  --service --namespace ul\_default --id 2 |
|F-Secure UltraLight ORSP Client |F-Secure UltraLight ORSP Client |Automatic |\Ultralight\ulcore\16 07432682\fsorsp64.e xe |
|F-Secure UltraLight Protected Hoster |- |Automatic |\Ultralight\ulcore\16 07432682\fsulprotho ster.exe" --service --namespace ul\_default --id 5 |

` `PAGE9 Antivirus Artifacts III 


Norton



|Parent Directory |
| - |
|C:\Program Files\Norton Internet Security\ |
Binaries present: 



|Name |Description |Sub directory |
| - | - | - |
|NortonSecurity.exe |NortonSecurity |Engine\%ld |
|nsWscSvc.exe |NortonSecurity WSC Service |Engine\%ld |
|SYMEFASI64.sys |Symantec Extended File Attributes |C:\Windows\System32\Drivers\NGCx64\%ld|
|SymEvnt.sys |Symantec Eventing Platform |NortonData\%ld\SymPlatform |
|SYMEVENT64x86.sys |Symantec Event Library |C:\Windows\System32\Drivers\|
|SRTSPX64.sys |Symantec Auto Protect|C:\Windows\System32\Drivers\NGCx64\%ld |
|SRTSP.sys |Symantec Auto Protect  |C:\Windows\System32\Drivers\NGCx64\%ld|
In-memory modules present: 



|Name |Description |Sub Directory |
| - | - | - |
|symamsi.dll |Symantec AMSI Provider |Engine\%ld |
|ccVrTrst.dll |Symantec Trust Validation Engine 64bit |Engine\%ld |
|ccSet.dll |Symantec Settings Manager Engine |Engine\%ld |
|ccLib.dll |Symantec Library |Engine\%ld |
|EFACli64.dll |Symantec Extended File Attributes |Engine\%ld |
|ccIPC.dll |Symantec ccIPC Engine |Engine\%ld |
|IPSEng32.dll |IPS Script Engine DLL |ProgramFile\NortonSecurity\NortonData\..\ |

` `PAGE10 Antivirus Artifacts III 

Functions Hooked 

KERNELBASE.DLL 



|[VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) |[CreateFileMappingW](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw) |[CreateFileMappingNumaW](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingnumaw) |
| - | - | - |
|[CreateFileW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) |[MapViewOfFile](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile) |[VirtualProtect](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) |
|[HeapCreate](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate) |[VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) |[MapViewOfFileEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffileex) |
|[CreateRemoteThreadEx](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethreadex) |[WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) |[VirtualProtectEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex) |
NTDLL.DLL 



|[RtlAddVectoredExceptionHandler](https://doxygen.reactos.org/d5/d55/vectoreh_8c.html#a31284daff42389226b0400bc89de0665) |[RtlRemoveVectoredExceptionHandler](https://doxygen.reactos.org/d5/d55/vectoreh_8c.html#ab690783c5f2a38c550740815ac236922) |[LdrLoadDll](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FExecutable%20Images%2FLdrLoadDll.html) |
| - | - | - |
||||
|[RtlCreateHeap](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateheap) |[NtSetInformationProcess](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FProcess%2FNtSetInformationProcess.html) |[NtMapViewOfSection](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html) |
|[NtWriteVirtualMemory](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html) |[NtCreateSection](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection) |[NtProtectVirtualMemory](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtProtectVirtualMemory.html) |
|[NtCreateFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile) |[NtCreateProcess](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/NtCreateProcess.html) |[NtCreateThreadEx](https://github.com/3gstudent/Inject-dll-by-APC/blob/master/NtCreateThreadEx.cpp) |
|[NtCreateUserProcess](http://www.rohitab.com/discuss/topic/40191-ntcreateuserprocess/) |[KiUserExceptionDispatcher](https://reverseengineering.stackexchange.com/questions/8809/kiuserexceptiondispatcher-hook) |N/A |
KERNEL32.DLL 



|[CreateFileMappingA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga) |[SetProcessDEPPolicy](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setprocessdeppolicy) |[VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) |
| - | - | - |
|[MapViewOfFile](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile) |[CreateFileMappingW](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw) |[VirtualProtect](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) |
|[HeapCreate](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate) |[MapViewOfFileEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffileex) |[CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) |
|[VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) |[VirtualProtectEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex) |[WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) |
|[WinExec](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec) |N/A |N/A |
[continued below] 

Minifilters Present: 



|Driver |Altitude |Type |
| - | - | - |
|symefasi.sys|[260610](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#260000---269998-fsfilter-content-screener)|FSFilter Content Screener |
|SRTSP.sys|[329000](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus)|FSFilter Anti-Virus |
|symevnt.sys |[365090](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#360000---389999-fsfilter-activity-monitor) |FSFilter Activity Monitor |
|bhdrvx64.sys |[365100](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#360000---389999-fsfilter-activity-monitor) |FSFilter Activity Monitor |
|symevnt.sys |[365090](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#360000---389999-fsfilter-activity-monitor) |FSFilter Activity Monitor |


|Antivirus Driver |Request |
| - | - |
|eeCtrl64.sys |[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|eeCtrl64.sys |[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-cleanup) |
|eeCtrl64.sys |[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|BHDrvx64.sys |[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|BHDrvx64.sys |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|BHDrvx64.sys |[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-cleanup) |
|BHDrvx64.sys |[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|BHDrvx64.sys |[IRP_MJ_SET_SECURITY](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-security) |
|BHDrvx64.sys |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
|BHDrvx64.sys |[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control) |
|BHDrvx64.sys |[IRP_MJ_DIRECTORY_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-directory-control) |
|SymEvnt.sys |[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|SymEvnt.sys |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|SymEvnt.sys |[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|SymEvnt.sys |[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control) |
|SymEvnt.sys |[IRP_MJ_SHUTDOWN](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-shutdown) |
|SymEvnt.sys |[IRP_MJ_LOCK_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-lock-control) |


|Antivirus Driver |Request |
| - | - |
|SRTSP64.SYS |[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|SRTSP64.SYS |[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-cleanup) |
|SRTSP64.SYS |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|SRTSP64.SYS |[IRP_MJ_VOLUME_MOUNT](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-volume-mount) |
|SRTSP64.SYS |[IRP_MJ_PNP](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-pnp) |
|SRTSP64.SYS |[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|SRTSP64.SYS |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
|SRTSP64.SYS |[IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-release-for-section-synchronization) |
|SRTSP64.SYS |[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control) |
|SRTSP64.SYS |[IRP_MJ_SHUTDOWN](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-shutdown) |
|SRTSP64.SYS |[IRP_MJ_DEVICE_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control) |
|SYMEFASI64.SYS |[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|SYMEFASI64.SYS |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
|SYMEFASI64.SYS |[IRP_MJ_SHUTDOWN](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-shutdown) |
|SYMEFASI64.SYS |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|SYMEFASI64.SYS |[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-cleanup) |
|SYMEFASI64.SYS |[IRP_MJ_CLOSE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-close) |
|SYMEFASI64.SYS |[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control) |
|SYMEFASI64.SYS |[IRP_MJ_DEVICE_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control) |
|SYMEFASI64.SYS |[IRP_MJ_PNP](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-pnp) |
|SYMEFASI64.SYS |[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
Web Traffic: 



|Protocol |Remote Address |Local Port |Remote Port |
| - | - | - | - |
|TCP |52.234.240.1 |59882 |443 |

` `PAGE13 Antivirus Artifacts III 
Services: 


|Name |Description |Startup Type |Path |
| - | - | - | - |
|Norton Security |Norton Security |Automatic |\Engine\%ld\NortonSecurity.exe |
|Norton WSC Service |Norton WSC Service |Automatic |\Engine\%ld\nsWscSvc.exe |

` `PAGE14 Antivirus Artifacts III 


Trend Micro 



|Parent Directory |
| - |
|C:\Program Files\TrendMicro |
Binaries present: 



|Name |Description |Sub directory |
| - | - | - |
|coreFrameworkHost.exe |Trend Micro Anti-Malware Solution |AMSP |
|uiWatchDog.exe |Trend Micro Client Session Agent Monitor  |UniClient |
|uiSeAgnt.exe |Client Session Agent  |UniClient|
|uiWinMgr.exe |Trend Micro Client Main Console |Titanium |
|Tmsalntance64.exe |Trend Micro Browser Exploit Detection Engine |AMSP|
|AMSPTelemetryService.exe |Trend Micro Anti-Malware Solution|AMSP|
|tmeyes.sys |TrendMicro Eyes driver Module |C:\Windows\System32\Drivers\|
|TMUMH.sys |Trend Micro UMH Driver x64 |C:\Windows\System32\Drivers\ |
|tmusa.sys |Trend Micro Osprey Scanner Driver |C:\Windows\System32\Drivers\ |
|tmnciesc.sys |Trend Micro NCIE Scanner |C:\Windows\System32\Drivers\ |
|TMEBC64.sys |Trend Micro early boot driver |C:\Windows\System32\Drivers\ |
|tmeevw.sys |Trend Micro EagleEye Driver (VW) |C:\Windows\System32\Drivers\ |
In-memory modules present: 



|Name |Description |Sub Directory |
| - | - | - |
|TmUmEvt64.dll |Trend Micro User-Mode Hook Event Module |\System32\tmumh\20019\AddOn\8.55.0.1018 |
|tmmon64.dll |Trend Micro UMH Monitor Engine |\System32\tmumh\20019 |
|TmAMSIProvider64.dll |Trend Micro AMSI Provider Module  |\System32\TmAMSI |
|TmOverlayIcon.dll |Trend Micro Folder Shield Shell Extension |Titanium |

` `PAGE16 Antivirus Artifacts III 

Functions Hooked 

KERNELBASE.DLL 



|[CreateFileA](https://docs.microsoft.com/en-us/windows/win32/fileio/opening-a-file-for-reading-or-writing) |[CreateFileW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) |[LoadLibraryExW](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw) |
| - | - | - |
|[CreateFileMappingW](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-createfilemappingw) |[LoadLibraryExA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexa) |[CreateRemoteThreadEx](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethreadex) |
|[VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) |[MapViewOfFile](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile) |[VirtualProtect](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) |
|[HeapCreate](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate) |[WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) |[VirtualProtectEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex) |
|[LoadLibraryA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) |[LoadLibraryW](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw) |N/A |
KERNEL32.DLL 



|[CreateFileMappingA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga) |N/A |N/A |
| - | - | - |
NTDLL.DLL 



|[RtlCreateHeap](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcreateheap) |[LdrUnloadDll](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Executable%20Images/LdrUnloadDll.html) |[LdrUnloadDll](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Executable%20Images/LdrUnloadDll.html) |
| - | - | - |
|[NtMapViewOfSection](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html) |[NtUnmapViewOfSection](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Section/NtUnmapViewOfSection.html) |[NtContinue](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtContinue.html) |
|[NtCreateSection](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatesection) |[NtProtectVirtualMemory](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtProtectVirtualMemory.html) |[NtCreateFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile) |
|[NtSetContextThread](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/Thread%20Context/NtSetContextThread.html) |N/A |N/A |
Minifilters Present: 



|Driver |Altitude |Type |
| - | - | - |
|tmeyes.sys|[328520](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus)|FSFilter Anti-Virus |


|Antivirus Driver |Request |
| - | - |
|tmeyes.sys|[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|tmeyes.sys|[IRP_MJ_READ](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-read) |
|tmeyes.sys|[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|tmeyes.sys|[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-cleanup) |
|tmeyes.sys|[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|tmeyes.sys|[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control) |
|tmeyes.sys|[IRP_MJ_VOLUME_MOUNT](https://community.osr.com/discussion/139007/irp-mj-volume-mount-vs-irp-mj-file-system-control) |
|tmeyes.sys |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
|tmeyes.sys |[IRP_MJ_SET_SECURITY](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-security) |
Web Traffic: 



|Protocol |Remote Address |Local Port |Remote Port |
| - | - | - | - |
|TCP |104.108.237.54 |58495 |443 |
|TCP |23.35.33.60 |58672 |443 |
Services: 



|Name |Description |Startup Type |Path |
| - | - | - | - |
|Amsp |Trend Micro Solution Platform |Automatic |AMSP\coreServiceSh ell.exe |
|AMSPTLM |Trend Micro Activity Data Service |Automatic |AMSP\AMSPTelemet ryService.exe |
WebRoot 



|Parent Directory |
| - |
|C:\Program Files\WebRoot |
Binaries present: 



|Name |Description |Sub directory |
| - | - | - |
|WRSA.exe |WebRoot Secure Anywhere |WRSA.exe |
|WRSkyClient.x64.exe |WebRoot Secure Anywhere  |Core |
|WRCoreService.x64.ex e |WebRoot Secure Anywhere Core Service  |Core|
|WRCore.x64.sys |WebRoot Secure Anywhere |Core |
|WRkrn.sys |WebRoot Secure Anywhere |Core|
In-memory modules present: 



|Name |Description |Sub Directory |
| - | - | - |
|WRusr.dll |WebRoot Secure Anywhere |C:\Windows\System32\|
|WRusr.dll |Webroot SecureAnywhere |C:\Windows\SysWOW64\ |
Functions Hooked: 

ADVAPI32.DLL 



|[OpenSCManagerW](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagerw) |[OpenServiceW](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openservicew) |[OpenSCManagerA](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagera) |
| - | - | - |
|[StartServiceW](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicew) |[ControlService](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-controlservice) |[CreateServiceA](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea) |
|[CreateServiceW](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew) |[DeleteService](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice) |[OpenServiceA](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openservicea) |
|[StartServiceA](https://docs.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicea) |[WmiExecuteMethodW](https://docs.microsoft.com/en-us/windows/win32/wmisdk/calling-a-method) |N/A |
USER32.DLL 



|[PostThreadMessageA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postthreadmessagea) |[PostMessageA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postmessagea) |[SendMessageA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagea) |
| - | - | - |
|[SendMessageTimeoutA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagetimeouta) |[SetWindowTextA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowtexta) |[CreateWindowExA](https://social.msdn.microsoft.com/Forums/en-US/3894ec7e-a00e-4735-9ee1-5cd07800ec1c/createwindowexa-to-many-functions?forum=Vsexpressvc) |
|[SetWindowsHookExA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa) |[DrawTextExW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-drawtextexw) |[CreateWindowExW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-createwindowexw) |
|[PostMessageW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postmessagew) |[SendMessageW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagew) |[SetWindowTextW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowtextw) |
|[PostThreadMessageW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postthreadmessagea) |[SendMessageTimeoutW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagetimeouta) |[SetWindowsHookExW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexw) |
|[SetWinEventHook](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwineventhook) |[SendMessageCallbackW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagecallbackw) |[SendNotifyMessageW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendnotifymessagea) |
|[ExitWindowsEx](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-exitwindowsex) |[MessageBoxTimeoutW](https://www.codeproject.com/Articles/7914/MessageBoxTimeout-API) |[SendMessageCallbackA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagecallbacka) |
KERNELBASE.DLL 



|[OutputDebugStringA](https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-outputdebugstringa) |[CreateProcessInternalW](https://doxygen.reactos.org/d9/dd7/dll_2win32_2kernel32_2client_2proc_8c.html#a13a0f94b43874ed5a678909bc39cc1ab) |N/A |
| - | - | - |
NTDLL.DLL 



|[NtWaitForSingleObject](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Type%20independed/NtWaitForSingleObject.html) |[NtDeviceIoControlFile](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntdeviceiocontrolfile) |[NtRequestWaitReplyPort](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Port/NtRequestWaitReplyPort.html) |
| - | - | - |
|[NtOpenProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess) |[NtMapViewOfSection](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html) |[NtTerminateProcess](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/NtTerminateProcess.html) |
|[NtDelayExecution](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtDelayExecution.html) |[NtWriteVirtualMemory](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html) |[NtOpenEvent](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Event/NtOpenEvent.html) |
|[NtAdjustPrivilegesToken](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Token/NtAdjustPrivilegesToken.html) |[NtQueueApcThread](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/APC/NtQueueApcThread.html) |[NtCreateEvent](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FEvent%2FNtCreateEvent.html) |
|[NtCreateSection](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html) |[NtCreateThread](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FNtCreateThread.html) |[NtProtectVirtualMemory](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtProtectVirtualMemory.html) |
|[NtTerminateThread](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtTerminateThread.html) |[NtWaitForMultipleObjects](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Type%20independed/NtWaitForMultipleObjects.html) |[NtSetValueKey](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Key/NtSetValueKey.html) |
|[NtAlpcConnectPort](https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html#ab360726aaf812f006b4aadee17d50f54) |[NtAlpcCreatePort](https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html#a2b0507db70f5c7c5cbde4b990e604e43) |[NtAlpcCreatePortSection](https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html#ae7b6c19e13a9edfa08bab40303e39af9) |
|[NtAlpcCreateSectionView](https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html#a434a398e14cc011a19c792dcd964bef9) |[NtAlpcSendWaitReceivePort](https://github.com/avalon1610/ALPC/blob/master/ALPC/ALPC.c) |[NtAssignProcessToJobObject](https://doxygen.reactos.org/d0/dbc/ntoskrnl_2ps_2job_8c.html#ae4efb8a058e6ef13772a7d7d670ed57d) |
|[NtConnectPort](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Port/NtConnectPort.html) |[NtCreateMutant](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Mutant/NtCreateMutant.html) |[NtCreatePort](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Port/NtCreatePort.html) |
|[NtCreateSemaphore](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Semaphore/NtCreateSemaphore.html) |[NtCreateThreadEx](https://github.com/3gstudent/Inject-dll-by-APC/blob/master/NtCreateThreadEx.cpp) |[NtDeleteKey](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwdeletekey) |
|[NtDeleteValueKey](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwdeletevaluekey) |[NtMakeTemporaryObject](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FType%20independed%2FNtMakeTemporaryObject.html) |[NtOpenMutant](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FMutant%2FNtOpenMutant.html) |
|[NtOpenSemaphore](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Semaphore/NtOpenSemaphore.html) |[NtOpenThread](https://docs.microsoft.com/en-us/windows/win32/devnotes/ntopenthread) |NtQueueApcThreadEx |
|[NtRequestPort](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Port/NtRequestPort.html) |[NtSecureConnectPort](http://www.codewarrior.cn/ntdoc/wrk/lpc/NtSecureConnectPort.htm) |[NtSetContextThread](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/Thread%20Context/NtSetContextThread.html) |
|[NtShutdownSystem](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Hardware/NtShutdownSystem.html) |[NtSystemDebugControl](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Debug/NtSystemDebugControl.html) |[CsrClientCallServer](https://www.geoffchappell.com/studies/windows/win32/ntdll/api/csrutil/clientcallserver.htm) |
URLMON.DLL 



|[URLDownloadToFileW](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123\(v=vs.85\)) |[URLDownloadToFileA](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123\(v=vs.85\)) |N/A |
| - | - | - |
WININET.DLL 



|[InternetOpenA](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopena) |[InternetCloseHandle](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetclosehandle) |[InternetOpenUrlA](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurla) |
| - | - | - |
GDI32.DLL 



|[BitBlt](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-bitblt) |[TextOutW](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-textoutw) |N/A |
| - | - | - |
KERNEL32.DLL 



|[GetTickCount](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount) |N/A |N/A |
| - | - | - |
RPCRT4.DLL 



|RpcSend |RpcSendReceive |NdrSendReceive |
| - | - | - |
Minifilters Present: 



|Driver |Altitude |Type |
| - | - | - |
|WRCore.x64.sys|[320110](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus)|FSFilter Anti-Virus |
|WRKrn.sys |[320111](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus) |FSFilter Anti-Virus |


|Antivirus Driver |Request |
| - | - |
|WRCore.x64.sys |[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|WRCore.x64.sys|[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|WRkrn.sys|[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|WRkrn.sys|[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-cleanup) |
|WRkrn.sys|[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|WRkrn.sys|[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |

` `PAGE22 Antivirus Artifacts III 
Services: 


|Name |Description |Startup Type |Path |
| - | - | - | - |
|WRSVC |WRSVC |Automatic |Webroot\WRSA.exe |
|WRSkyClient |WRSkyClient |Automatic |Webroot\Core\WRSk yClient.exe |
|WRCoreService |WRCoreService |Automatic |Webroot\Core\WRC oreService.exe |

` `PAGE23 Antivirus Artifacts III 


BitDefender 



|Parent Directory |
| - |
|C:\Program Files\Bitdefender Antivirus Free\ |
Binaries present: 



|Name |Description |Path |
| - | - | - |
|atc.sys |BitDefender Active Threat Controller |C:\Windows\System32\Drivers\|
|gemma.sys |BitDefender Generic Exploit Mitigation |C:\Windows\System32\Drivers\ |
|fvevol.sys |BitDefender Drive Encryption Driver |C:\Windows\System32\Drivers\ |
|bdredline.exe |BitDefender redline update |\ |
|vsserv.exe |BitDefender Security Service |\ |
|vsservppl.exe |BitDefender Correlation Service |\ |
|updatesrv.exe |BitDefender Update Service |\ |
|bdagent.exe |BitDefender bdagent.exe |\ |
In-memory modules present: 



|Name |Description |Path |
| - | - | - |
|bdhkm64.dll |BitDefender Hooking DLL |bdkdm\%ld\ |
|atcuf64.dll |BitDefender Active Threat Controller |atcuf\%ld\ |

` `PAGE24 Antivirus Artifacts III 

Functions Hooked: 

KERNELBASE.DLL 



|[DefineDosDeviceW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-definedosdevicew) |[CreateProcessW](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) |[CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) |
| - | - | - |
|[CreateProcessInternalA](https://doxygen.reactos.org/d9/dd7/dll_2win32_2kernel32_2client_2proc_8c_source.html#l04626) |[CreateProcessInternalW](https://doxygen.reactos.org/d9/dd7/dll_2win32_2kernel32_2client_2proc_8c.html#a13a0f94b43874ed5a678909bc39cc1ab) |[PeekConsoleInputW](https://docs.microsoft.com/en-us/windows/console/peekconsoleinput) |
|[CloseHandle](https://docs.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle) |[DeleteFileW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilew) |[OpenThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread) |
|[CreateRemoteThreadEx](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethreadex) |[GetProcAddress](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) |[MoveFileWithProgressW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefilewithprogressw) |
|[MoveFileExW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw) |[GetModuleBaseNameW](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulebasenamew) |[GetModuleInformation](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmoduleinformation) |
|[GetModuleFileNameExW](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulefilenameexw) |[EnumProcessModules](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules) |[SetEnvironmentVariableW](https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-setenvironmentvariablew) |
|[EnumDeviceDrivers](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumdevicedrivers) |[SetEnvironmentVariableA](https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-setenvironmentvariablea) |[QueueUserAPC](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc) |
|[GetLogicalProcessorInformationEx](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlogicalprocessorinformationex) |[LoadLibraryA](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya) |[LoadLibraryW](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw) |
|[GetLogicalProcessorInformation](https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlogicalprocessorinformation) |[GetApplicationRecoveryCallback](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-registerapplicationrecoverycallback) |[EnumProcessModulesEx](https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodulesex) |
|[PeekConsoleInputA](https://docs.microsoft.com/en-us/windows/console/peekconsoleinput) |[ReadConsoleInputA](https://docs.microsoft.com/en-us/windows/console/readconsoleinput)|[ReadConsoleInputW](https://docs.microsoft.com/en-us/windows/console/readconsoleinput) |
|[GenerateConsoleCtrlEvent](https://docs.microsoft.com/en-us/windows/console/generateconsolectrlevent) |[ReadConsoleA](https://docs.microsoft.com/en-us/windows/console/readconsole) |[ReadConsoleW](https://docs.microsoft.com/en-us/windows/console/readconsole) |
|[CreateRemoteThread](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread) |N/A |N/A |
COMBASE.DLL 



|[CoCreateInstance](https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cocreateinstance) |[CoGetClassObject](https://docs.microsoft.com/en-us/windows/win32/api/combaseapi/nf-combaseapi-cogetclassobject) |N/A |
| - | - | - |
KERNEl32.DLL 



|[Process32NextW](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32nextw) |[CreateToolhelp32Snapshot](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot) |[MoveFileExA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexa) |
| - | - | - |
|[MoveFileWithProgressA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefilewithprogressa) |[DefineDosDeviceA](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-definedosdevicew) |N/A |
GDI32.DLL 



|[CreateDCW](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-createdcw) |[BitBlt](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-bitblt) |[CreateCompatibleDC](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-createcompatibledc) |
| - | - | - |
|[CreateBitmap](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-createbitmap) |[CreateDCA](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-createdca) |[CreateCompatibleBitmap](https://docs.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-createcompatiblebitmap) |
USER32.DLL 



|[SetWindowsHookExW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexw) |[CallNextHookEx](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-callnexthookex) |[FindWindowExA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowexa) |
| - | - | - |
|[SendMessageA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagea) |[PeekMessageA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-peekmessagea) |[PeekMessageW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-peekmessagew) |
|[GetDesktopWindow](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdesktopwindow) |[SendMessageW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendmessagew) |[SetWindowLongW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowlongw) |
|[GetKeyState](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getkeystate) |[PostMessageW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postmessagew) |[EnumDesktopWindows](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumdesktopwindows) |
|[EnumWindows](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumwindows) |[GetMessageW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagew) |[SystemParametersInfoW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow) |
|[FindWindowW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowa) |[GetAsyncKeyState](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getasynckeystate) |[SetPropW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setpropw) |
|[FindWindowExW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowexw) |[GetDC](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdc) |[GetMessageA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagea) |
|[SystemParametersInfoA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfoa) |[SendNotifyMessageW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendnotifymessagea) |[SetWinEventHook](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwineventhook) |
|[PostMessageA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postmessagea) |[UnhookWindowsHookEx](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unhookwindowshookex) |[GetClipboardData](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getclipboarddata) |
|[SetWindowLongA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowlonga) |[SetClipboardData](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setclipboarddata) |[SendNotifyMessageA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendnotifymessagea) |
|[GetDCEx](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getdcex) |[GetKeyboardState](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getkeyboardstate) |[GetRawInputData](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getrawinputdata) |
|[GetWindowDC](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowdc) |[RegisterRawInputDevices](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-registerrawinputdevices) |[SetWindowsHookExA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa) |
|[FindWindowA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-findwindowa) |[SetPropA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setpropa) |N/A |
NTDLL.DLL 



|[RtlImageNtHeaderEx](https://doxygen.reactos.org/d7/de4/boot_2environ_2lib_2rtl_2libsupp_8c.html#a281660cbec703b18ab0f91f1cfc9c5fa) |[NtSetInformationThread](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationthread) |[NtClose](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntclose) |
| - | - | - |
|[NtOpenProcess](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ntopenprocess) |[NtMapViewOfSection](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html) |[NtUnmapViewOfSection](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Section/NtUnmapViewOfSection.html) |
|[NtTerminateProcess](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/NtTerminateProcess.html) |[NtWriteVirtualMemory](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html) |[NtDuplicateObject](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Type%20independed/NtDuplicateObject.html) |
|[NtReadVirtualMemory](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtReadVirtualMemory.html) |[NtAdjustPrivilegesToken](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Token/NtAdjustPrivilegesToken.html) |[NtQueueApcThread](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/APC/NtQueueApcThread.html) |
|[NtCreateProcessEx](http://www.rohitab.com/discuss/topic/42229-start-a-process-using-ntcreateprocessex-usermode/) |[NtCreateThread](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FNtCreateThread.html) |[NtResumeThread](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtResumeThread.html) |
|[NtAlpcConnectPort](https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html#ab360726aaf812f006b4aadee17d50f54) |[NtAlpcCreatePort](https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html#a2b0507db70f5c7c5cbde4b990e604e43) |[NtAlpcSendWaitReceivePort](https://processhacker.sourceforge.io/doc/ntlpcapi_8h.html#a139ba6b1a2410cacb224c91826c19246) |
|[NtCreateProcess](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/NtCreateProcess.html) |[NtCreateThreadEx](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FThread%2FNtCreateThread.html) |[NtCreateUserProcess](http://www.rohitab.com/discuss/topic/40191-ntcreateuserprocess/) |
|[NtQuerySystemEnvironmentValueEx](https://doxygen.reactos.org/d1/d26/ndk_2exfuncs_8h.html#a976cf61d4e9bfbf03ede5c796df40980) |[NtRaiseHardError](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FError%2FNtRaiseHardError.html) |[NtSetContextThread](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/Thread%20Context/NtSetContextThread.html) |
||
|[NtSetSystemEnvironmentValueEx](https://doxygen.reactos.org/db/d40/ntoskrnl_2ex_2sysinfo_8c.html#a19490952367dc7d35da24897fa8cbff8) |[RtlWow64SetThreadContext](https://processhacker.sourceforge.io/doc/ntrtl_8h_source.html) |[RtlReportException](https://processhacker.sourceforge.io/doc/ntrtl_8h.html#aaa4e0c8c566d33fdde74125d5c314b25) |
Minifilters Present: 



|Driver |Altitude |Type |
| - | - | - |
|vlflt.sys|[320832](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus)|FSFilter Anti-Virus |
|gemma.sys |[320782](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus) |FSFilter Anti-Virus |
|Atc.sys |[320781](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus) |FSFilter Anti-Virus |
|TRUFOS.SYS |[320770](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus) |FSFilter Anti-Virus |


|Antivirus Driver |Request |
| - | - |
|vlflt.sys|[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|vlflt.sys |[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-cleanup) |
|vlflt.sys |[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|vlflt.sys |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|vlflt.sys |[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control) |
|vlflt.sys |[IRP_MJ_VOLUME_MOUNT](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-volume-mount) |
|vlflt.sys |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
|vlflt.sys |[IRP_MJ_DIRECTORY_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-directory-control) |
|gemma.sys|[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|gemma.sys |[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-cleanup) |
|gemma.sys |[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|gemma.sys |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|gemma.sys |[IRP_MJ_READ](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-read) |
|gemma.sys |[IRP_MJ_QUERY_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-query-information) |


|Antivirus Driver |Request |
| - | - |
|atc.sys |[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|atc.sys |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|atc.sys |[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-cleanup) |
|atc.sys |[IRP_MJ_READ](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-read) |
|atc.sys |[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|atc.sys |[IRP_MJ_QUERY_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-query-information) |
|atc.sys |[IRP_MJ_DIRECTORY_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-directory-control) |
|atc.sys |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
|atc.sys |[IRP_MJ_QUERY_EA](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-query-ea) |
|atc.sys |[IRP_MJ_SET_EA](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-ea) |
|atc.sys |[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control) |
|atc.sys |[IRP_MJ_CREATE_NAMED_PIPE](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-create-named-pipe) |
|atc.sys |[IRP_MJ_PNP](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-pnp) |
|TRUFOS.SYS |[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|TRUFOS.SYS |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
Services: 



|Name |Description |Startup Type |Path |
| - | - | - | - |
|ProductAgentService |Bitdefender Product Agent Service |Automatic |ProductAgentService.exe |
|vsserv |Bitdefender Security Service |Automatic |vsserv.exe|
|vsservppl |Bitdefender Correlation Service |Automatic |vsservppl.exe |
|updatesrv |Bitdefender Update Service |Automatic |updatesrv.exe |
MalwareBytes 



|Parent Directory |
| - |
|C:\Program Files\MalwareBytes\ |
Binaries present: 



|Name |Description |Sub directory |
| - | - | - |
|mwac.sys |Malwarebytes Web Protection |C:\Windows\System32\Drivers\|
|mbamswissarmy.sys |Malwarebytes SwissArmy |C:\Windows\System32\Drivers\|
|mbam.sys |Malwarebytes Real-Time Protection |C:\Windows\System32\Drivers\|
|MbamChameleon.sys |Malwarebytes Chameleon |C:\Windows\System32\Drivers\|
|farflt.sys |Malwarebytes Anti-Ransomware Protection |C:\Windows\System32\Drivers\|
|mbae64.sys |Malwarebytes Anti-Exploit |C:\Windows\System32\Drivers\|
|MBAMService.exe |Malwarebytes Service |Anti-Malware|
|mbamtray.exe |Malwarebytes Tray Application |Anti-Malware|
|mbam.exe |Malwarebytes |Anti-Malware|
In-memory modules present: 



|Name |Description |Sub Directory |
| - | - | - |
|mbae.dll |MalwareBytes Anti-exploit |AntiMalware |
Functions Hooked: 

MSCVRT.DLL 



|[_wsystem](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/system-wsystem?view=msvc-160) |[system](https://docs.microsoft.com/en-us/cpp/c-runtime-library/reference/system-wsystem?view=msvc-160) |N/A |
| - | - | - |
WSA\_32.DLL 



|[WSAStartup](https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsastartup) |N/A |N/A |
| - | - | - |
SHELL32.DLL 



|[ShellExecuteW](https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecutew) |[ShellExecuteExW](https://docs.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-shellexecuteexw) |N/A |
| - | - | - |
NTDLL.DLL 



|[ResolveDelayLoadedAPI](https://docs.microsoft.com/en-us/windows/win32/devnotes/resolvedelayloadedapi) |GetDllHandle |[CreateProcessInternalW](https://doxygen.reactos.org/d9/dd7/dll_2win32_2kernel32_2client_2proc_8c.html#a13a0f94b43874ed5a678909bc39cc1ab) |
| - | - | - |
|[NtAllocateVirtualMemory](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory) |[NtProtectVirtualMemory](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtProtectVirtualMemory.html) |N/A |
KERNELBASE.DLL 



|[VirtualAllocEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex) |[CreateProcessW](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw) |CreateProcessInternalW |
| - | - | - |
|[GetModuleHandleW](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew) |[CreateFileW](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) |[LoadLibraryExW](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw) |
|[VirtualProtect](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) |[HeapCreate](https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate) |[VirtualAlloc](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) |
|[WriteProcessMemory](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory) |[CreateFileA](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) |[VirtualProtectEx](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex) |
|[CreateProcessA](https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) |[CreateProcessInternalA](https://doxygen.reactos.org/d9/dd7/dll_2win32_2kernel32_2client_2proc_8c.html#a0c3b312e8afb80d76805a196def1a374) |N/A |
URLMON.DLL 



|[URLDownloadToFileW](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123\(v=vs.85\)) |[URLDownloadToCacheFileA](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775122\(v=vs.85\)) |[URLDownloadToCacheFileW](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775122\(v=vs.85\)) |
| - | - | - |
|[URLDownloadToFileA](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123\(v=vs.85\)) |[URLOpenBlockingStreamA](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775127\(v=vs.85\)) |[URLOpenBlockingStreamW](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775127\(v=vs.85\)) |
|[URLOpenStreamA](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775129\(v=vs.85\)) |[URLOpenStreamW](https://docs.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775129\(v=vs.85\)) |N/A |
WININET.DLL 



|[InternetReadFile](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile) |[InternetReadFileExW](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfileexw) |[HttpOpenRequestW](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpopenrequestw) |
| - | - | - |
|[HttpSendRequestW](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpsendrequestw) |[HttpSendRequestExW](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpsendrequestexw) |[HttpSendRequestA](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpsendrequesta) |
|[HttpSendRequestExA](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpsendrequestexa) |[InternetOpenUrlA](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurla) |[InternetOpenUrlW](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurlw) |
|[HttpOpenRequestA](https://docs.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpopenrequesta) |N/A |N/A |
KERNEL32.DLL 



|[SetProcessDEPPolicy](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setprocessdeppolicy) |[CopyFileA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfilea) |[MoveFileA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefilea) |
| - | - | - |
|[MoveFileW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefilew) |[CopyFileW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-copyfilew) |[WinExec](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec) |
Minifilters Present: 



|Driver |Altitude |Type |
| - | - | - |
|mbam.sys|[328800](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus)|FSFilter Anti-Virus |
|mbamwatchdog.sys|[400900](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#400000---409999-fsfilter-top)|FSFilter Top |
|farwflt.sys|[268150](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#260000---269998-fsfilter-content-screener)|FSFilter Activity Monitor |


|Antivirus Driver |Request |
| - | - |
|mbamwatchdog.sys|[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|mbamwatchdog.sys|[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|mbamwatchdog.sys|[IRP_MJ_SET_SECURITY](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-security) |
|mbam.sys|[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|mbam.sys|[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
Web Traffic: 



|Protocol |Remote Address |Local Port |Remote Port |
| - | - | - | - |
|TCP |13.226.202.2 |50364 |443 |
Adaware 



|Parent Directory |
| - |
|C:\Program Files(x86)\adaware\adaware antivirus |
Binaries present: 



|Name |Description |Sub directory |
| - | - | - |
|AdawareDesktop.exe |Adaware Desktop |\adaware antivirus\12.10.111.0 |
|AdawareTray.exe |Adaware Tray |\adaware antivirus\12.10.111.0 |
|AdawareService.exe |Adaware service |\adaware antivirus\12.10.111.0 |
|atc.sys |BitDefender Active Threat Control Filesystem Minifilter |C:\Windows\System32\Drivers\|
|gzflt.sys |Bit Defender Gonzales Filesystem Driver |C:\Windows\System32\Drivers\|
In-memory modules present: 



|Name |Description |Path |
| - | - | - |
|N/A |N/A |N/A |
Functions Hooked: 



|N/A |N/A |N/A |
| - | - | - |
Minifilters Present: 



|Driver |Altitude |Type |
| - | - | - |
|gzflt.sys|[320820](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus)|FSFilter Anti-Virus |
|Atc.sys |[320781](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus) |FSFilter Anti-Virus |
|TRUFOS.SYS |[320770](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus) |FSFilter Anti-Virus |


|Antivirus Driver |Request |
| - | - |
|TRUFOS.SYS|[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|TRUFOS.SYS|[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
|gzflt.sys|[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|gzflt.sys|[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-cleanup) |
|gzflt.sys|[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|gzflt.sys |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|gzflt.sys |[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control) |
|gzflt.sys |[IRP_MJ_VOLUME_MOUNT](https://community.osr.com/discussion/139007/irp-mj-volume-mount-vs-irp-mj-file-system-control) |
|gzflt.sys |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
|atc.sys |[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|atc.sys |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|atc.sys |[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-cleanup) |
|atc.sys |[IRP_MJ_READ](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-read) |
|atc.sys |[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|atc.sys |[IRP_MJ_QUERY_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-query-information) |
|atc.sys |[IRP_MJ_DIRECTORY_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-directory-control) |
|atc.sys |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
|atc.sys |[IRP_MJ_QUERY_EA](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-query-ea) |
|atc.sys |[IRP_MJ_SET_EA](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-ea) |
|atc.sys |[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control) |
Services: 



|Name |Description |Startup Type |Path |
| - | - | - | - |
|Adaware antivirus service |Helps protect users from Malware & other potentially unwanted software |Automatic |adaware antivirus\%ld\AdAwareServ ice.exe |
Avast 



|Parent Directory |
| - |
|C:\Program Files\AvastSoftware\Avast |
Binaries present: 



|Name |Description |Sub directory |
| - | - | - |
|aswArPot.sys |Avast Anti Rootkit |C:\Windows\System32\Drivers\|
|aswbidsdriver.sys |Avast IDS Application Activity Monitor Driver. |C:\Windows\System32\Drivers\|
|aswbidsh.sys |Avast Application Activity Monitor Helper Driver |C:\Windows\System32\Drivers\|
|aswbuniv.sys |Avast Universal Driver |C:\Windows\System32\Drivers\|
|aswKbd.sys |Avast Keyboard Filter Driver |C:\Windows\System32\Drivers\|
|aswMonFlt.sys |Avast File System Filter |C:\Windows\System32\Drivers\ |
|aswNetHub.sys |Avast Network Security Driver |C:\Windows\System32\Drivers\ |
|aswRdr2.sys |Avast Antivirus |C:\Windows\System32\Drivers\ |
|aswSnx.sys |Avast Antivirus |C:\Windows\System32\Drivers\ |
|aswSP.sys |Avast Self Protection |C:\Windows\System32\Drivers\ |
|aswStm.sys |Avast Stream Filter |C:\Windows\System32\Drivers\ |
|aswVmm.sys |Avast VM Monitor |C:\Windows\System32\Drivers\ |
|wsc\_proxy.exe |Avast Remediation exe |/|
|AvastSvc.exe |Avast Service |/ |
|aswEngSrv.exe |Avast Antivirus engine server |/ |
|aswToolsSvc.exe |Avast Antivirus |/ |
|aswidsagent.exe |Avast Software Analyzer |/ |
|AvastUI.exe |Avast Antivirus |/ |
In-memory modules present: 



|Name |Description |Sub Directory |
| - | - | - |
|awshook.dll |Avast Hook Library |/x86 |
|ashShell.dll |Avast Shell Extension |/ |
Functions Hooked: 

ADVAPI32.DLL 



|[CryptImportKey](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptimportkey) |[LogonUserW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw) |[CryptGenKey](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgenkey) |
| - | - | - |
|[CryptDuplicateKey](https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptduplicatekey) |[LogonUserA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera) |[LogonUserExA](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserexa) |
|[LogonUserExW](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserexw) |N/A |N/A |
USER32.DLL 



|[GetClipboardData](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getclipboarddata) |[SetWindowsHookExA](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexa) |[SetWindowsHookExW](https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexw) |
| - | - | - |
NTDLL.DLL 



|[RtlQueryEnvironmentVariable](https://stackoverflow.com/questions/28376922/what-is-rtlqueryenvironmentvariable-for) |[LdrLoadDll](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/Executable%20Images/LdrLoadDll.html) |[NtQueryInformationProcess](https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess) |
| - | - | - |
|[NtMapViewOfSection](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtMapViewOfSection.html) |[NtTerminateProcess](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/NtTerminateProcess.html) |[NtOpenSection](https://stackoverflow.com/questions/29683015/ntopensectionl-device-physicalmemory-returns-status-object-name-not-found) |
|[NtWriteVirtualMemory](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html) |[NtOpenEvent](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Event/NtOpenEvent.html) |[NtCreateEvent](https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FEvent%2FNtCreateEvent.html) |
|[NtCreateSection](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FNtCreateSection.html) |[NtProtectVirtualMemory](http://www.codewarrior.cn/ntdoc/winnt/mm/NtProtectVirtualMemory.htm) |[NtResumeThread](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Thread/NtResumeThread.html) |
|[NtCreateMutant](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Mutant/NtCreateMutant.html) |[NtCreateSemaphore](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Semaphore/NtCreateSemaphore.html) |[NtCreateUserProcess](http://www.rohitab.com/discuss/topic/40191-ntcreateuserprocess/) |
|[NtOpenMutant](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Mutant/NtOpenMutant.html) |[NtOpenSemaphore](http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Semaphore/NtOpenSemaphore.html) |[NtOpenThread](https://docs.microsoft.com/en-us/windows/win32/devnotes/ntopenthread) |
|[NtSuspendProcess](https://ntopcode.wordpress.com/tag/ntsuspendprocess/) |[RtlDecompressBuffer](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtldecompressbuffer) |N/A |
Minifilters Present: 



|Driver |Altitude |Type |
| - | - | - |
|aswSP.sys|[388401](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#360000---389999-fsfilter-activity-monitor)|FSFilter Activity Monitor |
|aswMonFlt.sys |[320700](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus) |FSFilter Anti-Virus |
|aswSnx.sys |[137600](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#130000---139999-fsfilter-virtualization) |FSFilter Virtualization |


|Antivirus Driver |Request |
| - | - |
|aswSP.sys|[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|aswSP.sys|[IRP_MJ_CREATE_NAMED_PIPE](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-create-named-pipe) |
|aswSP.sys|[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|aswSP.sys|[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control) |
|aswSP.sys|[IRP_MJ_LOCK_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-lock-control) |
|aswSP.sys |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
|aswSP.sys |[IRP_MJ_SET_SECURITY](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-security) |
|aswSP.sys |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|aswSP.sys |[IRP_MJ_CLOSE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-close) |
|aswMonFlt.sys |[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|aswMonFlt.sys |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write)  |
|aswMonFlt.sys |[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-cleanup) |
|aswMonFlt.sys |[IRP_MJ_CLOSE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-close)  |
|aswMonFlt.sys |[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|aswMonFlt.sys |[IRP_MJ_SET_SECURITY](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-security) |
|aswMonFlt.sys |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
|aswMonFlt.sys |[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control) |
|aswSnx.sys |[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|aswSnx.sys |[IRP_MJ_NETWORK_QUERY_OPEN](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-network-query-open) |
|aswSnx.sys |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|aswSnx.sys |[IRP_MJ_DIRECTORY_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-directory-control) |
|aswSnx.sys |[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-cleanup) |
|aswSnx.sys |[IRP_MJ_QUERY_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-query-information) |
|aswSnx.sys |[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|aswSnx.sys |[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control)  |
|aswSnx.sys |[IRP_MJ_QUERY_VOLUME_INFORMATION ](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-query-volume-information) |
Web Traffic: 



|Protocol |Remote Address |Local Port |Remote Port |
| - | - | - | - |
|TCP |5.45.59.36 |51910 |80 |
|TCP |5.62.54.29 |51911 |80 |
|TCP |5.62.53.230 |52459 |443 |
|TCP |5.62.53.230 |52460 |443 |
|TCP |5.62.53.212 |52461 |443 |
|TCP |5.62.53.212 |52462 |443 |
[continued below] 
` `PAGE37 Antivirus Artifacts III 
Services: 


|Name |Description |Startup Type |Path |
| - | - | - | - |
|Avast Antivirus |Manages & implements Avast Antivirus services for this computer. This includes real time shields , the virus chest & the scheduler.  |Automatic |\AvastSvc.exe |
|Avast Browser Update Service  |Keep your avast software upto date. |Automatic |C:\Program Files (x86)\AVAST Software\Browser\Update\ AvastBrowserUpdate.exe /svc |
|Avast Browser Update Service |Keeps your avast software upto date  |Manual |C:\Program Files (x86)\AVAST Software\Browser\Update\ AvastBrowserUpdate.exe /medsvc |
|Avast Secure Browser Elevation Service |- |Manual |C:\Program Files (x86)\AVAST Software\Browser\Applicati on\%ld\elevation\_service.e xe |
|Avast Tools |Manages & implements avast tools services for the computer |Automatic |C:\Program Files\Avast Software\Avast\aswToolsSv c.exe /runassvc |
|AvastWsc Reporter |- |Automatic |C:\Program Files\Avast Software\Avast\wsc\_proxy. exe /runassvc /rpcserver |

` `PAGE38 Antivirus Artifacts III 


Dr.Web 



|Parent Directory |
| - |
|C:\Program Files\DrWeb |
Binaries present: 



|Name |Description |Sub directory |
| - | - | - |
|dwdg.sys |Dr.Web device Guard for Windows |C:\Windows\System32\Drivers\|
|spiderg3.sys |Dr.Web File System Monitor |C:\Windows\System32\Drivers\|
|A4B1FF85CA.sys |Dr.Web Protection for Windows |C:\program files\kmspico\temp|
|dwprot.sys |Dr.Web Protection for Windows |C:\Windows\System32\Drivers\|
|dwnetfilter.exe |Dr. Web Net Filtering Service  |\ |
|dwservice.exe |Dr. Web Control Service |\ |
|dwantispam.exe |Dr. Web Anti Spam |\ |
|dwarkdameon.exe |Dr. Web Anti-Rootkit Service  |\ |
|dwscanner.exe |Dr. Web Scanner SE |\ |
In-memory modules present: 



|Name |Description |Sub Directory |
| - | - | - |
|drwamsi64.dll |Dr. Web AMSI |/ |
Functions Hooked: 



|*See remarks at bottom* |N/A |N/A |
| - | - | - |
Minifilters Present: 



|Driver |Altitude |Type |
| - | - | - |
|spider3g.sys|[323600](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus) |FSFilter Anti-Virus |
|dwprot.sys |[323610](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus) |FSFilter Anti-Virus |

` `PAGE40 Antivirus Artifacts III 



|Antivirus Driver |Request |
| - | - |
|dwdg.sys|[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|dwprot.sys  |[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|dwprot.sys  |[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-cleanup) |
|dwprot.sys  |[IRP_MJ_CLOSE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-close) |
|dwprot.sys  |[IRP_MJ_READ](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-read) |
|dwprot.sys  |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|dwprot.sys  |[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|dwprot.sys  |[IRP_MJ_DEVICE_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control) |
|dwprot.sys  |[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control) |
|dwprot.sys  |[IRP_MJ_SET_EA](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-ea) |
|dwprot.sys  |[IRP_MJ_SET_SECURITY](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-security) |
|dwprot.sys  |[IRP_MJ_SET_EA](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-ea) |
|dwprot.sys  |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
|spiderg3.sys |[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|spiderg3.sys |[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control) |
|spiderg3.sys |[IRP_MJ_WRITE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|spiderg3.sys |[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-cleanup) |
|spiderg3.sys |[IRP_MJ_CLOSE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-close) |
|spiderg3.sys |[IRP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|spiderg3.sys |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
|spiderg3.sys |[IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-release-for-section-synchronization) |
|spiderg3.sys |[IRP_MJ_SHUTDOWN](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-shutdown) |
Web Traffic: 



|Protocol |Remote Address |Local Port |Remote Port |
| - | - | - | - |
|TCP |162.159.134.234 |50183 |443 |

` `PAGE42 Antivirus Artifacts III 
Services: 


|Name |Description |Startup Type |Path |
| - | - | - | - |
|Dr.Web Control Service |Dr.Web Control Service is an essential part of Dr.Web Anti-virus! Please do not stop and do not disable it |Automatic |<p>C:\Program Files\DrWeb\dwservice.exe </p><p>--logfile="C:\ProgramData\ Doctor Web\Logs\dwservice.log </p>|
|Dr.Web Net Filtering Service |Dr.Web Net Filtering Service checks incoming and outgoing traffic. |Manual |"C:\Program Files\DrWeb\dwnetfilter.ex e" --ats |
|Dr.Web Scanning Engine |Dr.Web Scanning Engine checks your files against viruses. It is an essential part of the Dr.Web Anti-Virus! Please do not stop and do not disable it. |Manual |"C:\Program Files\Common Files\Doctor Web\Scanning Engine\dwengine.exe" |
*Note: Dr Web hooks functions. The functions are hooked using reflective DLL loading. Process Explorer and Process Hacker do not detect the loaded / injected DLLs. Dr Web loads 3 additional DLLs including a modified NTDLL which has no header. The modified NTDLL variant is locked from a kernel-side component. I have not inspected this further.* 
` `PAGE43 Antivirus Artifacts III 


Kaspersky 



|Parent Directory |
| - |
|C:\Program Files(x86)\Kaspersky Lab |
Binaries present: 



|Name |Description |Sub directory |
| - | - | - |
|klupd\_klif\_klark.sys |Kaspersky Lab Anti-Rootkit |C:\Windows\System32\Drivers\|
|klupd\_klif\_mark.sys |Kaspersky Lab Anti-Rootkit Memory Driver |C:\Windows\System32\Drivers\|
|klupd\_klif\_arkmon.sys |Kaspersky Lab Anti-Rootkit Monitor Driver |C:\ProgramData\Kaspersky Lab\AVP21.2\|
|avp.exe |Kaspersky Anti-Virus |\Kaspersky Security Cloud 21.2 |
|avpui.exe |Kaspersky Anti-Virus |\Kaspersky Security Cloud 21.2 |
|kpm.exe |Kaspersky Password Manager |\AVP21.2\Lab |
|ksdeui.exe |Kaspersky Secure Connection |\Kaspersky VPN 5.2 |
|ksde.exe |Kaspersky Secure Connection |\Kaspersky VPN 5.2 |
|kldisk.sys |Virtual Disk |C:\Windows\System32\Drivers\ |
|klflt.sys |Filter Core |C:\Windows\System32\Drivers\ |
|klgse.sys |Security Extender |C:\Windows\System32\Drivers\ |
|klhk.sys |klhk |C:\Windows\System32\Drivers\ |
|klids.sys |Network Processor |C:\Windows\System32\Drivers\ |
|klif.sys |Core System Interceptors |C:\Windows\System32\Drivers\ |
|klim6.sys |Packet Network Filter |C:\Windows\System32\Drivers\ |
|klkbdflt2.sys |Light Keyboard Device Filter |C:\Windows\System32\Drivers\ |
|klpd.sys |Format Recognizer |C:\Windows\System32\Drivers\ |
|kltap.sys |TAP-Windows Virtual Network Driver |C:\Windows\System32\Drivers\ |
|klupd\_klif\_kimul.sys |Kaspersky Lab Anti-Rootkit Monitor Driver |C:\Windows\System32\Drivers\ |

` `PAGE45 Antivirus Artifacts III 

In-memory modules present: 



|Name |Description |Sub Directory |
| - | - | - |
|antimalware\_provider.dll |Kaspersky AntiMalwareProvider Component |Kaspersky Total Security 21.2\x64 |
Functions Hooked: 



|N/A |N/A |N/A |
| - | - | - |
Minifilters Present: 



|Driver |Altitude |Type |
| - | - | - |
|klif.sys|[323600](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes#320000---329998-fsfilter-anti-virus) |FSFilter Anti-Virus |


|Antivirus Driver |Request |
| - | - |
|klif.sys|[IRP_MJ_CREATE](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-create) |
|klif.sys |[IRP_MJ_CREATE_NAMED_PIPE](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-create-named-pipe) |
|klif.sys |[IRP_MJ_READ](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-read) |
|klif.sys |[IRP_MJ_WRITE ](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-write) |
|klif.sys |I[RP_MJ_SET_INFORMATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-set-information) |
|klif.sys |[IRP_MJ_DIRECTORY_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-directory-control) |
|klif.sys |[IRP_MJ_FILE_SYSTEM_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-file-system-control) |
|klif.sys |[IRP_MJ_DEVICE_CONTROL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-device-control) |
|klif.sys |[IRP_MJ_SHUTDOWN](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-shutdown) |
|klif.sys |[IRP_MJ_CLEANUP](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-cleanup) |
|klif.sys |[IRP_MJ_SET_SECURITY](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-security) |
|klif.sys |[IRP_MJ_PNP](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/irp-mj-pnp) |
|klif.sys |[IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-acquire-for-section-synchronization) |
|klif.sys |[IRP_MJ_VOLUME_MOUNT](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/flt-parameters-for-irp-mj-volume-mount) |
Web Traffic: 



|Protocol |Remote Address |Local Port |Remote Port |
| - | - | - | - |
|TCP |80.239.170.149 |50719 |80 |
|TCP |67.27.99.250 |50800 |443 |
|TCP |67.27.99.250 |50801 |443 |
|TCP |38.113.165.138 |51881 |443 |
|TCP |66.110.49.116 |51875 |443 |
Services: 



|Name |Description |Startup Type |Path |
| - | - | - | - |
|Kaspersky Anti-Virus Service 21.2 |Provides computer protection against viruses and other malware, network attacks, Internet fraud and spam. |Automatic |"C:\Program Files (x86)\Kaspersky Lab\Kaspersky Total Security 21.2\avp.exe" -r |
|Kaspersky Volume Shadow Copy Service Bridge 21.2 |Kaspersky Volume Shadow Copy Service Bridge |Manual |"C:\Program Files (x86)\Kaspersky Lab\Kaspersky Total Security 21.2\x64\vssbridge64.exe" |
|Kaspersky VPN Secure Connection Service 5.2 |Protects confidential data that the user enters on websites (such as banking card numbers or passwords for access to online banking services) and prevents theft of funds during online transactions. |Automatic |"C:\Program Files (x86)\Kaspersky Lab\Kaspersky VPN 5.2\ksde.exe" -r |
*Note: Kaspersky also contains a Standard Filter for Keyboard I/O* 

Conclusion: 

As this series has grown we are now starting to see anti-viruses use an array of different technologies which can be difficult for malware authors to see. Although many rely on archaic hooking techniques, and hook archaic functionality from well-known malware techniques, many also come equipped with fairly robust file system minifilters to capture data which escape the hooks. This is evident because in the original entry in the Antivirus Artifacts series F-Secure was able to detect the keylogger placed on the machine despite not using any API hooks and also being unfamiliar with the malicious binaries MD5 hash. This robust minifilter system, coupled with static binary analysis implementations (something YARA rule-like), could prove to be a challenging adversary for malware authors. 

As a final note: in this series I was unable to test these anti-viruses against the ‘Undertaker’ malware written because after the release of Antivirus Artifacts 1 most antivirus companies had flagged the file hash as malicious. The homebrew malware proof-of-concept can be viewed on VirusTotal. 

Previous paper proof-of-concept IOC: [2a419d2ddf31ee89a8deda913abf1b25d45bb0dc59a93c606756cfa66acb0791](https://www.virustotal.com/gui/file/2a419d2ddf31ee89a8deda913abf1b25d45bb0dc59a93c606756cfa66acb0791/detection) 
` `PAGE48 Antivirus Artifacts III 
