@Echo off
COLOR 1e

REM PVS Generalization Script
REM Version 15


REM ************************
REM  EMTPY THE RECYCLE BIN
REM ************************
REM
@Echo Clearing the Recycle Bin
rd /s /q %systemdrive%\$Recycle.bin
@Echo %DATE%-%TIME% Recycle Bin has been emptied>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo.

REM ***************************************************
REM  DELETE TEMP FILES IN C:\TEMP AND C:\WINDOWS\TEMP
REM ***************************************************
REM
@Echo Deleting temp files in C:\Temp and C:\Windows\Temp
REM if exist "C:\Temp" rmdir /S /Q C:\Temp
if exist "C:\Windows\Temp\*.*" del /S /Q C:\Windows\Temp\*.*
@Echo %DATE%-%TIME% Temp files have been deleted>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo.

REM *************************************
REM  DELETE LOGGED ON USER'S TEMP FILES
REM *************************************
REM
@Echo Deleting logged on user temp files
del /q /f /s %TEMP%\*
@Echo %DATE%-%TIME% Logged on user temp files have been deleted>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo.

REM *************************************
REM  DELETE SHORTCUTS ON PUBLIC DESKTOP
REM *************************************
REM
@Echo Deleting shortcuts on the public desktop folder
del /q /f C:\Users\Public\Desktop\*.lnk
@Echo %DATE%-%TIME% Shortcuts on public desktop folder have been deleted>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo.

REM *************************************************************
REM  DELETE SHORTCUTS IN ALL USERS STARTUP FOLDER IN START MENU
REM *************************************************************
REM
@Echo Deleting shortcuts in All Users startup folder in Start Menu
del /q /f "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*"
@Echo %DATE%-%TIME% Shortcuts in All users startup folder in Start Menu have been deleted>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo.

REM ************************
REM  VDES LOG FILE CLENAUP
REM ************************
REM
REM @Echo Deleting VDES log files
del /S /Q C:\VCW\Logs\VDES_Log.txt\*.*
REM @Echo %DATE%-%TIME% VDES logs have been cleared>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo.

REM ****************************
REM  LAKESIDE SYSTRACK CLEANUP
REM ****************************
REM
@Echo off
REM if exist "C:\Program Files (x86)\SysTrack" (
  @Echo off
  @Echo Cleaning up Lakeside SysTrack
  sc stop lsiagent
  del /F /S /Q d:\systrack\database\
  cd "C:\Program Files (x86)\SysTrack\LsiAgent\"
  del /F /Q LsiAgent1.log
  reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Lakeside Software\LsiAgent\Settings" /f
  @Echo %DATE%-%TIME% Lakeside SysTrack has been cleaned up>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
REM 
REM ) else (
REM   @Echo %DATE%-%TIME% Lakeside SysTrack not detected as an installed application>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
REM )
@Echo.
@Echo.

REM ******************************************************************
REM  EMPTY IE TEMP FILES, HISTORY, COOKIES, FORM DATA, AND PASSWORDS
REM ******************************************************************
REM
@Echo Clearing IE temp files, history, cookies, form data, and passwords
RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255
@Echo %DATE%-%TIME% IE temp files, history, cookies, form data, and passwords have been deleted>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo.

REM ***************************************************
REM  DELETE ALL RECENT ITEMS IN WINDOWS FILE EXPLORER
REM ***************************************************
REM
@Echo Deleting all 'recent items' in Windows File Explorer
del %appdata%\Microsoft\Windows\Recent\*.* /q
@Echo %DATE%-%TIME% 'Recent items' in Windows File Explorer have been deleted>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo.

REM ***********************************************
REM  STOP AND SET WINDOWS UPDATE SERVICE TO MANUAL
REM ***********************************************
REM
@Echo Stopping Windows Update service and setting service to Manual
net stop wuaserv
sc stop wuauserv
sc config wuauserv start=disabled
REM reg add "HKLM\SYSTEM\CurrentControlSet\services\wuauserv" /v Start /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
@Echo %DATE%-%TIME% Windows Update service has been stopped and service has been set to Manual>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo.



REM ***********************************************
REM  STOP AND SET EDGE SERVICES TO DISABLE
REM ***********************************************
REM
@Echo Stopping Edge Chromium service and setting service to Disable
sc stop MicrosoftEdgeElevationService
wmic service where name='MicrosoftEdgeElevationService' call ChangeStartmode Disabled
sc stop edgeupdate
wmic service where name='edgeupdate' call ChangeStartmode Disabled
sc stop edgeupdatem
wmic service where name='edgeupdatem' call ChangeStartmode Disabled
@Echo %DATE%-%TIME% Edge Chromium services have been stopped and set to Disabled>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo.




REM *******************************************
REM  DELETE DOWNLOADED WINDOWS UPDATE PATCHES
REM *******************************************
REM
@Echo Deleting downloaded Windows Update patches
if exist "C:\Windows\SoftwareDistribution\Download\*.*" del /Q /S C:\Windows\SoftwareDistribution\Download\*.*
@Echo %DATE%-%TIME% Downloaded Windows Update patches have been deleted>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo.



REM ***************************
REM  CLEAR WINDOWS EVENT LOGS
REM ***************************
REM
@Echo Clearing Windows Event Logs
wevtutil cl Application
wevtutil cl Security
wevtutil cl System
wevtutil cl Setup
@Echo %DATE%-%TIME% Windows Event Logs have been cleared>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo.

REM ***************************
REM  CLEAR FSLOGIX LOGS
REM ***************************
REM
@Echo Clearing FSLOGIX Logs
DEL C:\ProgramData\FSLogix\Logs\*.log /Q /S
@Echo %DATE%-%TIME% FSLOGIX Logs have been cleared>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo.

REM *******************
REM  ENABLE RSA LOGIN
REM *******************
REM
REM @Echo off
REM if exist "C:\Program Files\Common Files\RSA Shared\RSA.NET\RSAControlCenter.exe" (
REM  @Echo off
REM  @Echo Enabling RSA Login
REM	reg add "HKEY_LOCAL_MACHINE\SOFTWARE\RSA\RSA Desktop Preferences\Local Authentication Settings" /v "ChallengeMode" /t REG_DWORD /d 3 /F
REM	@Echo %DATE%-%TIME% RSA login has been enabled>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
REM ) else (
REM  @Echo %DATE%-%TIME% RSA not detected>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
REM )
REM reg add "HKLM\Software\RSA\RSA Desktop Preferences\Local Authentication Settings" /v "ChallengeMode" /t REG_DWORD /d 3 /f
REM @Echo.
REM @Echo.


REM **********************
REM  GENERALIZE APPSENSE
REM **********************
REM
@Echo Stopping the CCA service
REM net stop "AppSense Client Communications Agent"
@Echo Wiping the AppSense CCA AGent group ID and machine ID
REM reg add "HKEY_LOCAL_MACHINE\Software\AppSense Technologies\Communications Agent" /v "group id" /t reg_sz /d "" /f
REM reg add "HKEY_LOCAL_MACHINE\Software\AppSense Technologies\Communications Agent" /v "machine id" /t reg_sz /d "" /f
@Echo %DATE%-%TIME% AppSense has been generalized>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo.


REM *********************
REM  FLUSH DNS AND ARP
REM *********************
REM
@Echo Flushing DNS cache and ARP entries
Ipconfig /flushdns
arp.exe -d
@Echo %DATE%-%TIME% DNS and ARP have been flushed>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo.

REM **************************************************************************************
REM  IF XenServer VM - Remove IPs for XenServer VMs (resolve duplicate IPs when booting)
REM **************************************************************************************
REM
@Echo off
if exist "C:\Program Files\Citrix\XenTools\XenGuestAgent.exe" (
  @Echo off
  @Echo Detected XenServer VM, applying duplicate IP fix
	reg delete "HKLM\System\CurrentControlSet001\Services\TCPIP\Parameters\Interfaces\{42d28017-5bf4-4c68-8605-67d46b49bdb2}" /v DhcpIPAddress /f
	reg delete "HKLM\System\CurrentControlSet001\Services\TCPIP\Parameters\Interfaces\{a8a7dd8b-0bd7-4860-b686-52f3d3bddf02}" /v DhcpIPAddress /f
	reg delete "HKLM\System\CurrentControlSet\Services\TCPIP\Parameters\Interfaces\{42d28017-5bf4-4c68-8605-67d46b49bdb2}" /v DhcpIPAddress /f
	reg delete "HKLM\System\CurrentControlSet\Services\TCPIP\Parameters\Interfaces\{a8a7dd8b-0bd7-4860-b686-52f3d3bddf02}" /v DhcpIPAddress /f
	@Echo %DATE%-%TIME% XenServer duplicate IP fix applied>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log

) else (
  @Echo %DATE%-%TIME% VM not a XenServer VM>>C:\PVSPrep\logs\pvsprep_v15_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
)
@Echo.
@Echo.


REM *************************
REM  PERFORM SEP VIRUS SCAN 
REM *************************
REM
REM @Echo Running SEP monthly virus scan
REM "C:\Program Files (x86)\Symantec\Symantec Endpoint Protection\DoScan.exe" /Scanname "Monthly Scheduled Scan"
REM @Echo SEP monthly virus scan has completed
REM @Echo.
REM @Echo.

REM *************************
REM  Fix Microsoft Access ODBC Registry Keys 
REM *************************
REM
@ECHO Fix Microsoft Access ODBC Registry Keys
reg add "HKLM\SOFTWARE\ODBC\ODBCINST.INI\Microsoft Access dBASE Driver (*.dbf, *.ndx, *.mdx)" /v Driver /d "C:\Program Files\Common Files\Microsoft Shared\OFFICE16\ACEODBC.DLL" /f
reg add "HKLM\SOFTWARE\ODBC\ODBCINST.INI\Microsoft Access dBASE Driver (*.dbf, *.ndx, *.mdx)" /v Setup /d "C:\Program Files\Common Files\Microsoft Shared\OFFICE16\ACEODDBS.DLL" /f
reg add "HKLM\SOFTWARE\ODBC\ODBCINST.INI\Microsoft Access Driver (*.mdb, *.accdb)" /v Driver /d "C:\Program Files\Common Files\Microsoft Shared\OFFICE16\ACEODBC.DLL" /f
reg add "HKLM\SOFTWARE\ODBC\ODBCINST.INI\Microsoft Access Driver (*.mdb, *.accdb)" /v Setup /d "C:\Program Files\Common Files\Microsoft Shared\OFFICE16\ACEODBC.DLL" /f
reg add "HKLM\SOFTWARE\ODBC\ODBCINST.INI\Microsoft Access Text Driver (*.txt, *.csv)" /v Driver /d "C:\Program Files\Common Files\Microsoft Shared\OFFICE16\ACEODBC.DLL" /f
reg add "HKLM\SOFTWARE\ODBC\ODBCINST.INI\Microsoft Access Text Driver (*.txt, *.csv)" /v Setup /d "C:\Program Files\Common Files\Microsoft Shared\OFFICE16\ACEODTXT.DLL" /f
reg add "HKLM\SOFTWARE\ODBC\ODBCINST.INI\Microsoft Excel Driver (*.xls, *.xlsx, *.xlsm, *.xlsb)" /v Driver /d "C:\Program Files\Common Files\Microsoft Shared\OFFICE16\ACEODBC.DLL" /f
reg add "HKLM\SOFTWARE\ODBC\ODBCINST.INI\Microsoft Excel Driver (*.xls, *.xlsx, *.xlsm, *.xlsb)" /v Setup /d "C:\Program Files\Common Files\Microsoft Shared\OFFICE16\ACEODEXL.DLL" /f
REM @Echo.
REM @Echo.

@Echo OFF
REM *****************
REM  GENERALIZE SEP
REM *****************
REM
REM @Echo OFF
REM @Echo Generalizing SEP. Please wait as this process will take a few moments.
REM"c:\Program Files (x86)\Symantec\Symantec Endpoint Protection\smc.exe" -stop

REM for /d %%d in (
REM "C:\Program Files\Common Files\Symantec Shared\HWID"
REM "C:\Documents and Settings\All Users\Application Data\Symantec\Symantec Endpoint Protection\PersistedData"
REM "C:\ProgramData\Symantec\Symantec Endpoint Protecton\PersistedData"
REM "C:\Windows\Temp"
REM ) do del /f "%%~d\sephwid.xml"

REM for /d %%d in (
REM "C:\Documents and Settings\*"
REM "C:\Users\*"
REM ) do (
REM del /f "%%~d\Local Settings\Temp\sephwid.xml"
REM del /f "%%~d\Local Settings\Temp\communicator.dat"
REM )

REM reg delete "HKLM\Software\Wow6432Node\Symantec\Symantec Endpoint Protection\SMC\SYLINK\SyLink" /v ForceHardwareKey /f
REM reg delete "HKLM\Software\Wow6432Node\Symantec\Symantec Endpoint Protection\SMC\SYLINK\SyLink" /v HardwareID /f
REM reg delete "HKLM\SOFTWARE\Wow6432Node\Symantec\Symantec Endpoint Protection\SMC\SYLINK\SyLink" /v HostGUID /f

REM @Echo %DATE%-%TIME% SEP has been generalized>>C:\PVSPrep\logs\pvsprep_v15PU_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
@Echo.
@Echo ON
 

REM *************************
REM  WEM CACHE SYNC
REM *************************
REM
@Echo Running Citrix WEM Cache Sync
"C:\Program Files (x86)\Citrix\Workspace Environment Management Agent\AgentCacheUtility.exe" /refreshcache
REM @Echo Citrix WEM Cache Sync has completed
REM @Echo.
REM @Echo.

REM *************************
REM  Stop and Disable Azure services
REM *************************
REM
@Echo Stopping Azure services
sc stop "Azure Site Recovery VSS Provider"
sc stop "RdAgent"
sc stop "WindowsAzureGuestAgent"
@Echo Disabling Azure services
sc config "Azure Site Recovery VSS Provider" start=disabled
sc config "RdAgent" start=disabled
sc config "WindowsAzureGuestAgent" start=disabled
@Echo Azure Agent config changes completed
@Echo.
@Echo.

REM *************************
REM  ASK TO RUN NGEN UPDATE
REM *************************
REM
CLS
COLOR F4
REM @Echo.
REM CHOICE /C YN /T 120 /D N /M "Would you like to run NGEN update? Please note that this procedure can take quite awhile"

REM IF %ERRORLEVEL%==1 GoTo RUN-NGEN
REM IF %ERRORLEVEL%==2 GoTo SKIP-NGEN


:SHUTDOWN-PROMPT
CLS
COLOR F4
@Echo *****************************************************
@Echo *							  *
@Echo * PLEASE SYNC THIS VDISK WITH THE OTHER PVS SERVERS *
@Echo *							  *
@Echo *****************************************************
@Echo.
CHOICE /C YN /T 300 /D Y /M "Would you like to shutdown now? "

IF %ERRORLEVEL%==1 GoTo SEAL-IT
IF %ERRORLEVEL%==2 GoTo NOT-YET

:RUN-NGEN
@Echo Running NGEN update, please wait
C:\Windows\Microsoft.NET\framework\v4.0.30319\ngen.exe update
C:\Windows\Microsoft.NET\framework64\v4.0.30319\ngen.exe update
C:\Windows\Microsoft.NET\framework\v2.0.50727\ngen.exe update
C:\Windows\Microsoft.NET\framework64\v2.0.50727\ngen.exe update
@Echo %DATE%-%TIME% NGEN update complete>>C:\PVSPrep\logs\pvsprep_v15PU_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
GoTo :SHUTDOWN-PROMPT

:SKIP-NGEN
@Echo %DATE%-%TIME% Skipping NGEN update>>C:\PVSPrep\logs\pvsprep_v15PU_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
GoTo :SHUTDOWN-PROMPT

:SEAL-IT
@Echo %DATE%-%TIME% Sealing vDisk>>C:\PVSPrep\logs\pvsprep_v15PU_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
shutdown /s /t 5
GoTo :EOF

:NOT-YET
@Echo %DATE%-%TIME% Skipping shutdown>>C:\PVSPrep\logs\pvsprep_v15PU_%date:~-4,4%%date:~-10,2%%date:~-7,2%.log
GoTo :EOF