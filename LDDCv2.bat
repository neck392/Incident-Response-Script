:: 25.08.21
:: [Live Disk Data Collector] 휘발성과 비휘발성 데이터 수집 개인 업그레이드
@echo off
setlocal EnableExtensions EnableDelayedExpansion

:: 공통 옵션(추가 명령용; 기존 robocopy 라인은 그대로 둠)
set "RBOPX=/s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T"
set "EULA=-accepteula"
set "SYS=%ProgramFiles%\SysinternalsSuite"

:: 관리자 권한 확인(없으면 경고만 표시하고 계속)
>nul 2>&1 net session || echo [!] 관리자 권한 없이 실행 중입니다. 일부 결과가 제한될 수 있습니다.

::dir 생성 경로 설정
set "result=_result"
set "vol=%result%\_vol"
set "nonvol=%result%\_nonvol"

set "prefetch=%result%\_prefetch"

::vol 데이터 생성 경로
set "net=%vol%\_net"
set "process=%vol%\_process"
set "logonAccount=%vol%\_logonAccount"

::nonVol 데이터 생성 경로
set "cache=%nonvol%\_cache"
set "cookie=%nonvol%\_cookie"
set "registry=%nonvol%\_registry"
set "mft=%nonvol%\_mft"
set "eventLog=%nonvol%\_eventlog"
set "recent=%nonvol%\_recent"
set "quickLaunch=%nonvol%\_quicklaunch"

:REDO
echo ----------------------------------------------
echo.
echo.
echo.
echo   :          :'''.      :'''.        .'''''.
echo   :          :    '.    :    '.    .'
echo   :          :     :    :     :    :
echo   :          :    .'    :    .'    '.
echo   :.......   :...'      :...'        '.....'
echo.
echo.
echo.
echo --------- (Live Disk Data Collector) ---------
echo 1. All data
echo 2. Volatile data
echo 3. Non-volatile data
echo 4. Program end
echo ----------------------------------------------
set /p inputNum=Enter the number you want to run :

if "%inputNum%"=="1" goto 1
if "%inputNum%"=="2" goto 2
if "%inputNum%"=="3" goto 3
if "%inputNum%"=="4" goto 4
goto ERROR

::all
:1
if not exist "%result%" (
    mkdir "%result%"
    echo Created %result% directory. 
    echo START Date: %DATE% Time: %TIME% > _result\log.txt
) else (
    echo %result% directory already exists. passing...
)

if not exist "%prefetch%" (
    mkdir "%prefetch%"
    echo Created %prefetch% directory. 
    echo start prefetch_part at Date: %DATE% Time: %TIME% >> _result\log.txt
    forecopy_handy.exe -p .\_result\_prefetch\
    :: 추가: Prefetch 폴더 직접 백업(보조)
    if exist "%SystemRoot%\Prefetch" robocopy "%SystemRoot%\Prefetch" "%prefetch%\_mirror" %RBOPX% > "%prefetch%\robocopy_prefetch.txt"
) else (
    echo %prefetch% directory already exists. passing...
)

if not exist "%vol%" (
    mkdir "%vol%"
    echo Created %vol% directory.

    ::net
    if not exist "%net%" (
        mkdir "%net%"
        set "net=%vol%\_net"
        echo start net_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        ipconfig > "%net%\ipconfig.txt"
        getmac > "%net%\getmac.txt"
        net > "%net%\net.txt"
        netstat -ano > "%net%\netstat.txt"
        tcpvcon > "%net%\tcpvcon.txt"
        arp -a > "%net%\arp.txt"
        route print > "%net%\route.txt"

        :: ===== 추가 네트워크 수집 =====
        ipconfig /all > "%net%\ipconfig_all.txt"
        ipconfig /displaydns > "%net%\dns_cache.txt" 2> "%net%\dns_cache.err"
        netstat -abno > "%net%\netstat_abno.txt" 2> "%net%\netstat_abno.err"
        nbtstat -c > "%net%\nbtstat_cache.txt"
        netsh interface ip show config > "%net%\netsh_ip_config.txt"
        netsh advfirewall show allprofiles > "%net%\firewall_profiles.txt"
        netsh winhttp show proxy > "%net%\winhttp_proxy.txt"
        :: Sysinternals 확장(있을 때만)
        if exist "%SYS%\tcpvcon.exe" "%SYS%\tcpvcon.exe" %EULA% -a -n > "%net%\tcpvcon_full.txt"
    ) else (
        echo %net% directory already exists. passing...
    )

    ::process
    if not exist "%process%" (
        mkdir "%process%"
        set "process=%vol%\_process"
        echo start process_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        powershell.exe -command ps > "%process%\ps.txt"
        tasklist > "%process%\tasklist"
        handle.exe > "%process%\handle_opened_files.txt"
        Listdlls.exe > "%process%\Listdlls.txt"

        :: ===== 추가 프로세스/서비스/드라이버/시스템 정보 =====
        tasklist /v > "%process%\tasklist_verbose.txt"
        tasklist /svc > "%process%\tasklist_svc.txt"
        sc queryex type= service state= all > "%process%\services_all.txt"
        driverquery /v > "%process%\driverquery_verbose.txt"
        powershell -NoP -C "Get-Process | Sort-Object CPU -Descending | Select-Object -First 50 | Format-Table -AutoSize" > "%process%\top50_cpu.txt"
        powershell -NoP -C "Get-HotFix | Sort-Object InstalledOn | Format-Table -AutoSize" > "%process%\hotfix.txt"
        systeminfo > "%process%\systeminfo.txt"
        tzutil /g > "%process%\timezone.txt"
        schtasks /query /fo LIST /v > "%process%\scheduled_tasks.txt"

        :: Sysinternals 확장(있을 때만)
        if exist "%SYS%\handle.exe"      "%SYS%\handle.exe" %EULA% -a -u > "%process%\handle_verbose.txt"
        if exist "%SYS%\listdlls.exe"    "%SYS%\listdlls.exe" %EULA% -v > "%process%\listdlls_verbose.txt"
        if exist "%SYS%\autorunsc.exe"   "%SYS%\autorunsc.exe" %EULA% -a * -ct -nobanner -o "%process%\autoruns.csv"
    ) else (
        echo %process% directory already exists. passing...
    )

    ::logonAccount
    if not exist "%logonAccount%" (
        mkdir "%logonAccount%"
        set "logonAccount=%vol%\_logonAccount"
        echo start logonAccount_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        net session > "%logonAccount%\netsession.txt"
        net user > "%logonAccount%\netuser.txt"
        net localgroup > "%logonAccount%\netlocalgroup.txt"
        net localgroup administrators  > "%logonAccount%\netlocalgroupadministrators.txt"
        logonsessions.exe > "%logonAccount%\logonsessions.txt"
        PsLoggedon.exe > "%logonAccount%\PsLoggedon.txt"

        :: ===== 추가 계정/세션/정책 =====
        whoami /all > "%logonAccount%\whoami_all.txt"
        query user > "%logonAccount%\query_user.txt" 2> "%logonAccount%\query_user.err"
        net accounts > "%logonAccount%\net_accounts.txt"
        if exist "%SYS%\logonsessions.exe" "%SYS%\logonsessions.exe" %EULA% -p > "%logonAccount%\logonsessions_proc.txt"
        if exist "%SYS%\psloggedon.exe"   "%SYS%\psloggedon.exe" %EULA% > "%logonAccount%\psloggedon_full.txt"
    ) else (
        echo %logonAccount% directory already exists. passing...
    )

) else (
    echo %vol% directory already exists. passing...
)

if not exist "%nonvol%" (
    mkdir "%nonvol%"
    echo Created %nonvol% directory.

    ::cache
    if not exist "%cache%" (
        mkdir "%cache%"
        set "cache=%nonvol%\_cache"
        :: set "chromeCache=C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\Cache"
        echo start cache_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        robocopy "C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\Cache" "%cache%" /s /e /z /copy:DAT /r:3 /w:5 /log:"%cache%\robocopy_chrome_cache.txt"

        :: ===== 추가 브라우저 캐시(멀티 프로필/Edge/Firefox) =====
        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\*") do (
            if exist "%%~fP\Cache" robocopy "%%~fP\Cache" "%cache%\Chrome_%%~nP_Cache" %RBOPX% > "%cache%\Chrome_%%~nP_Cache.log"
        )
        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\User Data\*") do (
            if exist "%%~fP\Cache" robocopy "%%~fP\Cache" "%cache%\Edge_%%~nP_Cache" %RBOPX% > "%cache%\Edge_%%~nP_Cache.log"
        )
        for /d %%P in ("%APPDATA%\Mozilla\Firefox\Profiles\*") do (
            robocopy "%%~fP" "%cache%\Firefox_%%~nP" %RBOPX% /xd cache2 > "%cache%\Firefox_%%~nP.log"
        )
    ) else (
        echo %cache% directory already exists. passing...
    )

    ::cookie
    if not exist "%cookie%" (
        mkdir "%cookie%"
        set "cookie=%nonvol%\_cookie"
        echo start cookie_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        robocopy "C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\Network" "%cookie%" /s /e /z /copy:DAT /r:3 /w:5 /log:"%cookie%\cookie.txt"

        :: ===== 추가 쿠키/네트워크 데이터(프로필 확장/Edge) =====
        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\*") do (
            if exist "%%~fP\Network" robocopy "%%~fP\Network" "%cookie%\Chrome_%%~nP_Network" %RBOPX% > "%cookie%\Chrome_%%~nP_Network.log"
        )
        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\User Data\*") do (
            if exist "%%~fP\Network" robocopy "%%~fP\Network" "%cookie%\Edge_%%~nP_Network" %RBOPX% > "%cookie%\Edge_%%~nP_Network.log"
        )
    ) else (
        echo %cookie% directory already exists. passing...
    )

    ::registry
    if not exist "%registry%" (
        mkdir "%registry%"
        echo start registry_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        forecopy_handy.exe -g .\_result\_nonvol\_registry\

        :: ===== 추가: 레지스트리 하이브 스냅샷(reg save) =====
        reg save HKLM\SAM        "%registry%\SAM"        /y >nul 2>&1
        reg save HKLM\SYSTEM     "%registry%\SYSTEM"     /y >nul 2>&1
        reg save HKLM\SOFTWARE   "%registry%\SOFTWARE"   /y >nul 2>&1
        reg save HKLM\SECURITY   "%registry%\SECURITY"   /y >nul 2>&1
        reg save HKU\.DEFAULT    "%registry%\DEFAULT"    /y >nul 2>&1
        reg save HKCU            "%registry%\NTUSER.DAT" /y >nul 2>&1
        reg export HKCU\Software "%registry%\HKCU_Software.reg" /y >nul 2>&1
    ) else (
        echo %registry% directory already exists. passing...
    )
    
    ::mft
    if not exist "%mft%" (
        mkdir "%mft%"
        echo start mft_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        forecopy_handy.exe -m .\_result\_nonvol\_mft\

        :: ===== 추가: 볼륨/USN 정보 참고 =====
        fsutil fsinfo ntfsinfo %SystemDrive% > "%mft%\ntfsinfo.txt" 2> "%mft%\ntfsinfo.err"
        fsutil usn queryjournal %SystemDrive% > "%mft%\usn_journal_info.txt" 2> "%mft%\usn_journal_info.err"
    ) else (
        echo %mft% directory already exists. passing...
    )

    ::eventlog
    if not exist "%eventLog%" (
        mkdir "%eventLog%"
        echo start eventlog_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        forecopy_handy.exe -e .\_result\_nonvol\_eventlog\

        :: ===== 추가: wevtutil로 전체 로그 내보내기(가능한 것만) =====
        for /f "delims=" %%L in ('wevtutil el') do (
            wevtutil epl "%%L" "%eventLog%\%%L.evtx" 2>> "%eventLog%\_wevtutil_errors.txt"
        )
    ) else (
        echo %eventLog% directory already exists. passing...
    )

    ::recent
    if not exist "%recent%" (
        mkdir "%recent%"
        set "recent=%nonvol%\_recent"
        echo start recent_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        robocopy "%APPDATA%\Microsoft\Office\Recent" "%recent%" /s /e /z /copy:DAT /r:3 /w:5 /log:"%recent%\recent.txt"

        :: ===== 추가: Windows Shell Recent & JumpLists =====
        robocopy "%APPDATA%\Microsoft\Windows\Recent" "%recent%\ShellRecent" %RBOPX% > "%recent%\ShellRecent.log"
        robocopy "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations" "%recent%\JumpLists_AutoDest" %RBOPX% > "%recent%\JumpLists_AutoDest.log"
        robocopy "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations"     "%recent%\JumpLists_CustomDest" %RBOPX% > "%recent%\JumpLists_CustomDest.log"
    ) else (
        echo %recent% directory already exists. passing...
    )

    ::quicklaunch
    if not exist "%quickLaunch%" (
        mkdir "%quickLaunch%"
        set "quickLaunch=%nonvol%\_quicklaunch"
        echo start quicklaunch_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        robocopy "%APPDATA%\Microsoft\Internet Explorer\Quick Launch" "%quickLaunch%" /s /e /z /copy:DAT /r:3 /w:5 /log:"%quickLaunch%\quicklaunch.txt"

        :: ===== 추가: 작업표시줄 고정 아이콘 =====
        robocopy "%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" "%quickLaunch%\TaskBar" %RBOPX% > "%quickLaunch%\TaskBar.log"
    ) else (
        echo %quickLaunch% directory already exists. passing...
    )

) else (
    echo %nonvol% directory already exists. passing...
)

goto REDO
pause

::vol
:2 
if not exist "%result%" (
    mkdir "%result%"
    echo Created %result% directory. 
    echo START Date: %DATE% Time: %TIME% > _result\log.txt
) else (
    echo %result% directory already exists. passing...
)

if not exist "%vol%" (
    mkdir "%vol%"
    echo Created %vol% directory.
    ::net
    if not exist "%net%" (
        mkdir "%net%"
        set "net=%vol%\_net"
        echo start net_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        ipconfig > "%net%\ipconfig.txt"
        getmac > "%net%\getmac.txt"
        net > "%net%\net.txt"
        netstat -ano > "%net%\netstat.txt"
        tcpvcon > "%net%\tcpvcon.txt"
        arp -a > "%net%\arp.txt"
        route print > "%net%\route.txt"

        :: 추가 네트워크(동일)
        ipconfig /all > "%net%\ipconfig_all.txt"
        ipconfig /displaydns > "%net%\dns_cache.txt" 2> "%net%\dns_cache.err"
        netstat -abno > "%net%\netstat_abno.txt" 2> "%net%\netstat_abno.err"
        nbtstat -c > "%net%\nbtstat_cache.txt"
        netsh interface ip show config > "%net%\netsh_ip_config.txt"
        netsh advfirewall show allprofiles > "%net%\firewall_profiles.txt"
        netsh winhttp show proxy > "%net%\winhttp_proxy.txt"
        if exist "%SYS%\tcpvcon.exe" "%SYS%\tcpvcon.exe" %EULA% -a -n > "%net%\tcpvcon_full.txt"
    ) else (
        echo %net% directory already exists. passing...
    )

    ::process
    if not exist "%process%" (
        mkdir "%process%"
        set "process=%vol%\_process"
        echo start process_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        powershell.exe -command ps > "%process%\ps.txt"
        tasklist > "%process%\tasklist"
        handle.exe > "%process%\handle_opened_files.txt"
        Listdlls.exe > "%process%\Listdlls.txt"

        :: 추가 프로세스/서비스/드라이버/시스템 정보(동일)
        tasklist /v > "%process%\tasklist_verbose.txt"
        tasklist /svc > "%process%\tasklist_svc.txt"
        sc queryex type= service state= all > "%process%\services_all.txt"
        driverquery /v > "%process%\driverquery_verbose.txt"
        powershell -NoP -C "Get-Process | Sort-Object CPU -Descending | Select-Object -First 50 | Format-Table -AutoSize" > "%process%\top50_cpu.txt"
        powershell -NoP -C "Get-HotFix | Sort-Object InstalledOn | Format-Table -AutoSize" > "%process%\hotfix.txt"
        systeminfo > "%process%\systeminfo.txt"
        tzutil /g > "%process%\timezone.txt"
        schtasks /query /fo LIST /v > "%process%\scheduled_tasks.txt"

        if exist "%SYS%\handle.exe"      "%SYS%\handle.exe" %EULA% -a -u > "%process%\handle_verbose.txt"
        if exist "%SYS%\listdlls.exe"    "%SYS%\listdlls.exe" %EULA% -v > "%process%\listdlls_verbose.txt"
        if exist "%SYS%\autorunsc.exe"   "%SYS%\autorunsc.exe" %EULA% -a * -ct -nobanner -o "%process%\autoruns.csv"
    ) else (
        echo %process% directory already exists. passing...
    )

    ::logonAccount
    if not exist "%logonAccount%" (
        mkdir "%logonAccount%"
        set "logonAccount=%vol%\_logonAccount"
        echo start logonAccount_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        net session > "%logonAccount%\netsession.txt"
        net user > "%logonAccount%\netuser.txt"
        net localgroup > "%logonAccount%\netlocalgroup.txt"
        net localgroup administrators  > "%logonAccount%\netlocalgroupadministrators.txt"
        logonsessions.exe > "%logonAccount%\logonsessions.txt"
        PsLoggedon.exe > "%logonAccount%\PsLoggedon.txt"

        :: 추가 계정/세션/정책(동일)
        whoami /all > "%logonAccount%\whoami_all.txt"
        query user > "%logonAccount%\query_user.txt" 2> "%logonAccount%\query_user.err"
        net accounts > "%logonAccount%\net_accounts.txt"
        if exist "%SYS%\logonsessions.exe" "%SYS%\logonsessions.exe" %EULA% -p > "%logonAccount%\logonsessions_proc.txt"
        if exist "%SYS%\psloggedon.exe"   "%SYS%\psloggedon.exe" %EULA% > "%logonAccount%\psloggedon_full.txt"
    ) else (
        echo %logonAccount% directory already exists. passing...
    )

) else (
    echo %vol% directory already exists. passing...
)

goto REDO
pause

::nonvol
:3
if not exist "%result%" (
    mkdir "%result%"
    echo Created %result% directory. 
    echo START Date: %DATE% Time: %TIME% > _result\log.txt
) else (
    echo %result% directory already exists. passing...
)

if not exist "%prefetch%" (
    mkdir "%prefetch%"
    echo Created %prefetch% directory. 
    echo start prefetch_part at Date: %DATE% Time: %TIME% >> _result\log.txt
    forecopy_handy.exe -p .\_result\_prefetch\
    :: 추가: Prefetch 폴더 직접 백업(보조)
    if exist "%SystemRoot%\Prefetch" robocopy "%SystemRoot%\Prefetch" "%prefetch%\_mirror" %RBOPX% > "%prefetch%\robocopy_prefetch.txt"
) else (
    echo %prefetch% directory already exists. passing...
)

if not exist "%nonvol%" (
    mkdir "%nonvol%"
    echo Created %nonvol% directory.

    ::cache
    if not exist "%cache%" (
        mkdir "%cache%"
        set "cache=%nonvol%\_cache"
        :: set "chromeCache=C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\Cache"
        echo start cache_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        robocopy "C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\Cache" "%cache%" /s /e /z /copy:DAT /r:3 /w:5 /log:"%cache%\robocopy_chrome_cache.txt"

        :: 추가(동일)
        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\*") do (
            if exist "%%~fP\Cache" robocopy "%%~fP\Cache" "%cache%\Chrome_%%~nP_Cache" %RBOPX% > "%cache%\Chrome_%%~nP_Cache.log"
        )
        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\User Data\*") do (
            if exist "%%~fP\Cache" robocopy "%%~fP\Cache" "%cache%\Edge_%%~nP_Cache" %RBOPX% > "%cache%\Edge_%%~nP_Cache.log"
        )
        for /d %%P in ("%APPDATA%\Mozilla\Firefox\Profiles\*") do (
            robocopy "%%~fP" "%cache%\Firefox_%%~nP" %RBOPX% /xd cache2 > "%cache%\Firefox_%%~nP.log"
        )
    ) else (
        echo %cache% directory already exists. passing...
    )

    ::cookie
    if not exist "%cookie%" (
        mkdir "%cookie%"
        set "cookie=%nonvol%\_cookie"
        echo start cookie_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        robocopy "C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default\Network" "%cookie%" /s /e /z /copy:DAT /r:3 /w:5 /log:"%cookie%\cookie.txt"

        :: 추가(동일)
        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\*") do (
            if exist "%%~fP\Network" robocopy "%%~fP\Network" "%cookie%\Chrome_%%~nP_Network" %RBOPX% > "%cookie%\Chrome_%%~nP_Network.log"
        )
        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\User Data\*") do (
            if exist "%%~fP\Network" robocopy "%%~fP\Network" "%cookie%\Edge_%%~nP_Network" %RBOPX% > "%cookie%\Edge_%%~nP_Network.log"
        )
    ) else (
        echo %cookie% directory already exists. passing...
    )

    ::registry
    if not exist "%registry%" (
        mkdir "%registry%"
        echo start registry_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        forecopy_handy.exe -g .\_result\_nonvol\_registry\

        :: 추가: 레지스트리 하이브 스냅샷
        reg save HKLM\SAM        "%registry%\SAM"        /y >nul 2>&1
        reg save HKLM\SYSTEM     "%registry%\SYSTEM"     /y >nul 2>&1
        reg save HKLM\SOFTWARE   "%registry%\SOFTWARE"   /y >nul 2>&1
        reg save HKLM\SECURITY   "%registry%\SECURITY"   /y >nul 2>&1
        reg save HKU\.DEFAULT    "%registry%\DEFAULT"    /y >nul 2>&1
        reg save HKCU            "%registry%\NTUSER.DAT" /y >nul 2>&1
        reg export HKCU\Software "%registry%\HKCU_Software.reg" /y >nul 2>&1
    ) else (
        echo %registry% directory already exists. passing...
    )
    
    ::mft
    if not exist "%mft%" (
        mkdir "%mft%"
        echo start mft_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        forecopy_handy.exe -m .\_result\_nonvol\_mft\

        :: 추가: NTFS/USN 정보
        fsutil fsinfo ntfsinfo %SystemDrive% > "%mft%\ntfsinfo.txt" 2> "%mft%\ntfsinfo.err"
        fsutil usn queryjournal %SystemDrive% > "%mft%\usn_journal_info.txt" 2> "%mft%\usn_journal_info.err"
    ) else (
        echo %mft% directory already exists. passing...
    )

    ::eventlog
    if not exist "%eventLog%" (
        mkdir "%eventLog%"
        echo start eventlog_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        forecopy_handy.exe -e .\_result\_nonvol\_eventlog\

        :: 추가: wevtutil 전체 내보내기
        for /f "delims=" %%L in ('wevtutil el') do (
            wevtutil epl "%%L" "%eventLog%\%%L.evtx" 2>> "%eventLog%\_wevtutil_errors.txt"
        )
    ) else (
        echo %eventLog% directory already exists. passing...
    )
    
    ::recent
    if not exist "%recent%" (
        mkdir "%recent%"
        set "recent=%nonvol%\_recent"
        echo start recent_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        robocopy "%APPDATA%\Microsoft\Office\Recent" "%recent%" /s /e /z /copy:DAT /r:3 /w:5 /log:"%recent%\recent.txt"

        :: 추가: Windows Shell Recent & JumpLists
        robocopy "%APPDATA%\Microsoft\Windows\Recent" "%recent%\ShellRecent" %RBOPX% > "%recent%\ShellRecent.log"
        robocopy "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations" "%recent%\JumpLists_AutoDest" %RBOPX% > "%recent%\JumpLists_AutoDest.log"
        robocopy "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations"     "%recent%\JumpLists_CustomDest" %RBOPX% > "%recent%\JumpLists_CustomDest.log"
    ) else (
        echo %recent% directory already exists. passing...
    )

    ::quicklaunch
    if not exist "%quickLaunch%" (
        mkdir "%quickLaunch%"
        set "quickLaunch=%nonvol%\_quicklaunch"
        echo start quicklaunch_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        robocopy "%APPDATA%\Microsoft\Internet Explorer\Quick Launch" "%quickLaunch%" /s /e /z /copy:DAT /r:3 /w:5 /log:"%quickLaunch%\quicklaunch.txt"

        :: 추가: 작업표시줄 고정 아이콘
        robocopy "%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" "%quickLaunch%\TaskBar" %RBOPX% > "%quickLaunch%\TaskBar.log"
    ) else (
        echo %quickLaunch% directory already exists. passing...
    )
  
) else (
    echo %nonvol% directory already exists. passing...
)

goto REDO
pause

::end
:4
echo Exit the program.
echo END Date: %DATE% Time: %TIME% >> _result\log.txt
exit
pause

::ERROR
:ERROR
echo Invalid input. Check the values you entered.
goto REDO
pause
