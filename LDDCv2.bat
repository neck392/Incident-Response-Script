:: 25.08.21
:: [Live Disk Data Collector] 휘발성과 비휘발성 데이터 수집 개인 업그레이드
:: 이전 개발 스크립트 (https://github.com/Digital-Forensic-Study/LDDC_Batch_script)
@echo off

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
    :: 보조: Prefetch 폴더 직접 백업
    if exist "%SystemRoot%\Prefetch" robocopy "%SystemRoot%\Prefetch" "%prefetch%\_mirror" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%prefetch%\robocopy_prefetch.txt"
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

        :: 추가 네트워크 수집
        ipconfig /all > "%net%\ipconfig_all.txt"
        ipconfig /displaydns > "%net%\dns_cache.txt" 2> "%net%\dns_cache.err"
        netstat -abno > "%net%\netstat_abno.txt" 2> "%net%\netstat_abno.err"
        nbtstat -c > "%net%\nbtstat_cache.txt"
        netsh interface ip show config > "%net%\netsh_ip_config.txt"
        netsh advfirewall show allprofiles > "%net%\firewall_profiles.txt"
        netsh winhttp show proxy > "%net%\winhttp_proxy.txt"
        if exist "%ProgramFiles%\SysinternalsSuite\tcpvcon.exe" "%ProgramFiles%\SysinternalsSuite\tcpvcon.exe" -accepteula -a -n > "%net%\tcpvcon_full.txt"
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

        :: 추가 프로세스/시스템 정보
        tasklist /v > "%process%\tasklist_verbose.txt"
        tasklist /svc > "%process%\tasklist_svc.txt"
        sc queryex type= service state= all > "%process%\services_all.txt"
        driverquery /v > "%process%\driverquery_verbose.txt"
        powershell -NoP -C "Get-Process | Sort-Object CPU -Descending | Select-Object -First 50 | Format-Table -AutoSize" > "%process%\top50_cpu.txt"
        powershell -NoP -C "Get-HotFix | Sort-Object InstalledOn | Format-Table -AutoSize" > "%process%\hotfix.txt"
        systeminfo > "%process%\systeminfo.txt"
        tzutil /g > "%process%\timezone.txt"
        schtasks /query /fo LIST /v > "%process%\scheduled_tasks.txt"

        if exist "%ProgramFiles%\SysinternalsSuite\handle.exe"   "%ProgramFiles%\SysinternalsSuite\handle.exe" -accepteula -a -u > "%process%\handle_verbose.txt"
        if exist "%ProgramFiles%\SysinternalsSuite\listdlls.exe" "%ProgramFiles%\SysinternalsSuite\listdlls.exe" -accepteula -v > "%process%\listdlls_verbose.txt"
        if exist "%ProgramFiles%\SysinternalsSuite\autorunsc.exe" "%ProgramFiles%\SysinternalsSuite\autorunsc.exe" -accepteula -a * -ct -nobanner -o "%process%\autoruns.csv"
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

        :: 추가 계정/세션/정책
        whoami /all > "%logonAccount%\whoami_all.txt"
        query user > "%logonAccount%\query_user.txt" 2> "%logonAccount%\query_user.err"
        net accounts > "%logonAccount%\net_accounts.txt"
        if exist "%ProgramFiles%\SysinternalsSuite\logonsessions.exe" "%ProgramFiles%\SysinternalsSuite\logonsessions.exe" -accepteula -p > "%logonAccount%\logonsessions_proc.txt"
        if exist "%ProgramFiles%\SysinternalsSuite\psloggedon.exe"   "%ProgramFiles%\SysinternalsSuite\psloggedon.exe" -accepteula > "%logonAccount%\psloggedon_full.txt"
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

        :: 멀티 프로필/타 브라우저
        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\*") do (
            if exist "%%~fP\Cache" robocopy "%%~fP\Cache" "%cache%\Chrome_%%~nP_Cache" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%cache%\Chrome_%%~nP_Cache.log"
        )
        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\User Data\*") do (
            if exist "%%~fP\Cache" robocopy "%%~fP\Cache" "%cache%\Edge_%%~nP_Cache" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%cache%\Edge_%%~nP_Cache.log"
        )
        for /d %%P in ("%APPDATA%\Mozilla\Firefox\Profiles\*") do (
            robocopy "%%~fP" "%cache%\Firefox_%%~nP" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T /xd cache2 > "%cache%\Firefox_%%~nP.log"
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

        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\*") do (
            if exist "%%~fP\Network" robocopy "%%~fP\Network" "%cookie%\Chrome_%%~nP_Network" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%cookie%\Chrome_%%~nP_Network.log"
        )
        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\User Data\*") do (
            if exist "%%~fP\Network" robocopy "%%~fP\Network" "%cookie%\Edge_%%~nP_Network" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%cookie%\Edge_%%~nP_Network.log"
        )
    ) else (
        echo %cookie% directory already exists. passing...
    )

    ::registry
    if not exist "%registry%" (
        mkdir "%registry%"
        echo start registry_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        forecopy_handy.exe -g .\_result\_nonvol\_registry\

        :: 레지스트리 하이브 스냅샷
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

        :: NTFS/USN 정보
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

        :: wevtutil로 전체 채널 내보내기(일부 채널은 실패할 수 있으며 오류 로그에 기록)
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

        :: Windows Shell Recent & JumpLists
        robocopy "%APPDATA%\Microsoft\Windows\Recent" "%recent%\ShellRecent" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%recent%\ShellRecent.log"
        robocopy "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations" "%recent%\JumpLists_AutoDest" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%recent%\JumpLists_AutoDest.log"
        robocopy "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations"     "%recent%\JumpLists_CustomDest" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%recent%\JumpLists_CustomDest.log"
    ) else (
        echo %recent% directory already exists. passing...
    )

    ::quicklaunch
    if not exist "%quickLaunch%" (
        mkdir "%quickLaunch%"
        set "quickLaunch=%nonvol%\_quicklaunch"
        echo start quicklaunch_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        robocopy "%APPDATA%\Microsoft\Internet Explorer\Quick Launch" "%quickLaunch%" /s /e /z /copy:DAT /r:3 /w:5 /log:"%quickLaunch%\quicklaunch.txt"

        :: 작업표시줄 고정 아이콘
        robocopy "%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" "%quickLaunch%\TaskBar" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%quickLaunch%\TaskBar.log"
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

        :: 추가 네트워크
        ipconfig /all > "%net%\ipconfig_all.txt"
        ipconfig /displaydns > "%net%\dns_cache.txt" 2> "%net%\dns_cache.err"
        netstat -abno > "%net%\netstat_abno.txt" 2> "%net%\netstat_abno.err"
        nbtstat -c > "%net%\nbtstat_cache.txt"
        netsh interface ip show config > "%net%\netsh_ip_config.txt"
        netsh advfirewall show allprofiles > "%net%\firewall_profiles.txt"
        netsh winhttp show proxy > "%net%\winhttp_proxy.txt"
        if exist "%ProgramFiles%\SysinternalsSuite\tcpvcon.exe" "%ProgramFiles%\SysinternalsSuite\tcpvcon.exe" -accepteula -a -n > "%net%\tcpvcon_full.txt"
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

        :: 추가 프로세스/시스템 정보
        tasklist /v > "%process%\tasklist_verbose.txt"
        tasklist /svc > "%process%\tasklist_svc.txt"
        sc queryex type= service state= all > "%process%\services_all.txt"
        driverquery /v > "%process%\driverquery_verbose.txt"
        powershell -NoP -C "Get-Process | Sort-Object CPU -Descending | Select-Object -First 50 | Format-Table -AutoSize" > "%process%\top50_cpu.txt"
        powershell -NoP -C "Get-HotFix | Sort-Object InstalledOn | Format-Table -AutoSize" > "%process%\hotfix.txt"
        systeminfo > "%process%\systeminfo.txt"
        tzutil /g > "%process%\timezone.txt"
        schtasks /query /fo LIST /v > "%process%\scheduled_tasks.txt"

        if exist "%ProgramFiles%\SysinternalsSuite\handle.exe"   "%ProgramFiles%\SysinternalsSuite\handle.exe" -accepteula -a -u > "%process%\handle_verbose.txt"
        if exist "%ProgramFiles%\SysinternalsSuite\listdlls.exe" "%ProgramFiles%\SysinternalsSuite\listdlls.exe" -accepteula -v > "%process%\listdlls_verbose.txt"
        if exist "%ProgramFiles%\SysinternalsSuite\autorunsc.exe" "%ProgramFiles%\SysinternalsSuite\autorunsc.exe" -accepteula -a * -ct -nobanner -o "%process%\autoruns.csv"
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

        :: 추가 계정/세션/정책
        whoami /all > "%logonAccount%\whoami_all.txt"
        query user > "%logonAccount%\query_user.txt" 2> "%logonAccount%\query_user.err"
        net accounts > "%logonAccount%\net_accounts.txt"
        if exist "%ProgramFiles%\SysinternalsSuite\logonsessions.exe" "%ProgramFiles%\SysinternalsSuite\logonsessions.exe" -accepteula -p > "%logonAccount%\logonsessions_proc.txt"
        if exist "%ProgramFiles%\SysinternalsSuite\psloggedon.exe"   "%ProgramFiles%\SysinternalsSuite\psloggedon.exe" -accepteula > "%logonAccount%\psloggedon_full.txt"
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
    if exist "%SystemRoot%\Prefetch" robocopy "%SystemRoot%\Prefetch" "%prefetch%\_mirror" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%prefetch%\robocopy_prefetch.txt"
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

        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\*") do (
            if exist "%%~fP\Cache" robocopy "%%~fP\Cache" "%cache%\Chrome_%%~nP_Cache" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%cache%\Chrome_%%~nP_Cache.log"
        )
        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\User Data\*") do (
            if exist "%%~fP\Cache" robocopy "%%~fP\Cache" "%cache%\Edge_%%~nP_Cache" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%cache%\Edge_%%~nP_Cache.log"
        )
        for /d %%P in ("%APPDATA%\Mozilla\Firefox\Profiles\*") do (
            robocopy "%%~fP" "%cache%\Firefox_%%~nP" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T /xd cache2 > "%cache%\Firefox_%%~nP.log"
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

        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\*") do (
            if exist "%%~fP\Network" robocopy "%%~fP\Network" "%cookie%\Chrome_%%~nP_Network" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%cookie%\Chrome_%%~nP_Network.log"
        )
        for /d %%P in ("C:\Users\%USERNAME%\AppData\Local\Microsoft\Edge\User Data\*") do (
            if exist "%%~fP\Network" robocopy "%%~fP\Network" "%cookie%\Edge_%%~nP_Network" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%cookie%\Edge_%%~nP_Network.log"
        )
    ) else (
        echo %cookie% directory already exists. passing...
    )

    ::registry
    if not exist "%registry%" (
        mkdir "%registry%"
        echo start registry_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        forecopy_handy.exe -g .\_result\_nonvol\_registry\

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

        robocopy "%APPDATA%\Microsoft\Windows\Recent" "%recent%\ShellRecent" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%recent%\ShellRecent.log"
        robocopy "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations" "%recent%\JumpLists_AutoDest" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%recent%\JumpLists_AutoDest.log"
        robocopy "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations"     "%recent%\JumpLists_CustomDest" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%recent%\JumpLists_CustomDest.log"
    ) else (
        echo %recent% directory already exists. passing...
    )

    ::quicklaunch
    if not exist "%quickLaunch%" (
        mkdir "%quickLaunch%"
        set "quickLaunch=%nonvol%\_quicklaunch"
        echo start quicklaunch_part at Date: %DATE% Time: %TIME% >> _result\log.txt
        robocopy "%APPDATA%\Microsoft\Internet Explorer\Quick Launch" "%quickLaunch%" /s /e /z /copy:DAT /r:3 /w:5 /log:"%quickLaunch%\quicklaunch.txt"

        robocopy "%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar" "%quickLaunch%\TaskBar" /s /e /z /copy:DAT /r:3 /w:5 /DCOPY:T > "%quickLaunch%\TaskBar.log"
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
