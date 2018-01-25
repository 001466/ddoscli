@echo off


rem Copy all files to "C:\ECSharp"
xcopy src\pthreadGC2.dll "C:\ECSharp\" /y
xcopy src\libgcc_s_dw2-1.dll "C:\ECSharp\" /y
xcopy src\libstdc++-6.dll "C:\ECSharp\" /y

xcopy src\ecs.exe "C:\ECSharp\" /y



rem Setup WinPcap
echo Setup WinPcap...
src\WinPcap_4_1_3

rem Add directory to system environment
setx path "%path%;C:\ECSharp"


pause
