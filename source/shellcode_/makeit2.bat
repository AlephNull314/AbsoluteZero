@echo off

%masm32%\bin\ml /c /coff "shellcode.asm"
%masm32%\bin\Link /SUBSYSTEM:CONSOLE /OPT:NOREF "shellcode.obj"
pause
