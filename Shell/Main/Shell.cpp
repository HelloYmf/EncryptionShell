#include <Windows.h>
#include <string>
#include <iostream>
#include "../PE Module/PeTools.h"
#include <stdio.h>
#include <memoryapi.h>
using namespace std;

//Shell路径
PATH CurrentPath;

//获取当前进程完整路径
PATH GetCurrentPath()
{
	TCHAR exePath[256] = { 0 };
	GetModuleFileName(NULL, exePath, 255);
	PATH Path = exePath;
	return Path;
}

//卸载内存
BOOL UnLoadMem(HANDLE ProcHnd , DWORD BaseAddr)
{
	//定义一个函数指针
	typedef DWORD(__stdcall* pfZwUnmapViewOfSection)(DWORD, DWORD);
	pfZwUnmapViewOfSection ZwUnmapViewOfSection = NULL;
	BOOL res = FALSE;
	//加载DLL
	HMODULE m = LoadLibrary("ntdll.dll");
	if (m) 
	{
		printf("ntdll.dll加载成功\n");
		ZwUnmapViewOfSection = (pfZwUnmapViewOfSection)GetProcAddress(m, "ZwUnmapViewOfSection");
		if (ZwUnmapViewOfSection)
			res = (ZwUnmapViewOfSection((DWORD)ProcHnd, BaseAddr) == 0);
		FreeLibrary(m);
	}
	return res;
}

//分配内存
LPVOID VirtualAllocate(HANDLE hProcess, PVOID pAddress, DWORD size_t)
{
	HMODULE hModuleKernel = LoadLibraryA("kernel32.dll");
	if (!hModuleKernel)
	{
		printf("获取kernel失败\n");
		TerminateProcess(hProcess, 1);
		return NULL;
	}
	typedef void* (__stdcall* pfVirtualAllocEx)(
		HANDLE hProcess,
		LPVOID lpAddress,
		DWORD dwSize,
		DWORD flAllocationType,
		DWORD flProtect);
	pfVirtualAllocEx VirtualAllocEx = NULL;
	VirtualAllocEx = (pfVirtualAllocEx)GetProcAddress((hModuleKernel), "VirtualAllocEx");
	if (!VirtualAllocEx(
		hProcess,
		pAddress,
		size_t,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	))
	{
		//如果不成功, 这里会报487内存访问错误, 很正常, 因为申请源地址有东西
		printf("GetLastError: %d\n", (int)GetLastError());
		//printf("ImageBase被占用, 将随机申请空间. 请修复重定位表");
		LPVOID newImageBase = NULL;
		if ((newImageBase = VirtualAllocEx(
			hProcess,
			NULL,
			size_t,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE
		)))
			return newImageBase;
		printf("没有足够空间");
		return NULL;
	}

	FreeLibrary(hModuleKernel);
	return pAddress;
}

//获取Src的Buffer
VOID GetSrcBuffer(Cbuffer& buffer,DWORD& SrcSize)
{
	//获取自身内存中地址
	HANDLE moudle_address = GetModuleHandle(NULL);
	//获取当前进程完整路径
	CurrentPath = GetCurrentPath();
	//创建一个Shell的PE对象
	PeInstance CurrentPe(moudle_address, 0, 0);
	SrcSize = CurrentPe.GetLastSectionSize();
	buffer.AllocMem(SrcSize);
	//从最后一个节中获取数据，存到buffer中
	CurrentPe.GetDataFromLastSection(buffer, SrcSize);
	buffer.used = SrcSize;
}

//挂起方式创建进程
PROCESS_INFORMATION SuspendedCreatePro(PATH Path)
{
	STARTUPINFO si = { 0 };
	si.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION pi;
	CreateProcess(
		Path.c_str(),
		NULL,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&si,
		&pi
	);
	return pi;
}

//获取上下文
CONTEXT GetContext(HANDLE hThread)
{
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	BOOL ok = ::GetThreadContext(hThread, &context);
	if (ok)
		printf("context获取成功!\n");
	return context;
}

int main()
{
	CurrentPath = GetCurrentPath();
//构建Src的PE对象
	DWORD SrcSize;
	Cbuffer Srcbuffer;
	GetSrcBuffer(Srcbuffer,SrcSize);
	PeInstance SrcPe((HANDLE)Srcbuffer, 1, SrcSize);
	/*PeInstance SrcPe("E:\\Test\\Source\\PeTool.exe",1);
	CurrentPath = GetCurrentPath();*/
//以挂起方式运行Shell进程 
	PROCESS_INFORMATION pi = SuspendedCreatePro(CurrentPath);
//得到主线程的Context
	CONTEXT context = GetContext(pi.hThread);
//获取进程的ImageBase								
	char* baseAddress = (CHAR*)context.Ebx + 8;
	DWORD dwImageBase = 0;
	ReadProcessMemory(pi.hProcess, baseAddress, &dwImageBase, 4, NULL);
//卸载外壳程序的文件镜像
	UnLoadMem(pi.hProcess, dwImageBase);
//获取Src的ImageBase
	char SrcImageBase[256];
	sprintf_s(SrcImageBase, "%x", SrcPe.OptionalHeader->ImageBase);
//分配内存
	LPVOID ProcessMem = VirtualAllocate(pi.hProcess, (PVOID)dwImageBase, SrcPe.OptionalHeader->SizeOfImage);
	//LPVOID ProcessMem = VirtualAllocate(pi.hProcess, (PVOID)SrcPe.OptionalHeader->ImageBase, SrcPe.OptionalHeader->SizeOfImage);
	if (ProcessMem)
	{
		if ( (DWORD)ProcessMem == SrcPe.OptionalHeader->ImageBase )
		{
			printf("申请空间成功!地址为:%x\n",(DWORD)ProcessMem);
		}
		else
		{
			printf("申请空间成功!地址不对.地址为:%x\n", (DWORD)ProcessMem);
			if ( SrcPe.HaveRelocation() )
			{
				//修复重定位表
				SrcPe.FixRelocation((DWORD)ProcessMem);
				printf("修复重定位表成功!\n");
			}
			else
			{
				printf("无重定位表，无需修复!\n");
			}
		}
		//拉伸PE
		SrcPe.ToImageBuffer();
		DWORD WriteBytes = 0;
		BOOL Result = WriteProcessMemory(pi.hProcess, ProcessMem, SrcPe.GetBufferInstance(1), SrcPe.OptionalHeader_Image->SizeOfImage, &WriteBytes);
		if ( Result == FALSE )
		{
			printf("内存写入失败！错误码为：%d\n", GetLastError());
			return 0;
		}
		//修正运行环境的基址和入口地址
		WriteProcessMemory(pi.hProcess, (LPVOID)(context.Ebx + 8), &ProcessMem, 4, NULL);
		context.Eip = (DWORD)ProcessMem + SrcPe.OptionalHeader->AddressOfEntryPoint;
		::SetThreadContext(pi.hThread, &context);
		//(7) 恢复主线程执行
		::ResumeThread(pi.hThread);
		printf("恢复线程执行成功!\n");

		return 0;
	}
	else
	{
		printf("内存分配失败!\n");
		WaitForSingleObject(pi.hProcess, INFINITE);
		WaitForSingleObject(pi.hThread, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 0;
	}
}