#include <Windows.h>
#include <string>
#include <iostream>
#include "../PE Module/PeTools.h"
#include <stdio.h>
#include <memoryapi.h>
using namespace std;

//Shell·��
PATH CurrentPath;

//��ȡ��ǰ��������·��
PATH GetCurrentPath()
{
	TCHAR exePath[256] = { 0 };
	GetModuleFileName(NULL, exePath, 255);
	PATH Path = exePath;
	return Path;
}

//ж���ڴ�
BOOL UnLoadMem(HANDLE ProcHnd , DWORD BaseAddr)
{
	//����һ������ָ��
	typedef DWORD(__stdcall* pfZwUnmapViewOfSection)(DWORD, DWORD);
	pfZwUnmapViewOfSection ZwUnmapViewOfSection = NULL;
	BOOL res = FALSE;
	//����DLL
	HMODULE m = LoadLibrary("ntdll.dll");
	if (m) 
	{
		printf("ntdll.dll���سɹ�\n");
		ZwUnmapViewOfSection = (pfZwUnmapViewOfSection)GetProcAddress(m, "ZwUnmapViewOfSection");
		if (ZwUnmapViewOfSection)
			res = (ZwUnmapViewOfSection((DWORD)ProcHnd, BaseAddr) == 0);
		FreeLibrary(m);
	}
	return res;
}

//�����ڴ�
LPVOID VirtualAllocate(HANDLE hProcess, PVOID pAddress, DWORD size_t)
{
	HMODULE hModuleKernel = LoadLibraryA("kernel32.dll");
	if (!hModuleKernel)
	{
		printf("��ȡkernelʧ��\n");
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
		//������ɹ�, ����ᱨ487�ڴ���ʴ���, ������, ��Ϊ����Դ��ַ�ж���
		printf("GetLastError: %d\n", (int)GetLastError());
		//printf("ImageBase��ռ��, ���������ռ�. ���޸��ض�λ��");
		LPVOID newImageBase = NULL;
		if ((newImageBase = VirtualAllocEx(
			hProcess,
			NULL,
			size_t,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE
		)))
			return newImageBase;
		printf("û���㹻�ռ�");
		return NULL;
	}

	FreeLibrary(hModuleKernel);
	return pAddress;
}

//��ȡSrc��Buffer
VOID GetSrcBuffer(Cbuffer& buffer,DWORD& SrcSize)
{
	//��ȡ�����ڴ��е�ַ
	HANDLE moudle_address = GetModuleHandle(NULL);
	//��ȡ��ǰ��������·��
	CurrentPath = GetCurrentPath();
	//����һ��Shell��PE����
	PeInstance CurrentPe(moudle_address, 0, 0);
	SrcSize = CurrentPe.GetLastSectionSize();
	buffer.AllocMem(SrcSize);
	//�����һ�����л�ȡ���ݣ��浽buffer��
	CurrentPe.GetDataFromLastSection(buffer, SrcSize);
	buffer.used = SrcSize;
}

//����ʽ��������
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

//��ȡ������
CONTEXT GetContext(HANDLE hThread)
{
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	BOOL ok = ::GetThreadContext(hThread, &context);
	if (ok)
		printf("context��ȡ�ɹ�!\n");
	return context;
}

int main()
{
	CurrentPath = GetCurrentPath();
//����Src��PE����
	DWORD SrcSize;
	Cbuffer Srcbuffer;
	GetSrcBuffer(Srcbuffer,SrcSize);
	PeInstance SrcPe((HANDLE)Srcbuffer, 1, SrcSize);
	/*PeInstance SrcPe("E:\\Test\\Source\\PeTool.exe",1);
	CurrentPath = GetCurrentPath();*/
//�Թ���ʽ����Shell���� 
	PROCESS_INFORMATION pi = SuspendedCreatePro(CurrentPath);
//�õ����̵߳�Context
	CONTEXT context = GetContext(pi.hThread);
//��ȡ���̵�ImageBase								
	char* baseAddress = (CHAR*)context.Ebx + 8;
	DWORD dwImageBase = 0;
	ReadProcessMemory(pi.hProcess, baseAddress, &dwImageBase, 4, NULL);
//ж����ǳ�����ļ�����
	UnLoadMem(pi.hProcess, dwImageBase);
//��ȡSrc��ImageBase
	char SrcImageBase[256];
	sprintf_s(SrcImageBase, "%x", SrcPe.OptionalHeader->ImageBase);
//�����ڴ�
	LPVOID ProcessMem = VirtualAllocate(pi.hProcess, (PVOID)dwImageBase, SrcPe.OptionalHeader->SizeOfImage);
	//LPVOID ProcessMem = VirtualAllocate(pi.hProcess, (PVOID)SrcPe.OptionalHeader->ImageBase, SrcPe.OptionalHeader->SizeOfImage);
	if (ProcessMem)
	{
		if ( (DWORD)ProcessMem == SrcPe.OptionalHeader->ImageBase )
		{
			printf("����ռ�ɹ�!��ַΪ:%x\n",(DWORD)ProcessMem);
		}
		else
		{
			printf("����ռ�ɹ�!��ַ����.��ַΪ:%x\n", (DWORD)ProcessMem);
			if ( SrcPe.HaveRelocation() )
			{
				//�޸��ض�λ��
				SrcPe.FixRelocation((DWORD)ProcessMem);
				printf("�޸��ض�λ��ɹ�!\n");
			}
			else
			{
				printf("���ض�λ�������޸�!\n");
			}
		}
		//����PE
		SrcPe.ToImageBuffer();
		DWORD WriteBytes = 0;
		BOOL Result = WriteProcessMemory(pi.hProcess, ProcessMem, SrcPe.GetBufferInstance(1), SrcPe.OptionalHeader_Image->SizeOfImage, &WriteBytes);
		if ( Result == FALSE )
		{
			printf("�ڴ�д��ʧ�ܣ�������Ϊ��%d\n", GetLastError());
			return 0;
		}
		//�������л����Ļ�ַ����ڵ�ַ
		WriteProcessMemory(pi.hProcess, (LPVOID)(context.Ebx + 8), &ProcessMem, 4, NULL);
		context.Eip = (DWORD)ProcessMem + SrcPe.OptionalHeader->AddressOfEntryPoint;
		::SetThreadContext(pi.hThread, &context);
		//(7) �ָ����߳�ִ��
		::ResumeThread(pi.hThread);
		printf("�ָ��߳�ִ�гɹ�!\n");

		return 0;
	}
	else
	{
		printf("�ڴ����ʧ��!\n");
		WaitForSingleObject(pi.hProcess, INFINITE);
		WaitForSingleObject(pi.hThread, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 0;
	}
}