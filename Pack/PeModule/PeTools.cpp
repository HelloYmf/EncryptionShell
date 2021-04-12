#include "PeTools.h"

PeInstance::PeInstance(HANDLE PeAddr, int flag, size_t fileSize)
{
	//��ȡ����ָ��
	PBYTE pTemp = (PBYTE)PeAddr;
	DosHeader = (PIMAGE_DOS_HEADER)pTemp;					//��ȡDOSͷ
	pTemp = pTemp + ((PIMAGE_DOS_HEADER)pTemp)->e_lfanew;	//ƫ�Ƶ�NTͷ
	NtHeader = (PIMAGE_NT_HEADERS)pTemp;					//��ȡNTͷ
	pTemp = pTemp + 0x4;									//ƫ�Ƶ���׼PEͷ
	FileHeader = (PIMAGE_FILE_HEADER)pTemp;					//��ȡ��׼PEͷ
	pTemp = pTemp + 0x14;									//ƫ�Ƶ���ѡPEͷ
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pTemp;			//��ȡ��ѡPEͷ
	pTemp = pTemp + FileHeader->SizeOfOptionalHeader;		//ƫ�Ƶ��ڱ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)pTemp;			//��ȡ�ڱ�
	if (flag == 0)
	{
		InitWay = 0;
		FileSize = OptionalHeader->SizeOfImage;
		//���ImageBuffer
		ImageBuffer.AllocMem(OptionalHeader->SizeOfImage);
		ImageBuffer.used = OptionalHeader->SizeOfImage;
		memcpy(ImageBuffer, (PBYTE)PeAddr, OptionalHeader->SizeOfImage);
	}
	else
	{
		InitWay = 1;
		FileSize = fileSize;
		//���FileBuffer
		FileBuffer.AllocMem(fileSize);
		FileBuffer.used = fileSize;
		memcpy(FileBuffer, (PBYTE)PeAddr, fileSize);
	}
}

PeInstance::PeInstance(PATH path)
{
	InitWay = 1;
	//��PE�ļ�
	Cfile PeFile(path);
	FileSize = PeFile.size();
	//д��FileBuffer
	FileBuffer.AllocMem(FileSize);
	FileBuffer.used = FileSize;
	PeFile >> FileBuffer;
	//��ȡ����ָ��
	PBYTE pTemp = FileBuffer;
	DosHeader = (PIMAGE_DOS_HEADER)pTemp;					//��ȡDOSͷ
	pTemp = pTemp + ((PIMAGE_DOS_HEADER)pTemp)->e_lfanew;	//ƫ�Ƶ�NTͷ
	NtHeader = (PIMAGE_NT_HEADERS)pTemp;					//��ȡNTͷ
	pTemp = pTemp + 0x4;									//ƫ�Ƶ���׼PEͷ
	FileHeader = (PIMAGE_FILE_HEADER)pTemp;					//��ȡ��׼PEͷ
	pTemp = pTemp + 0x14;									//ƫ�Ƶ���ѡPEͷ
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pTemp;			//��ȡ��ѡPEͷ
	pTemp = pTemp + FileHeader->SizeOfOptionalHeader;		//ƫ�Ƶ��ڱ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)pTemp;			//��ȡ�ڱ�
}

BOOL PeInstance::AddSeaction(size_t SectionSize)
{
	//����������
	BYTE NewSectionName[] = "Fly";				
	//����һ���µ�FileBuffer
	NewBuffer.AllocMem(FileSize + Align(SectionSize, OptionalHeader->FileAlignment));
	//��ԭ�������ݿ�������
	NewBuffer.used = FileSize + Align(SectionSize, OptionalHeader->FileAlignment);
	NewBuffer.copy_from(FileBuffer, FileSize);
	
	PBYTE pTemp = NewBuffer;
	//��������ָ��
	PBYTE pNewBuffer = NewBuffer;
	DosHeader = (PIMAGE_DOS_HEADER)pNewBuffer;					//��ȡDOSͷ
	pNewBuffer = pNewBuffer + DosHeader->e_lfanew;				//ƫ�Ƶ�NTͷ
	NtHeader = (PIMAGE_NT_HEADERS)pNewBuffer;					//��ȡNTͷ
	pNewBuffer = pNewBuffer + 0x4;								//ƫ�Ƶ���׼PEͷ
	FileHeader = (PIMAGE_FILE_HEADER)pNewBuffer;				//��ȡ��׼PEͷ
	pNewBuffer = pNewBuffer + 0x14;								//ƫ�Ƶ���ѡPEͷ
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pNewBuffer;		//��ȡ��ѡPEͷ
	pNewBuffer = pNewBuffer + FileHeader->SizeOfOptionalHeader;	//ƫ�Ƶ��ڱ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)pNewBuffer;			//��ȡ�ڱ�
	//�жϽڱ�ռ��Ƿ����
	if (OptionalHeader->SizeOfHeaders - (DWORD)(&(pSectionHeader[FileHeader->NumberOfSections]) - (DWORD)(NewBuffer)) < 0x50)
	{
		printf("�ڱ�ռ䲻�㣡\n");
		PromoteHeaders();	//��������ͷ+�ڱ�
	}
	//ƫ�Ƶ�Ҫ��ӽڱ��λ��
	pNewBuffer = (PBYTE)(pTemp + (DWORD)(&pSectionHeader[FileHeader->NumberOfSections]) - (DWORD)(pTemp));
	//�������һ��ȫ0�ṹ
	memset(pNewBuffer + 0x28, 0x0, 0x28);
	//���ýڱ�����
	for (int i = 0; i < strlen((char*)NewSectionName); i++)	//���ýڱ�����
		((PBYTE)((PIMAGE_SECTION_HEADER)pNewBuffer)->Name)[i] = NewSectionName[i];
	((PBYTE)((PIMAGE_SECTION_HEADER)pNewBuffer)->Name)[strlen((char*)NewSectionName)] = 0x0;
	((PIMAGE_SECTION_HEADER)pNewBuffer)->Misc.VirtualSize = Align(SectionSize,OptionalHeader->SectionAlignment);	//�����ڴ��д�С
	DWORD MaxSize = pSectionHeader[FileHeader->NumberOfSections - 1].SizeOfRawData > pSectionHeader[FileHeader->NumberOfSections - 1].Misc.VirtualSize ?
		pSectionHeader[FileHeader->NumberOfSections - 1].SizeOfRawData : pSectionHeader[FileHeader->NumberOfSections - 1].Misc.VirtualSize;
	DWORD SizeOfData = Align(MaxSize, OptionalHeader->SectionAlignment);
	((PIMAGE_SECTION_HEADER)pNewBuffer)->VirtualAddress = pSectionHeader[FileHeader->NumberOfSections - 1].VirtualAddress + SizeOfData;	//�����ڴ���ƫ��
	((PIMAGE_SECTION_HEADER)pNewBuffer)->SizeOfRawData = Align(SectionSize,OptionalHeader->FileAlignment);	//�����ļ��д�С
	((PIMAGE_SECTION_HEADER)pNewBuffer)->PointerToRawData = pSectionHeader[FileHeader->NumberOfSections - 1].PointerToRawData + pSectionHeader[FileHeader->NumberOfSections - 1].SizeOfRawData;	//�����ļ���ƫ��
	for (int i = 0; i < FileHeader->NumberOfSections - 1; i++)
	{
		((PIMAGE_SECTION_HEADER)pNewBuffer)->Characteristics = ((PIMAGE_SECTION_HEADER)pNewBuffer)->Characteristics | pSectionHeader[i].Characteristics;	//��������
	}
	//�޸Ľڱ������
	FileHeader->NumberOfSections++;
	//���ýڵ�����
	memset((PBYTE)pTemp + pSectionHeader[FileHeader->NumberOfSections - 1].PointerToRawData, 0x7, Align(SectionSize, OptionalHeader->FileAlignment));
	//�޸�SizeOfImage
	OptionalHeader->SizeOfImage = OptionalHeader->SizeOfImage + Align(SectionSize, OptionalHeader->SectionAlignment);

	return TRUE;
}

BOOL PeInstance::AddDataToNewSection(Cbuffer& SrcBuffer,size_t SrcSize)
{
	NewBuffer.copy_from(SrcBuffer, SrcSize, pSectionHeader[FileHeader->NumberOfSections - 1].PointerToRawData);

	return TRUE;
}

BOOL PeInstance::GetDataFromLastSection(Cbuffer& DesBuffer, size_t DesSize)
{
	switch (InitWay)
	{
		case 0:
		{
			memcpy(DesBuffer,
				(PBYTE)((DWORD)FileBuffer + pSectionHeader[FileHeader->NumberOfSections - 1].VirtualAddress),
				DesSize);
			break;
		}
		case 1:
		{
			memcpy(DesBuffer,
				(PBYTE)((DWORD)FileBuffer + pSectionHeader[FileHeader->NumberOfSections - 1].PointerToRawData),
				DesSize);
			break;
		}
	}

	return TRUE;
}

DWORD PeInstance::GetLastSectionSize()
{
	switch (InitWay)
	{
		case 0:
			return pSectionHeader[FileHeader->NumberOfSections - 1].Misc.VirtualSize;
		case 1:
			return pSectionHeader[FileHeader->NumberOfSections - 1].SizeOfRawData;
	}

}

BOOL PeInstance::Save(PATH path, int Flag)
{
	Cfile NewFile(path);
	switch (Flag)
	{
		case 0:
		{
			//����FileBuffer
			NewFile << FileBuffer;
		}
		case 1:
		{
			//����ImageBuffer
			NewFile << ImageBuffer;
		}
		case 2:
		{
			//����NewBuffer
			NewFile << NewBuffer;
		}
	}

	return TRUE;
}

size_t PeInstance::GetSize()
{
	return FileSize;
}

Cbuffer& PeInstance::GetBufferInstance()
{
	if (NewBuffer)
		return NewBuffer;
	else
		return FileBuffer;
}

int PeInstance::Align(int Value, int align)
{
	{
		if (Value % align == 0)
		{
			return Value;
		}
		return ((Value / align) + 1) * align;
	}
}

DWORD PeInstance::RvaToFoa(DWORD dwRva)
{
	DWORD dwFoa = 0;

	//�ж��Ƿ���ͷ+�ڱ���
	if (dwRva <= OptionalHeader->SizeOfHeaders)
	{
		dwFoa = dwRva;
		return dwFoa;
	}

	//�ж����Ƿ��ڽ���
	int i;
	for (i = 0; i < FileHeader->NumberOfSections; i++)
	{
		if (dwRva >= pSectionHeader[i].VirtualAddress && dwRva <= (pSectionHeader[i].VirtualAddress + pSectionHeader[i].SizeOfRawData))
		{
			dwFoa = dwRva - pSectionHeader[i].VirtualAddress;
			return dwFoa + pSectionHeader[i].PointerToRawData;
		}
	}
}

DWORD PeInstance::FoaToRva(DWORD dwFoa)
{
	DWORD dwRva = 0;

	//�ж��Ƿ���ͷ+�ڱ���
	if (dwFoa <= OptionalHeader->SizeOfHeaders)
	{
		dwRva = dwFoa;
		return dwRva;
	}

	//�ж��Ƿ��ڽ���
	int i = 0;
	for (i = 0; i < FileHeader->NumberOfSections; i++)
	{
		if (dwFoa >= pSectionHeader[i].PointerToRawData && dwFoa <= (pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData))
		{
			dwRva = dwFoa - pSectionHeader[i].PointerToRawData;
			return dwRva + pSectionHeader[i].VirtualAddress;
		}
	}
}

BOOL PeInstance::PromoteHeaders()
{
	PBYTE pTemp = NewBuffer;
	PBYTE pFileBuffer = NewBuffer;
	DWORD SizeOfCopy = (DWORD)(&pSectionHeader[FileHeader->NumberOfSections]) - (DWORD)(pFileBuffer + DosHeader->e_lfanew);
	DWORD FillSize = (DWORD)(&pSectionHeader[FileHeader->NumberOfSections]) - (DWORD)pFileBuffer - 0x40 - SizeOfCopy;
	//��������ͷ+�ڱ�
	for (DWORD i = 0; i < SizeOfCopy; i++)
	{
		(pFileBuffer + 0x40)[i] = (pFileBuffer + DosHeader->e_lfanew)[i];
	}
	//���
	memset((pFileBuffer + 0x40 + SizeOfCopy), 0x0, FillSize);
	//����e_lfanew
	DosHeader->e_lfanew = 0x40;
	//������������ͷ+�ڱ�ָ��
	pTemp = pTemp + DosHeader->e_lfanew;						//ƫ�Ƶ�NTͷ
	NtHeader = (PIMAGE_NT_HEADERS)pTemp;						//��ȡNTͷ
	pTemp = pTemp + 0x4;										//ƫ�Ƶ���׼PEͷ
	FileHeader = (PIMAGE_FILE_HEADER)pTemp;						//��ȡ��׼PEͷ
	pTemp = pTemp + 0x14;										//ƫ�Ƶ���ѡPEͷ
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pTemp;				//��ȡ��ѡPEͷ
	pTemp = pTemp + FileHeader->SizeOfOptionalHeader;			//ƫ�Ƶ��ڱ�
	pSectionHeader = (PIMAGE_SECTION_HEADER)pTemp;				//��ȡ�ڱ�
	return TRUE;
}
