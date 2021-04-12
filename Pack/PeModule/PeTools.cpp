#include "PeTools.h"

PeInstance::PeInstance(HANDLE PeAddr, int flag, size_t fileSize)
{
	//获取各种指针
	PBYTE pTemp = (PBYTE)PeAddr;
	DosHeader = (PIMAGE_DOS_HEADER)pTemp;					//获取DOS头
	pTemp = pTemp + ((PIMAGE_DOS_HEADER)pTemp)->e_lfanew;	//偏移到NT头
	NtHeader = (PIMAGE_NT_HEADERS)pTemp;					//获取NT头
	pTemp = pTemp + 0x4;									//偏移到标准PE头
	FileHeader = (PIMAGE_FILE_HEADER)pTemp;					//获取标准PE头
	pTemp = pTemp + 0x14;									//偏移到可选PE头
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pTemp;			//获取可选PE头
	pTemp = pTemp + FileHeader->SizeOfOptionalHeader;		//偏移到节表
	pSectionHeader = (PIMAGE_SECTION_HEADER)pTemp;			//获取节表
	if (flag == 0)
	{
		InitWay = 0;
		FileSize = OptionalHeader->SizeOfImage;
		//填充ImageBuffer
		ImageBuffer.AllocMem(OptionalHeader->SizeOfImage);
		ImageBuffer.used = OptionalHeader->SizeOfImage;
		memcpy(ImageBuffer, (PBYTE)PeAddr, OptionalHeader->SizeOfImage);
	}
	else
	{
		InitWay = 1;
		FileSize = fileSize;
		//填充FileBuffer
		FileBuffer.AllocMem(fileSize);
		FileBuffer.used = fileSize;
		memcpy(FileBuffer, (PBYTE)PeAddr, fileSize);
	}
}

PeInstance::PeInstance(PATH path)
{
	InitWay = 1;
	//打开PE文件
	Cfile PeFile(path);
	FileSize = PeFile.size();
	//写入FileBuffer
	FileBuffer.AllocMem(FileSize);
	FileBuffer.used = FileSize;
	PeFile >> FileBuffer;
	//获取各种指针
	PBYTE pTemp = FileBuffer;
	DosHeader = (PIMAGE_DOS_HEADER)pTemp;					//获取DOS头
	pTemp = pTemp + ((PIMAGE_DOS_HEADER)pTemp)->e_lfanew;	//偏移到NT头
	NtHeader = (PIMAGE_NT_HEADERS)pTemp;					//获取NT头
	pTemp = pTemp + 0x4;									//偏移到标准PE头
	FileHeader = (PIMAGE_FILE_HEADER)pTemp;					//获取标准PE头
	pTemp = pTemp + 0x14;									//偏移到可选PE头
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pTemp;			//获取可选PE头
	pTemp = pTemp + FileHeader->SizeOfOptionalHeader;		//偏移到节表
	pSectionHeader = (PIMAGE_SECTION_HEADER)pTemp;			//获取节表
}

BOOL PeInstance::AddSeaction(size_t SectionSize)
{
	//新增节名字
	BYTE NewSectionName[] = "Fly";				
	//申请一块新的FileBuffer
	NewBuffer.AllocMem(FileSize + Align(SectionSize, OptionalHeader->FileAlignment));
	//把原来的内容拷贝过来
	NewBuffer.used = FileSize + Align(SectionSize, OptionalHeader->FileAlignment);
	NewBuffer.copy_from(FileBuffer, FileSize);
	
	PBYTE pTemp = NewBuffer;
	//更新所有指针
	PBYTE pNewBuffer = NewBuffer;
	DosHeader = (PIMAGE_DOS_HEADER)pNewBuffer;					//获取DOS头
	pNewBuffer = pNewBuffer + DosHeader->e_lfanew;				//偏移到NT头
	NtHeader = (PIMAGE_NT_HEADERS)pNewBuffer;					//获取NT头
	pNewBuffer = pNewBuffer + 0x4;								//偏移到标准PE头
	FileHeader = (PIMAGE_FILE_HEADER)pNewBuffer;				//获取标准PE头
	pNewBuffer = pNewBuffer + 0x14;								//偏移到可选PE头
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pNewBuffer;		//获取可选PE头
	pNewBuffer = pNewBuffer + FileHeader->SizeOfOptionalHeader;	//偏移到节表
	pSectionHeader = (PIMAGE_SECTION_HEADER)pNewBuffer;			//获取节表
	//判断节表空间是否充足
	if (OptionalHeader->SizeOfHeaders - (DWORD)(&(pSectionHeader[FileHeader->NumberOfSections]) - (DWORD)(NewBuffer)) < 0x50)
	{
		printf("节表空间不足！\n");
		PromoteHeaders();	//提升所有头+节表
	}
	//偏移到要添加节表的位置
	pNewBuffer = (PBYTE)(pTemp + (DWORD)(&pSectionHeader[FileHeader->NumberOfSections]) - (DWORD)(pTemp));
	//后面填充一个全0结构
	memset(pNewBuffer + 0x28, 0x0, 0x28);
	//设置节表内容
	for (int i = 0; i < strlen((char*)NewSectionName); i++)	//设置节表名字
		((PBYTE)((PIMAGE_SECTION_HEADER)pNewBuffer)->Name)[i] = NewSectionName[i];
	((PBYTE)((PIMAGE_SECTION_HEADER)pNewBuffer)->Name)[strlen((char*)NewSectionName)] = 0x0;
	((PIMAGE_SECTION_HEADER)pNewBuffer)->Misc.VirtualSize = Align(SectionSize,OptionalHeader->SectionAlignment);	//设置内存中大小
	DWORD MaxSize = pSectionHeader[FileHeader->NumberOfSections - 1].SizeOfRawData > pSectionHeader[FileHeader->NumberOfSections - 1].Misc.VirtualSize ?
		pSectionHeader[FileHeader->NumberOfSections - 1].SizeOfRawData : pSectionHeader[FileHeader->NumberOfSections - 1].Misc.VirtualSize;
	DWORD SizeOfData = Align(MaxSize, OptionalHeader->SectionAlignment);
	((PIMAGE_SECTION_HEADER)pNewBuffer)->VirtualAddress = pSectionHeader[FileHeader->NumberOfSections - 1].VirtualAddress + SizeOfData;	//设置内存中偏移
	((PIMAGE_SECTION_HEADER)pNewBuffer)->SizeOfRawData = Align(SectionSize,OptionalHeader->FileAlignment);	//设置文件中大小
	((PIMAGE_SECTION_HEADER)pNewBuffer)->PointerToRawData = pSectionHeader[FileHeader->NumberOfSections - 1].PointerToRawData + pSectionHeader[FileHeader->NumberOfSections - 1].SizeOfRawData;	//设置文件中偏移
	for (int i = 0; i < FileHeader->NumberOfSections - 1; i++)
	{
		((PIMAGE_SECTION_HEADER)pNewBuffer)->Characteristics = ((PIMAGE_SECTION_HEADER)pNewBuffer)->Characteristics | pSectionHeader[i].Characteristics;	//设置属性
	}
	//修改节表的数量
	FileHeader->NumberOfSections++;
	//设置节的内容
	memset((PBYTE)pTemp + pSectionHeader[FileHeader->NumberOfSections - 1].PointerToRawData, 0x7, Align(SectionSize, OptionalHeader->FileAlignment));
	//修改SizeOfImage
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
			//保存FileBuffer
			NewFile << FileBuffer;
		}
		case 1:
		{
			//保存ImageBuffer
			NewFile << ImageBuffer;
		}
		case 2:
		{
			//保存NewBuffer
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

	//判断是否在头+节表中
	if (dwRva <= OptionalHeader->SizeOfHeaders)
	{
		dwFoa = dwRva;
		return dwFoa;
	}

	//判断在是否在节中
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

	//判断是否在头+节表中
	if (dwFoa <= OptionalHeader->SizeOfHeaders)
	{
		dwRva = dwFoa;
		return dwRva;
	}

	//判断是否在节中
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
	//拷贝所有头+节表
	for (DWORD i = 0; i < SizeOfCopy; i++)
	{
		(pFileBuffer + 0x40)[i] = (pFileBuffer + DosHeader->e_lfanew)[i];
	}
	//填充
	memset((pFileBuffer + 0x40 + SizeOfCopy), 0x0, FillSize);
	//修正e_lfanew
	DosHeader->e_lfanew = 0x40;
	//重新修正所有头+节表指针
	pTemp = pTemp + DosHeader->e_lfanew;						//偏移到NT头
	NtHeader = (PIMAGE_NT_HEADERS)pTemp;						//获取NT头
	pTemp = pTemp + 0x4;										//偏移到标准PE头
	FileHeader = (PIMAGE_FILE_HEADER)pTemp;						//获取标准PE头
	pTemp = pTemp + 0x14;										//偏移到可选PE头
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pTemp;				//获取可选PE头
	pTemp = pTemp + FileHeader->SizeOfOptionalHeader;			//偏移到节表
	pSectionHeader = (PIMAGE_SECTION_HEADER)pTemp;				//获取节表
	return TRUE;
}
