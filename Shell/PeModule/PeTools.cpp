#include "PeTools.h"

PeInstance::PeInstance(HANDLE PeAddr, int flag ,size_t fileSize)
{
	//获取各种指针
	PBYTE pTemp = (PBYTE)PeAddr;
	DosHeader = (PIMAGE_DOS_HEADER)pTemp;							//获取DOS头
	pTemp = pTemp + ((PIMAGE_DOS_HEADER)pTemp)->e_lfanew;			//偏移到NT头
	NtHeader = (PIMAGE_NT_HEADERS)pTemp;							//获取NT头
	pTemp = pTemp + 0x4;											//偏移到标准PE头
	FileHeader = (PIMAGE_FILE_HEADER)pTemp;							//获取标准PE头
	pTemp = pTemp + 0x14;											//偏移到可选PE头
	OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pTemp;					//获取可选PE头
	pTemp = pTemp + FileHeader->SizeOfOptionalHeader;				//偏移到节表
	pSectionHeader = (PIMAGE_SECTION_HEADER)pTemp;					//获取节表

	if (flag == 0)
	{
		InitWay = 0;
		FileSize = OptionalHeader->SizeOfImage;
		//填充内存缓冲区
		ImageBuffer.AllocMem(OptionalHeader->SizeOfImage);
		ImageBuffer.used = OptionalHeader->SizeOfImage;
		memcpy(ImageBuffer, (PBYTE)PeAddr, OptionalHeader->SizeOfImage);

		//获取各种指针
		PBYTE pImageTemp = (PBYTE)ImageBuffer;
		DosHeader_Image = (PIMAGE_DOS_HEADER)pImageTemp;					//获取DOS头
		pImageTemp = pImageTemp + ((PIMAGE_DOS_HEADER)pImageTemp)->e_lfanew;	//偏移到NT头
		NtHeader_Image = (PIMAGE_NT_HEADERS)pImageTemp;					//获取NT头
		pImageTemp = pImageTemp + 0x4;									//偏移到标准PE头
		FileHeader_Image = (PIMAGE_FILE_HEADER)pImageTemp;					//获取标准PE头
		pImageTemp = pImageTemp + 0x14;									//偏移到可选PE头
		OptionalHeader_Image = (PIMAGE_OPTIONAL_HEADER)pImageTemp;			//获取可选PE头
		pImageTemp = pImageTemp + FileHeader_Image->SizeOfOptionalHeader;		//偏移到节表
		pSectionHeader_Image = (PIMAGE_SECTION_HEADER)pImageTemp;			//获取节表
	}
	else
	{
		InitWay = 1;
		FileSize = fileSize;
		//填充文件缓冲区
		FileBuffer.AllocMem(fileSize);
		FileBuffer.used = fileSize;
		memcpy(FileBuffer, (PBYTE)PeAddr, fileSize);

		//更新各种指针
		PBYTE pFileTemp = (PBYTE)FileBuffer;
		DosHeader = (PIMAGE_DOS_HEADER)pFileTemp;					//获取DOS头
		pFileTemp = pFileTemp + ((PIMAGE_DOS_HEADER)pFileTemp)->e_lfanew;	//偏移到NT头
		NtHeader = (PIMAGE_NT_HEADERS)pFileTemp;					//获取NT头
		pFileTemp = pFileTemp + 0x4;									//偏移到标准PE头
		FileHeader = (PIMAGE_FILE_HEADER)pFileTemp;					//获取标准PE头
		pFileTemp = pFileTemp + 0x14;									//偏移到可选PE头
		OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pFileTemp;			//获取可选PE头
		pFileTemp = pFileTemp + FileHeader->SizeOfOptionalHeader;		//偏移到节表
		pSectionHeader = (PIMAGE_SECTION_HEADER)pFileTemp;			//获取节表
	}
}

PeInstance::PeInstance(PATH path, int flag)
{
	//打开PE文件
	Cfile PeFile(path);
	FileSize = PeFile.size();
	PBYTE pTemp = NULL;
	switch (flag)
	{
		case 1:
		{
			InitWay = 1;
			//写入FileBuffer
			FileBuffer.AllocMem(FileSize);
			FileBuffer.used = FileSize;
			PeFile >> FileBuffer;
			//获取各种指针
			pTemp = FileBuffer;
			DosHeader = (PIMAGE_DOS_HEADER)pTemp;					//获取DOS头
			pTemp = pTemp + ((PIMAGE_DOS_HEADER)pTemp)->e_lfanew;	//偏移到NT头
			NtHeader = (PIMAGE_NT_HEADERS)pTemp;					//获取NT头
			pTemp = pTemp + 0x4;									//偏移到标准PE头
			FileHeader = (PIMAGE_FILE_HEADER)pTemp;					//获取标准PE头
			pTemp = pTemp + 0x14;									//偏移到可选PE头
			OptionalHeader = (PIMAGE_OPTIONAL_HEADER)pTemp;			//获取可选PE头
			pTemp = pTemp + FileHeader->SizeOfOptionalHeader;		//偏移到节表
			pSectionHeader = (PIMAGE_SECTION_HEADER)pTemp;			//获取节表
			break;
		}
		case 0:
		{
			InitWay = 0;
			//写入ImageBuffer
			ImageBuffer.AllocMem(FileSize);
			ImageBuffer.used = FileSize;
			PeFile >> ImageBuffer;
			//获取各种指针
			pTemp = ImageBuffer;
			DosHeader_Image = (PIMAGE_DOS_HEADER)pTemp;					//获取DOS头
			pTemp = pTemp + ((PIMAGE_DOS_HEADER)pTemp)->e_lfanew;	//偏移到NT头
			NtHeader_Image = (PIMAGE_NT_HEADERS)pTemp;					//获取NT头
			pTemp = pTemp + 0x4;									//偏移到标准PE头
			FileHeader_Image = (PIMAGE_FILE_HEADER)pTemp;					//获取标准PE头
			pTemp = pTemp + 0x14;									//偏移到可选PE头
			OptionalHeader_Image = (PIMAGE_OPTIONAL_HEADER)pTemp;			//获取可选PE头
			pTemp = pTemp + FileHeader_Image->SizeOfOptionalHeader;		//偏移到节表
			pSectionHeader_Image = (PIMAGE_SECTION_HEADER)pTemp;			//获取节表
			break;
		}
	}
	
}

BOOL PeInstance::ToImageBuffer()
{
	ImageBuffer.AllocMem(OptionalHeader->SizeOfImage);
	ImageBuffer.used = OptionalHeader->SizeOfImage;
	//PBYTE pImageBuffer = ImageBuffer;

	//拷贝所有头+节表
	ImageBuffer.copy_from(FileBuffer, OptionalHeader->SizeOfHeaders, 0);

	//拷贝所有节
	for (int j = 0; j < FileHeader->NumberOfSections; j++)
	{
		for (DWORD k = 0; k < pSectionHeader[j].SizeOfRawData; k++)
		{
			((PBYTE)ImageBuffer + pSectionHeader[j].VirtualAddress)[k] = ((PBYTE)FileBuffer + pSectionHeader[j].PointerToRawData)[k];
		}
	}

	PBYTE pTemp = ImageBuffer;
	DosHeader_Image = (PIMAGE_DOS_HEADER)pTemp;					//获取DOS头
	pTemp = pTemp + ((PIMAGE_DOS_HEADER)pTemp)->e_lfanew;	//偏移到NT头
	NtHeader_Image = (PIMAGE_NT_HEADERS)pTemp;					//获取NT头
	pTemp = pTemp + 0x4;									//偏移到标准PE头
	FileHeader_Image = (PIMAGE_FILE_HEADER)pTemp;					//获取标准PE头
	pTemp = pTemp + 0x14;									//偏移到可选PE头
	OptionalHeader_Image = (PIMAGE_OPTIONAL_HEADER)pTemp;			//获取可选PE头
	pTemp = pTemp + FileHeader_Image->SizeOfOptionalHeader;		//偏移到节表
	pSectionHeader_Image = (PIMAGE_SECTION_HEADER)pTemp;			//获取节表

	//返回成功标志
	return TRUE;
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
	((PIMAGE_SECTION_HEADER)pNewBuffer)->Misc.VirtualSize = Align(SectionSize, OptionalHeader->SectionAlignment);	//设置内存中大小
	DWORD MaxSize = pSectionHeader[FileHeader->NumberOfSections - 1].SizeOfRawData > pSectionHeader[FileHeader->NumberOfSections - 1].Misc.VirtualSize ?
		pSectionHeader[FileHeader->NumberOfSections - 1].SizeOfRawData : pSectionHeader[FileHeader->NumberOfSections - 1].Misc.VirtualSize;
	DWORD SizeOfData = Align(MaxSize, OptionalHeader->SectionAlignment);
	((PIMAGE_SECTION_HEADER)pNewBuffer)->VirtualAddress = pSectionHeader[FileHeader->NumberOfSections - 1].VirtualAddress + SizeOfData;	//设置内存中偏移
	((PIMAGE_SECTION_HEADER)pNewBuffer)->SizeOfRawData = Align(SectionSize, OptionalHeader->FileAlignment);	//设置文件中大小
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
				(PBYTE)((DWORD)ImageBuffer + pSectionHeader[FileHeader_Image->NumberOfSections - 1].VirtualAddress),
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

BOOL PeInstance::HaveRelocation()
{
	PIMAGE_DATA_DIRECTORY DataDirectory = OptionalHeader->DataDirectory;

	return (DataDirectory[5].VirtualAddress)
		&& (DataDirectory[5].Size);
}

BOOL PeInstance::FixRelocation(DWORD newImageBase)
{
	PBYTE Point = NULL;		//可以随意偏移的指针
	PDWORD Offset = NULL;	//要修正的地址
	DWORD BeforeBase = OptionalHeader->ImageBase;	//保存修改前的ImageBase
	//修改ImageBase
	OptionalHeader->ImageBase = newImageBase;
	//获取重定位表指针
	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)(RvaToFoa(OptionalHeader->DataDirectory[5].VirtualAddress) + (DWORD)FileBuffer);
	Point = (PBYTE)pBaseRelocation;
	//遍历重定位表
	for (int i = 0; ((PIMAGE_BASE_RELOCATION)Point)->SizeOfBlock != 0 && ((PIMAGE_BASE_RELOCATION)Point)->VirtualAddress != 0; i++)
	{
		for (int j = 0; j < (((PIMAGE_BASE_RELOCATION)Point)->SizeOfBlock - 8) / 2; j++)
		{
			if ((((PWORD)(Point + 0x8))[j] >> 0xC) == 0x3)
			{
				Offset = (PDWORD)((DWORD)FileBuffer + RvaToFoa((((PWORD)(Point + 0x8))[j] & 0xFFF) + ((PIMAGE_BASE_RELOCATION)Point)->VirtualAddress));
				*Offset = *Offset - BeforeBase + OptionalHeader->ImageBase;
			}
		}
		Point = Point + ((PIMAGE_BASE_RELOCATION)Point)->SizeOfBlock;
	}

	return TRUE;
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
			printf("FileBuffer保存成功！\n");
			break;
		}
		case 1:
		{
			//保存ImageBuffer
			NewFile << ImageBuffer;
			printf("ImageBuffer保存成功！\n");
			break;
		}
		case 2:
		{
			//保存NewBuffer
			NewFile << NewBuffer;
			printf("NewBuffer保存成功！\n");
			break;
		}
	}

	return TRUE;
}

size_t PeInstance::GetSize()
{
	return FileSize;
}

Cbuffer& PeInstance::GetBufferInstance(int Flag)
{
	switch (Flag)
	{
		case 0:
		{
			return FileBuffer;
			break;
		}
		case 1:
		{
			return ImageBuffer;
			break;
		}
		case 2:
		{
			return NewBuffer;
			break;
		}
	}
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
