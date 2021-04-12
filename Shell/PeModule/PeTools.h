#pragma once
#define PATH string
#include <Windows.h>
#include <string>
#include "../File Module/Cfile.h"
#include "../Memory Module/Cbuffer.h"
using namespace std;

/*
	PE文件类
*/

class PeInstance
{
public:
	//根据地址初始化PE对象
	PeInstance(HANDLE PeAddr, int flag, size_t fileSize);
	//根据路径初始化PE对象
	PeInstance(PATH path,int flag);
	//拉伸PE，更新指针
	BOOL ToImageBuffer();
	//新增节
	BOOL AddSeaction(size_t SectionSize);
	//往新增节中添加数据
	BOOL AddDataToNewSection(Cbuffer& SrcBuffer, size_t SrcSize);
	//从最后一个节中取数据
	BOOL GetDataFromLastSection(Cbuffer& DesBuffer, size_t DesSize);
	//获取最后一个节的大小
	DWORD GetLastSectionSize();
	//是否含有重定位表
	BOOL HaveRelocation();
	//修复重定位表
	BOOL FixRelocation(DWORD NewBaseAddr);
	//存盘
	BOOL Save(PATH path, int Flag);
	//获取PE文件大小
	size_t GetSize();
	//获取缓冲区引用
	Cbuffer& GetBufferInstance(int Flag);
private:
	//获取对齐后的值
	int Align(int Value, int align);
	//RVA->FOA
	DWORD RvaToFoa(DWORD dwRva);
	//FOA->RVA
	DWORD FoaToRva(DWORD dwFoa);
	//提升头+节表
	BOOL PromoteHeaders();
public:
	//PE指针
	PIMAGE_DOS_HEADER DosHeader = NULL;								//DOS头指针
	PIMAGE_NT_HEADERS NtHeader = NULL;								//NT头指针
	PIMAGE_FILE_HEADER FileHeader = NULL;							//标准PE头指针
	PIMAGE_OPTIONAL_HEADER OptionalHeader = NULL;					//可选PE头指针 
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;					//节表指针

	PIMAGE_DOS_HEADER DosHeader_Image = NULL;						//DOS头指针_Image
	PIMAGE_NT_HEADERS NtHeader_Image = NULL;						//NT头指针_Image
	PIMAGE_FILE_HEADER FileHeader_Image = NULL;						//标准PE头指针_Image
	PIMAGE_OPTIONAL_HEADER OptionalHeader_Image = NULL;				//可选PE头指针_Image
	PIMAGE_SECTION_HEADER pSectionHeader_Image = NULL;				//节表指针_Image
	//缓冲区
	Cbuffer FileBuffer;												//文件中的样子
	Cbuffer ImageBuffer;											//内存中的样子
	Cbuffer NewBuffer;												//新增节后FileBuffer
	//PE文件大小
	size_t FileSize;
	//初始化方式
	int InitWay;
};