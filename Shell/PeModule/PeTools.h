#pragma once
#define PATH string
#include <Windows.h>
#include <string>
#include "../File Module/Cfile.h"
#include "../Memory Module/Cbuffer.h"
using namespace std;

/*
	PE�ļ���
*/

class PeInstance
{
public:
	//���ݵ�ַ��ʼ��PE����
	PeInstance(HANDLE PeAddr, int flag, size_t fileSize);
	//����·����ʼ��PE����
	PeInstance(PATH path,int flag);
	//����PE������ָ��
	BOOL ToImageBuffer();
	//������
	BOOL AddSeaction(size_t SectionSize);
	//�����������������
	BOOL AddDataToNewSection(Cbuffer& SrcBuffer, size_t SrcSize);
	//�����һ������ȡ����
	BOOL GetDataFromLastSection(Cbuffer& DesBuffer, size_t DesSize);
	//��ȡ���һ���ڵĴ�С
	DWORD GetLastSectionSize();
	//�Ƿ����ض�λ��
	BOOL HaveRelocation();
	//�޸��ض�λ��
	BOOL FixRelocation(DWORD NewBaseAddr);
	//����
	BOOL Save(PATH path, int Flag);
	//��ȡPE�ļ���С
	size_t GetSize();
	//��ȡ����������
	Cbuffer& GetBufferInstance(int Flag);
private:
	//��ȡ������ֵ
	int Align(int Value, int align);
	//RVA->FOA
	DWORD RvaToFoa(DWORD dwRva);
	//FOA->RVA
	DWORD FoaToRva(DWORD dwFoa);
	//����ͷ+�ڱ�
	BOOL PromoteHeaders();
public:
	//PEָ��
	PIMAGE_DOS_HEADER DosHeader = NULL;								//DOSͷָ��
	PIMAGE_NT_HEADERS NtHeader = NULL;								//NTͷָ��
	PIMAGE_FILE_HEADER FileHeader = NULL;							//��׼PEͷָ��
	PIMAGE_OPTIONAL_HEADER OptionalHeader = NULL;					//��ѡPEͷָ�� 
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;					//�ڱ�ָ��

	PIMAGE_DOS_HEADER DosHeader_Image = NULL;						//DOSͷָ��_Image
	PIMAGE_NT_HEADERS NtHeader_Image = NULL;						//NTͷָ��_Image
	PIMAGE_FILE_HEADER FileHeader_Image = NULL;						//��׼PEͷָ��_Image
	PIMAGE_OPTIONAL_HEADER OptionalHeader_Image = NULL;				//��ѡPEͷָ��_Image
	PIMAGE_SECTION_HEADER pSectionHeader_Image = NULL;				//�ڱ�ָ��_Image
	//������
	Cbuffer FileBuffer;												//�ļ��е�����
	Cbuffer ImageBuffer;											//�ڴ��е�����
	Cbuffer NewBuffer;												//�����ں�FileBuffer
	//PE�ļ���С
	size_t FileSize;
	//��ʼ����ʽ
	int InitWay;
};