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
	//���ݵ�ַ��ʼ��PE����(����flag����ѡ���ļ������������ڴ滺����)
	PeInstance(HANDLE PeAddr, int flag, size_t fileSize);
	//����·����ʼ��PE����
	PeInstance(PATH path);
	//������
	BOOL AddSeaction(size_t SectionSize);
	//�����������������
	BOOL AddDataToNewSection(Cbuffer& SrcBuffer, size_t SrcSize);
	//�����һ������ȡ����
	BOOL GetDataFromLastSection(Cbuffer& DesBuffer, size_t DesSize);
	//��ȡ���һ���ڵĴ�С
	DWORD GetLastSectionSize();
	//����
	BOOL Save(PATH path, int Flag);
	//��ȡPE�ļ���С
	size_t GetSize();
	//��ȡ����������
	Cbuffer& GetBufferInstance();
private:
	//��ȡ������ֵ
	int Align(int Value, int align);
	//RVA->FOA
	DWORD RvaToFoa(DWORD dwRva);
	//FOA->RVA
	DWORD FoaToRva(DWORD dwFoa);
	//����ͷ+�ڱ�
	BOOL PromoteHeaders();
private:
	//PEָ��
	PIMAGE_DOS_HEADER DosHeader = NULL;								//DOSͷָ��
	PIMAGE_NT_HEADERS NtHeader = NULL;								//NTͷָ��
	PIMAGE_FILE_HEADER FileHeader = NULL;							//��׼PEͷָ��
	PIMAGE_OPTIONAL_HEADER OptionalHeader = NULL;					//��ѡPEͷָ�� 
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;					//�ڱ�ָ��
	//������
	Cbuffer FileBuffer;												//�ļ��е�����
	Cbuffer ImageBuffer;											//�ڴ��е�����
	Cbuffer NewBuffer;												//�����ں�Ļ�����
	//PE�ļ���С
	size_t FileSize;
	//��ʼ����ʽ
	int InitWay;
};