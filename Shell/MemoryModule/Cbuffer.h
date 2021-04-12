#pragma once
#include<stdlib.h>
#include<string>

#pragma once
//����������
//������ģ��֮�䴫�ݻ�����
class Cbuffer {

public:
//By.Է����		2021.4.4
	//Ĭ�Ϲ��캯��
	Cbuffer();

	//����С�����ڴ�
	void AllocMem(unsigned long long size);
//
	//malloc
	explicit Cbuffer(unsigned long long size, unsigned long long used = 0);

	//��ֵ���� �����Ż�
	Cbuffer(Cbuffer&& other_buffer) noexcept;

	//Without Deep Copy
	Cbuffer(const Cbuffer&) = delete;
	
	//copy content from other memory
	void copy_from(void* src,int size, int pos = 0);

	//copy content from std::string
	void copy_from(const std::string& src);

	//free
	~Cbuffer();

	//������ָ������ת��
	template<typename T>
	inline operator T() const {
		return (T)buffer;
	}

public:

	//malloc size
	unsigned long long used;

private:
	
	//buffer pointer
	void* buffer;

};


