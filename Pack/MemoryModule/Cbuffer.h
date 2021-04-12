#pragma once
#include<stdlib.h>
#include<string>

#pragma once
//缓冲区管理
//用于在模块之间传递缓冲区
class Cbuffer {

public:
//By.苑明飞		2021.4.4
	//默认构造函数
	Cbuffer();

	//按大小分配内存
	void AllocMem(unsigned long long size);
//
	//malloc
	explicit Cbuffer(unsigned long long size, unsigned long long used = 0);

	//右值引用 传递优化
	Cbuffer(Cbuffer&& other_buffer) noexcept;

	//Without Deep Copy
	Cbuffer(const Cbuffer&) = delete;
	
	//copy content from other memory
	void copy_from(void* src,int size, int pos = 0);

	//copy content from std::string
	void copy_from(const std::string& src);

	//free
	~Cbuffer();

	//缓冲区指针任意转型
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


