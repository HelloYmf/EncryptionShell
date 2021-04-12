#include "Cbuffer.h"


Cbuffer::Cbuffer()
{
	buffer = NULL;
	used = 0;
}

void Cbuffer::AllocMem(unsigned long long size)
{
	buffer = malloc(size);
	memset(buffer, 0x00, size);
}

Cbuffer::Cbuffer(unsigned long long size, unsigned long long used)
	:used(used){
	buffer = malloc(size);
	memset(buffer, 0x00, size);
}

Cbuffer::Cbuffer(Cbuffer&& other_buffer) noexcept {
	buffer = other_buffer.buffer;
	used = other_buffer.used;
}

void Cbuffer::copy_from(void* src, int used, int pos) {
	memcpy((char*)buffer + pos, src, used);
}

void Cbuffer::copy_from(const std::string& src){
	this->copy_from((void*)src.c_str(), src.length());
}

Cbuffer::~Cbuffer() {
	free(buffer);
}

