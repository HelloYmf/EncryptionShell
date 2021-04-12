#include "Cfile.h"

Cfile::Cfile(std::string path) {
	hfile = CreateFileA(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_ALWAYS, 0, 0);
}

unsigned Cfile::size() const {
	return GetFileSize(hfile, 0);
}

bool Cfile::operator>>(Cbuffer& buffer) {
	DWORD real_read;
	return ReadFile(hfile, buffer, buffer.used, &real_read, 0);
}


bool Cfile::operator <<(const Cbuffer& buffer) {
	DWORD real_write;
	return WriteFile(hfile, buffer, buffer.used, &real_write, 0);
}

Cfile::~Cfile() {
	CloseHandle(hfile);
}

void Cfile::move_file_pointer(unsigned dis) {
	SetFilePointer(hfile, dis, 0, FILE_BEGIN);
}
