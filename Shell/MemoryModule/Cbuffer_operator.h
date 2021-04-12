#include"Cbuffer.h"
#pragma once
class Cbuffer_operator {
public:
    virtual bool operator >> (Cbuffer&) = 0;
    virtual bool operator << (const Cbuffer&) = 0;
};