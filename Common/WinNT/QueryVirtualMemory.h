#pragma once
#include <Windows.h>
#include "../Log/NdLog.h"
#include "../String/StringHelper.h"
#include <strsafe.h>

BOOL AvailablePhysicsMemory(__out UINT64& availablePhysicsMemory);

//
// �޸𸮰� ���� ���ٸ� ���� ©���� ������ �Լ��� ���ϰ� ���� ���� �����Ѵ�.
// ���� ©���� ���� ������ AvailablePhysicsMemory �Լ��� ����� ��.
//
INT64 GetAvailableMemory();

VOID PrintAvailableMemory();