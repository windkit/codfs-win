// CodFsfs.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

/*

Copyright (c) 2007, 2008 Hiroki Asakawa info@dokan-dev.net

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#pragma comment(lib, "Ws2_32.lib")

#define _WINSOCKAPI_
#include <windows.h>
#include <winbase.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <io.h>

#include <set>
#include <thread>
#include <unordered_map>
#include <forward_list>

#include "common/convertor.hh"
#include "common/garbagecollector.hh"

#include "config/config.hh"

#include "fuse/filemetadatacache.hh"
#include "fuse/filedatacache.hh"

#include "client/client.hh"
#include "client/client_communicator.hh"

#include "../dokan.h"
#include "../dokanx/fileinfo.h"
#include "../Common/String/StringHelper.h"

Client* client;
ClientCommunicator* _clientCommunicator;
ConfigLayer* configLayer;
uint32_t _clientId = 12345;

FileMetaDataCache* _fileMetaDataCache;
FileDataCache* _fileDataCache;

uint32_t _segmentSize;
uint32_t _prefetchCount;
std::forward_list<struct SegmentMetaData> _segmentMetaDataList;
uint32_t _segmentMetaDataAllocateSize = 50;
uint32_t _preAllocSegCount;

thread garbageCollectionThread;
thread receiveThread;

mutex _segmentMetaMutex;
RWMutex* _namespaceMutex;

//unordered_map<ULONG64, uint32_t> codfsIdMap;
unordered_map<wstring, uint32_t> fileIdMap;

BOOL g_UseStdErr;
BOOL g_DebugMode;

static WCHAR g_RootDirectory[MAX_PATH] = L"C:";
static WCHAR g_MountPoint[MAX_PATH] = L"M:";

char* fillbuf;

string _fuseFolder = "fusedir";

void startGarbageCollectionThread() {
	GarbageCollector::getInstance().start();
}

void codfs_init() {
	logw(L"Inti");
	configLayer = new ConfigLayer("common.xml", "clientconfig.xml");

	printf("%s\n", configLayer->getConfigString("Fuse>segmentSize"));
	_segmentSize = (uint32_t)stringToByte(configLayer->getConfigString("Fuse>segmentSize"));
	_prefetchCount = configLayer->getConfigInt("Fuse>prefetchCount");

	fillbuf = (char*)malloc(sizeof(char)* _segmentSize);
	memset(fillbuf, 0, sizeof(char)* _segmentSize);

//	debug("Segment Size: %" PRIu32 "\n", _segmentSize);
//	debug("Prefetch Count %" PRIu32 "\n", _prefetchCount);

	_clientId = rand() % 10000 + 10000;
	client = new Client(_clientId);
	_clientCommunicator = client->getCommunicator();
	_clientCommunicator->createServerSocket();

	_fileMetaDataCache = new FileMetaDataCache();
	_fileDataCache = new FileDataCache();

	_namespaceMutex = new RWMutex();

	_preAllocSegCount = configLayer->getConfigInt("Fuse>PreallocateSegmentNumber");

	// 1. Garbage Collection Thread
	garbageCollectionThread = thread(startGarbageCollectionThread);

	// 2. Receive Thread
	receiveThread = thread(&Communicator::waitForMessage, _clientCommunicator);

	_clientCommunicator->setId(_clientId);
	_clientCommunicator->setComponentType(CLIENT);

	//_clientCommunicator->connectAllComponents();
	_clientCommunicator->connectToMds();
	_clientCommunicator->connectToMonitor();
	_clientCommunicator->getOsdListAndConnect();

	return;
}

NTSTATUS ToNtStatus(DWORD dwError)
{
    switch (dwError)
    {
    case ERROR_FILE_NOT_FOUND:
        return STATUS_OBJECT_NAME_NOT_FOUND;
    case ERROR_PATH_NOT_FOUND:
        return STATUS_OBJECT_PATH_NOT_FOUND;
    case ERROR_INVALID_PARAMETER:
        return STATUS_INVALID_PARAMETER;
    default:
        return STATUS_ACCESS_DENIED;
    }
}

std::wstring GetFilePath(
    __in const std::wstring& fileName
    )
{
    return std::wstring(g_RootDirectory) + fileName;
}

#include <fstream>

static uint32_t getSegmentNum(uint64_t size){
	return size / _segmentSize + ((size % _segmentSize) == 0) ? 0 : 1;
}

static uint32_t createNameSpace(wstring path_in) {
	//writeLock writelock(*_namespaceMutex);
	uint32_t fileId = 0;
	if (fileIdMap.count(path_in)) {
		return fileIdMap[path_in];
	}

	wstring filePath = GetFilePath(path_in);
	FILE* fp = _wfopen(filePath.c_str(), L"w");
	if (fp == NULL) {
		logw(L"Cannot create shadown file for %s", filePath.c_str());
		exit(-1);
	}

	struct FileMetaData fileMetaData;
	string filePath_s(filePath.begin(), filePath.end());

	logw(L"New File ID %u", fileId);
	fileMetaData = _clientCommunicator->uploadFile(_clientId, filePath_s.c_str(), 0, _preAllocSegCount);
	fileMetaData._fileType = NORMAL;
	fileId = fileMetaData._id;

	logw(L"Writing File ID to %s", filePath.c_str());
	int ret = fprintf(fp, "%" PRIu32, fileId);
	fclose(fp);
	
	_fileMetaDataCache->saveMetaData(fileMetaData);

	fileIdMap[path_in] = fileId;
	
	return fileId;
}

static uint32_t checkNameSpace(wstring path_in) {
	//readLock readlock(*_namespaceMutex);
	if (fileIdMap.count(path_in)) {
		logw(L"File ID Return from Cache %s <%d>", path_in.c_str(), fileIdMap[path_in]);
		return fileIdMap[path_in];
	}
	wstring fpath = GetFilePath(path_in);

	FILE* fp = _wfopen(fpath.c_str(), L"r");
	if (fp == NULL) {
		logw(L"File %s Does not Exist", fpath.c_str());
		return 0;
	}

	uint32_t fileId;
	int ret = fscanf(fp, "%" PRIu32, &fileId);

	fclose(fp);

	if (ret < 0) {
		logw(L"No File ID for %s", fpath.c_str());
		return 0;
	}

	logw(L"File ID %u for %s", fileId, fpath.c_str());
	fileIdMap[path_in] = fileId;
	return fileId;
}

static uint32_t removeNameSpace(wstring path_in) {
	uint32_t fileId = checkNameSpace(path_in);
	if (fileId != 0) {
		//writeLock writelock(*_namespaceMutex);
		wstring fpath = GetFilePath(path_in);
		_wunlink(fpath.c_str());
	}
	return fileId;
}

static struct FileMetaData getAndCacheFileMetaData(uint32_t id) {

	struct FileMetaData fileMetaData;
	logw(L"Get Metadata for %d", id);
	set<uint32_t> onlineList;
	try {
		fileMetaData = _fileMetaDataCache->getMetaData(id);
		logw(L"Metadata Found for %d", id);

		/// TODO: Degraded Read with Failed Primary
		/*
		for (uint32_t primary : fileMetaData._primaryList) {
		debug("Checking Primary %" PRIu32 " for ID %" PRIu32 "\n", primary, id);
		// if at least one primary is disconnected, request latest metadata from MDS
		if (onlineList.count(primary) == 0) {
		if (_clientCommunicator->getSockfdFromId(primary) == (uint32_t)-1){
		fileMetaData = _clientCommunicator->getFileInfo(_clientId, id);
		_fileMetaDataCache->saveMetaData(fileMetaData);
		break;
		}
		else
		onlineList.insert(primary);
		}
		}
		*/
	}
	catch (const std::out_of_range& oor) {
		logw(L"Meta Data of File %d Not Cached", id);
		fileMetaData = _clientCommunicator->getFileInfo(_clientId, id);
		if (fileMetaData._fileType == NOTFOUND)
			return fileMetaData;
		_fileMetaDataCache->saveMetaData(fileMetaData);
	}
	return fileMetaData;
}

static struct SegmentMetaData allocateSegmentMetaData() {
	_segmentMetaMutex.lock();
	if (_segmentMetaDataList.empty()) {
		vector<struct SegmentMetaData> segmentMetaDataList = _clientCommunicator->getNewSegmentList(_clientId, _segmentMetaDataAllocateSize);
		_segmentMetaDataList.insert_after(_segmentMetaDataList.before_begin(), segmentMetaDataList.begin(), segmentMetaDataList.end());
	}
	struct SegmentMetaData _segmentMetaData = _segmentMetaDataList.front();
	_segmentMetaDataList.pop_front();
	_segmentMetaMutex.unlock();
	return _segmentMetaData;
}

/*
* FileId Mutex for modify file meta data
*/
std::mutex _fileRWMutexMapMutex;
unordered_map <uint32_t, RWMutex*> _fileRWMutexMap;
static RWMutex* obtainFileRWMutex(uint32_t fileId) {
	// obtain rwmutex for this segment
	_fileRWMutexMapMutex.lock();
	RWMutex* rwmutex;
	if (_fileRWMutexMap.count(fileId) == 0) {
		rwmutex = new RWMutex();
		_fileRWMutexMap[fileId] = rwmutex;
	}
	else {
		rwmutex = _fileRWMutexMap[fileId];
	}
	_fileRWMutexMapMutex.unlock();
	return rwmutex;
}

static void
PrintUserName(PDOKAN_FILE_INFO	DokanFileInfo)
{
    HANDLE	handle;
    UCHAR buffer[1024];
    DWORD returnLength;
    WCHAR accountName[256];
    WCHAR domainName[256];
    DWORD accountLength = _countof(accountName);
    DWORD domainLength = _countof(domainName);
    PTOKEN_USER tokenUser;
    SID_NAME_USE snu;

    handle = DokanOpenRequestorToken(DokanFileInfo);
    if (handle == INVALID_HANDLE_VALUE) {
        logw(L"  DokanOpenRequestorToken failed");
        return;
    }

    if (!GetTokenInformation(handle, TokenUser, buffer, sizeof(buffer), &returnLength)) {
        logw(L"  GetTokenInformaiton failed: %d", GetLastError());
        CloseHandle(handle);
        return;
    }

    CloseHandle(handle);

    tokenUser = (PTOKEN_USER)buffer;
    if (!LookupAccountSid(NULL, tokenUser->User.Sid, accountName,
            &accountLength, domainName, &domainLength, &snu)) {
        logw(L"  LookupAccountSid failed: %d", GetLastError());
        return;
    }

    logw(L"  AccountName: %s, DomainName: %s", accountName, domainName);
}

#define CodFsCheckFlag(val, flag) if (val&flag) { logw(L#flag); }


void CheckFileAttributeFlags(DWORD FlagsAndAttributes)
{
    CodFsCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_ARCHIVE);
    CodFsCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_ENCRYPTED);
    CodFsCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_HIDDEN);
    CodFsCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_NORMAL);
    CodFsCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
    CodFsCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_OFFLINE);
    CodFsCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_READONLY);
    CodFsCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_SYSTEM);
    CodFsCheckFlag(FlagsAndAttributes, FILE_ATTRIBUTE_TEMPORARY);
    CodFsCheckFlag(FlagsAndAttributes, FILE_FLAG_WRITE_THROUGH);
    CodFsCheckFlag(FlagsAndAttributes, FILE_FLAG_OVERLAPPED);
    CodFsCheckFlag(FlagsAndAttributes, FILE_FLAG_NO_BUFFERING);
    CodFsCheckFlag(FlagsAndAttributes, FILE_FLAG_RANDOM_ACCESS);
    CodFsCheckFlag(FlagsAndAttributes, FILE_FLAG_SEQUENTIAL_SCAN);
    CodFsCheckFlag(FlagsAndAttributes, FILE_FLAG_DELETE_ON_CLOSE);
    CodFsCheckFlag(FlagsAndAttributes, FILE_FLAG_BACKUP_SEMANTICS);
    CodFsCheckFlag(FlagsAndAttributes, FILE_FLAG_POSIX_SEMANTICS);
    CodFsCheckFlag(FlagsAndAttributes, FILE_FLAG_OPEN_REPARSE_POINT);
    CodFsCheckFlag(FlagsAndAttributes, FILE_FLAG_OPEN_NO_RECALL);
    CodFsCheckFlag(FlagsAndAttributes, SECURITY_ANONYMOUS);
    CodFsCheckFlag(FlagsAndAttributes, SECURITY_IDENTIFICATION);
    CodFsCheckFlag(FlagsAndAttributes, SECURITY_IMPERSONATION);
    CodFsCheckFlag(FlagsAndAttributes, SECURITY_DELEGATION);
    CodFsCheckFlag(FlagsAndAttributes, SECURITY_CONTEXT_TRACKING);
    CodFsCheckFlag(FlagsAndAttributes, SECURITY_EFFECTIVE_ONLY);
    CodFsCheckFlag(FlagsAndAttributes, SECURITY_SQOS_PRESENT);
}

void CheckDesiredAccessFlags(DWORD DesiredAccess)
{
    CodFsCheckFlag(DesiredAccess, GENERIC_READ);
    CodFsCheckFlag(DesiredAccess, GENERIC_WRITE);
    CodFsCheckFlag(DesiredAccess, GENERIC_EXECUTE);

    CodFsCheckFlag(DesiredAccess, DELETE);
    CodFsCheckFlag(DesiredAccess, FILE_READ_DATA);
    CodFsCheckFlag(DesiredAccess, FILE_READ_ATTRIBUTES);
    CodFsCheckFlag(DesiredAccess, FILE_READ_EA);
    CodFsCheckFlag(DesiredAccess, READ_CONTROL);
    CodFsCheckFlag(DesiredAccess, FILE_WRITE_DATA);
    CodFsCheckFlag(DesiredAccess, FILE_WRITE_ATTRIBUTES);
    CodFsCheckFlag(DesiredAccess, FILE_WRITE_EA);
    CodFsCheckFlag(DesiredAccess, FILE_APPEND_DATA);
    CodFsCheckFlag(DesiredAccess, WRITE_DAC);
    CodFsCheckFlag(DesiredAccess, WRITE_OWNER);
    CodFsCheckFlag(DesiredAccess, SYNCHRONIZE);
    CodFsCheckFlag(DesiredAccess, FILE_EXECUTE);
    CodFsCheckFlag(DesiredAccess, STANDARD_RIGHTS_READ);
    CodFsCheckFlag(DesiredAccess, STANDARD_RIGHTS_WRITE);
    CodFsCheckFlag(DesiredAccess, STANDARD_RIGHTS_EXECUTE);
}

void CheckShareModeFlags(DWORD ShareMode)
{
    CodFsCheckFlag(ShareMode, FILE_SHARE_READ);
    CodFsCheckFlag(ShareMode, FILE_SHARE_WRITE);
    CodFsCheckFlag(ShareMode, FILE_SHARE_DELETE);
}

NTSTATUS CodFsSetEndOfFile(
	LPCWSTR				FileName,
	LONGLONG			ByteOffset,
	PDOKAN_FILE_INFO	DokanFileInfo);

NTSTATUS CodFsCreateFile(
    LPCWSTR					FileName,
    DWORD					DesiredAccess,
    DWORD					ShareMode,
    DWORD					CreationDisposition,
    DWORD					FlagsAndAttributes,
    PDOKAN_FILE_INFO		DokanFileInfo)
{
	writeLock writelock(*_namespaceMutex);
    logw(L"Start<%s>", FileName);
    std::wstring filePath;
    HANDLE handle;
    DWORD fileAttr;

    filePath = GetFilePath(FileName);

    logw(L"CreateFile : %s", filePath.c_str());

    PrintUserName(DokanFileInfo);

    if (CreationDisposition == CREATE_NEW)
        logw(L"CREATE_NEW");
    if (CreationDisposition == OPEN_ALWAYS)
        logw(L"OPEN_ALWAYS");
    if (CreationDisposition == CREATE_ALWAYS)
        logw(L"CREATE_ALWAYS");
    if (CreationDisposition == OPEN_EXISTING)
        logw(L"OPEN_EXISTING");
    if (CreationDisposition == TRUNCATE_EXISTING)
        logw(L"TRUNCATE_EXISTING");

    logw(L"ShareMode = 0x%x", ShareMode);

    CheckShareModeFlags(ShareMode);

    logw(L"AccessMode = 0x%x", DesiredAccess);

    CheckDesiredAccessFlags(DesiredAccess);

    // When filePath is a directory, needs to change the flag so that the file can be opened.
    fileAttr = GetFileAttributes(filePath.c_str());
	if ((fileAttr != INVALID_FILE_ATTRIBUTES) && (fileAttr & FILE_ATTRIBUTE_DIRECTORY)) {
        FlagsAndAttributes |= FILE_FLAG_BACKUP_SEMANTICS;
		DokanFileInfo->IsDirectory = true;
        //AccessMode = 0;
    }
    logw(L"FlagsAndAttributes = 0x%08X", FlagsAndAttributes);

	CheckFileAttributeFlags(FlagsAndAttributes);

	if (filePath.back() == '\\') {
		DokanFileInfo->IsDirectory = true;
	}

	logw(L"%s isDirectory: %d", filePath.c_str(), DokanFileInfo->IsDirectory);

	uint32_t fileId = 0;

	if (DokanFileInfo->IsDirectory) {
		handle = CreateFile(
			filePath.c_str(),
			DesiredAccess,//GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE,
			ShareMode,
			NULL, // security attribute
			CreationDisposition,
			FlagsAndAttributes & ~FILE_FLAG_DELETE_ON_CLOSE,// |FILE_FLAG_NO_BUFFERING,
			NULL); // template file handle

		if (handle == INVALID_HANDLE_VALUE) {
			DWORD error = GetLastError();
			logw(L"error code = %d", error);
			if (error == ERROR_FILE_NOT_FOUND)
			{
				return STATUS_OBJECT_NAME_NOT_FOUND;
			}
			else
			{
				return STATUS_ACCESS_DENIED;
			}
		}
		DokanFileInfo->Context = (ULONG64)handle;
		return STATUS_SUCCESS;
	}
	else {
		fileId = checkNameSpace(FileName);
		
		switch (CreationDisposition) {
			case CREATE_NEW:
				if (fileId != 0) {
					SetLastError(ERROR_FILE_EXISTS);
					return STATUS_ACCESS_DENIED;
				}
				else {
					fileId = createNameSpace(FileName);
				}
				break;
			case CREATE_ALWAYS:
				if (fileId != 0) {
					SetLastError(ERROR_FILE_EXISTS);
				}
				else {
					fileId = createNameSpace(FileName);
				}
				break;
			case OPEN_ALWAYS:
				if (fileId != 0){
					SetLastError(ERROR_ALREADY_EXISTS);
				}
				else {
					fileId = createNameSpace(FileName);
				}
				break;
			case OPEN_EXISTING:
				if (fileId == 0)
					return STATUS_OBJECT_NAME_NOT_FOUND;
				break;
			case TRUNCATE_EXISTING:
				if (fileId == 0) {
					return STATUS_OBJECT_NAME_NOT_FOUND;
				}
				else {
					CodFsSetEndOfFile(FileName, 0, DokanFileInfo);
					/// TODO: Truncate File
				}
				break;
		}

		DokanFileInfo->Context = (ULONG64)fileId;
		return STATUS_SUCCESS;
	}
}


NTSTATUS CodFsCreateDirectory(
    LPCWSTR					FileName,
    PDOKAN_FILE_INFO	    DokanFileInfo)
{
	writeLock writelock(*_namespaceMutex);
    UNREFERENCED_PARAMETER(DokanFileInfo);
    logw(L"Start<%s>", FileName);
    std::wstring filePath = GetFilePath(FileName);

    logw(L"CreateDirectory : %s", filePath.c_str());
    if (!CreateDirectory(filePath.c_str(), NULL)) {
        DWORD error = GetLastError();
        logw(L"failed(%d)", error);
        return ToNtStatus(error);
    }
    return STATUS_SUCCESS;
}


NTSTATUS CodFsOpenDirectory(
    LPCWSTR					FileName,
    PDOKAN_FILE_INFO		DokanFileInfo)
{
	readLock readlock(*_namespaceMutex);
    logw(L"Start<%s>", FileName);
    HANDLE handle;
    DWORD attr;
    std::wstring filePath = GetFilePath(FileName);

    logw(L"OpenDirectory : %s", filePath.c_str());

    attr = GetFileAttributes(filePath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        DWORD error = GetLastError();
        logw(L"failed(%d)", error);
        return ToNtStatus(error);
    }
    if (!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        return STATUS_NOT_A_DIRECTORY;
    }

    handle = CreateFile(
        filePath.c_str(),
        0,
        FILE_SHARE_READ|FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL);

    if (handle == INVALID_HANDLE_VALUE) {
        DWORD dwError = GetLastError();
        logw(L"failed(%d)", dwError);
        return ToNtStatus(dwError);
    }

    logw(L"");

    DokanFileInfo->Context = (ULONG64)handle;

    return STATUS_SUCCESS;
}


void CodFsCloseFile(
    LPCWSTR					FileName,
    PDOKAN_FILE_INFO		DokanFileInfo)
{
	readLock readlock(*_namespaceMutex);
    std::wstring filePath = GetFilePath(FileName);

    if (DokanFileInfo->Context) {
        logw(L"CloseFile: %s", filePath.c_str());
        logw(L"error : not cleanuped file");
		if (DokanFileInfo->IsDirectory){
			CloseHandle((HANDLE)DokanFileInfo->Context);
		}
        DokanFileInfo->Context = 0;
    } else {
        //DbgPrint(L"Close: %s\ninvalid handle", filePath.c_str());
        logw(L"Close: %s", filePath.c_str());
    }

    //DbgPrint(L"");
}

NTSTATUS CodFsFlushFileBuffers(
	LPCWSTR		FileName,
	PDOKAN_FILE_INFO	DokanFileInfo);

void CodFsCleanup(
    LPCWSTR					FileName,
    PDOKAN_FILE_INFO		DokanFileInfo)
{
	std::wstring filePath = GetFilePath(FileName);

    if (DokanFileInfo->Context) {
        logw(L"Cleanup: %s", filePath.c_str());

		// Write Back
		NTSTATUS ret = CodFsFlushFileBuffers(FileName, DokanFileInfo);
		if (ret < 0){
			logw(L"Cleanup Triggered Flush Failed");
			return;
		}

		if (DokanFileInfo->IsDirectory)
			CloseHandle((HANDLE)DokanFileInfo->Context);

        DokanFileInfo->Context = 0;

		if (DokanFileInfo->DeleteOnClose) {
			writeLock writelock(*_namespaceMutex);
            logw(L"DeleteOnClose");
            if (DokanFileInfo->IsDirectory) {
                logw(L"  DeleteDirectory ");
                if (!RemoveDirectory(filePath.c_str())) {
                    logw(L"error code = %d", GetLastError());
                } else {
                    logw(L"success");
                }
            } else {
				logw(L"  DeleteFile ");
				uint32_t fileId = removeNameSpace(FileName);
				if (fileId != 0) {
					_fileMetaDataCache->removeMetaData(fileId);
					fileIdMap.erase(FileName);
				}     
            }
        }

    } else {
        logw(L"Cleanup: %s\ninvalid handle", filePath.c_str());
    }
}

NTSTATUS CodFsReadFile(
    LPCWSTR				FileName,
    LPVOID				Buffer,
    DWORD				BufferLength,
    LPDWORD				ReadLength,
    LONGLONG			Offset,
    PDOKAN_FILE_INFO	DokanFileInfo)
{
	readLock readlock(*_namespaceMutex);
    HANDLE	handle = (HANDLE)DokanFileInfo->Context;
    //BOOL	opened = FALSE;
    //std::wstring filePath = GetFilePath(FileName);
    NTSTATUS status = STATUS_SUCCESS;

	logw(L"ReadFile : %s offset %I64d, length %d", FileName, Offset, BufferLength);
	uint32_t fileId;
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        logw(L"invalid handle, cleanuped?");
		fileId = checkNameSpace(FileName);
		if (fileId == 0)
			return STATUS_OBJECT_NAME_NOT_FOUND;
	}
	else
		fileId = (uint32_t)DokanFileInfo->Context;
	
	struct FileMetaData fileMetaData = getAndCacheFileMetaData(fileId);
	uint64_t sizeRead = 0;
	uint32_t lastSegmentCount = 0;
	char* bufptr = (char*)Buffer;
	if ((uint64_t)Offset >= fileMetaData._size)
		return 0;

	while (sizeRead < (uint64_t)BufferLength) {
		readLock rdLock(*obtainFileRWMutex(fileId));
		// TODO: Check Read Size
		uint32_t segmentCount = ((uint64_t)Offset + sizeRead) / (uint64_t)_segmentSize;		// position of segment in the file
		uint64_t segmentId = fileMetaData._segmentList[segmentCount];
		uint32_t primary = fileMetaData._primaryList[segmentCount];
		uint32_t segmentOffset = (uint64_t)Offset + sizeRead - ((uint64_t)segmentCount * (uint64_t)_segmentSize);	// offset within the segment
		uint64_t readSize = (uint64_t)_segmentSize - segmentOffset;
		if ((uint64_t)BufferLength - sizeRead < readSize)
			readSize = (uint64_t)BufferLength - sizeRead;
		if (fileMetaData._size - (uint64_t)Offset - sizeRead < readSize)
			readSize = fileMetaData._size - (uint64_t)Offset - sizeRead;

		logs("Reading Offset %d with segment %d", Offset + sizeRead, segmentId)
		// return immediately if data is cached, otherwise retrieve data from OSDs
		uint32_t retstat = _fileDataCache->readDataCache(segmentId, primary, bufptr, readSize, segmentOffset);
		bufptr += retstat;
		sizeRead += retstat;
		lastSegmentCount = segmentCount;
		if (fileMetaData._size <= (uint64_t)Offset + sizeRead)
			break;
	}

	*ReadLength = sizeRead;
	logw(L"ReadSize: %d", *ReadLength);

	// prefetch the next _prefetchCount segments
	for (uint32_t i = 0; i < _prefetchCount; ++i) {
		uint32_t segmentCount = lastSegmentCount + i;
		if (segmentCount < fileMetaData._segmentList.size())
			_fileDataCache->prefetchSegment(fileMetaData._segmentList[segmentCount], fileMetaData._primaryList[segmentCount]);
	}

    return status;
}

NTSTATUS CodFsWriteFile(
    LPCWSTR		FileName,
    LPCVOID		Buffer,
    DWORD		NumberOfBytesToWrite,
    LPDWORD		pNumberOfBytesWritten,
    LONGLONG			Offset,
    PDOKAN_FILE_INFO	DokanFileInfo)
{
	readLock readlock(*_namespaceMutex);
    HANDLE	handle = (HANDLE)DokanFileInfo->Context;

	logw(L"WriteFile : <%s>, offset %I64d, NumberOfBytesToWrite: %d", FileName, Offset, NumberOfBytesToWrite);

	uint32_t fileId;
	if (!handle || handle == INVALID_HANDLE_VALUE) {
		logw(L"invalid handle, cleanuped?");
		fileId = checkNameSpace(FileName);
		if (fileId == 0)
			return STATUS_OBJECT_NAME_NOT_FOUND;
	}
	else
		fileId = (uint32_t)DokanFileInfo->Context;

	struct FileMetaData fileMetaData = getAndCacheFileMetaData(fileId);
    if (DokanFileInfo->WriteToEndOfFile)
    {
		Offset = fileMetaData._size;
    }
	
	uint64_t sizeWritten = 0;
	const char* bufptr = (char*)Buffer;

	while (sizeWritten < (uint64_t)NumberOfBytesToWrite) {
		uint32_t segmentCount = ((uint64_t)Offset + sizeWritten) / (uint64_t)_segmentSize;
		{
			writeLock wtLock(*obtainFileRWMutex(fileId));
			//fileMetaData = getAndCacheFileMetaData(fileId);
			while (segmentCount >= fileMetaData._segmentList.size()) {
				fileMetaData = getAndCacheFileMetaData(fileId);
				if (segmentCount >= fileMetaData._segmentList.size()) {
					//fileMetaData = getAndCacheFileMetaData(fileId);
					struct SegmentMetaData segmentMetaData = allocateSegmentMetaData();
					fileMetaData._segmentList.push_back(segmentMetaData._id);
					logw(L"Added Segment List %d", segmentMetaData._id);
					fileMetaData._primaryList.push_back(segmentMetaData._primary);
					_fileMetaDataCache->saveMetaData(fileMetaData);
				} // else someone else has already allocate for this offset
			}
		}
		uint64_t segmentId = fileMetaData._segmentList[segmentCount];
		uint32_t primary = fileMetaData._primaryList[segmentCount];
		uint32_t segmentOffset = (uint64_t)Offset + sizeWritten - ((uint64_t)segmentCount * _segmentSize);
		uint32_t writeSize = _segmentSize - segmentOffset;
		if ((uint64_t)NumberOfBytesToWrite - sizeWritten < writeSize)
			writeSize = (uint64_t)NumberOfBytesToWrite - sizeWritten;
		uint32_t retstat = _fileDataCache->writeDataCache(segmentId, primary, bufptr, writeSize, segmentOffset, fileMetaData._fileType);
		bufptr += retstat;
		sizeWritten += retstat;
	}

	if ((Offset + sizeWritten) > fileMetaData._size)
		fileMetaData._size = Offset + sizeWritten;
	_fileMetaDataCache->saveMetaData(fileMetaData);

	*pNumberOfBytesWritten = sizeWritten;
	return STATUS_SUCCESS;
}

NTSTATUS CodFsFlushFileBuffers(
    LPCWSTR		FileName,
    PDOKAN_FILE_INFO	DokanFileInfo)
{
	readLock readlock(*_namespaceMutex);
    HANDLE	handle = (HANDLE)DokanFileInfo->Context;
    std::wstring filePath = GetFilePath(FileName);

    logw(L"FlushFileBuffers : %s", filePath.c_str());

    if (!handle || handle == INVALID_HANDLE_VALUE) {
        logw(L"invalid handle, but return success");
        return STATUS_SUCCESS;
    }

	if (DokanFileInfo->IsDirectory)
		return STATUS_SUCCESS;

	uint32_t fileId = checkNameSpace(FileName);

	if (fileId > 0){
		struct FileMetaData fileMetaData = getAndCacheFileMetaData(fileId);
		//debug("File Metadata for %" PRIu32 "Loaded\n", fileId);

		for (uint32_t i = 0; i < fileMetaData._segmentList.size(); ++i) {
			_fileDataCache->closeDataCache(fileMetaData._segmentList[i], true);
		}

		_clientCommunicator->saveFileSize(_clientId, fileId, fileMetaData._size);
		_clientCommunicator->saveSegmentList(_clientId, fileId, fileMetaData._segmentList);
		logw(L"File Information Sent\n");
	}

	return STATUS_SUCCESS;
}


NTSTATUS CodFsGetFileInformation(
    LPCWSTR							FileName,
    LPBY_HANDLE_FILE_INFORMATION	HandleFileInformation,
    PDOKAN_FILE_INFO				DokanFileInfo)
{
	readLock readlock(*_namespaceMutex);
    //HANDLE	handle = (HANDLE)DokanFileInfo->Context;
	HANDLE	handle;

    std::wstring filePath = GetFilePath(FileName);

    logw(L"GetFileInfo : %s", filePath.c_str());

	DWORD fileAttr = GetFileAttributes(filePath.c_str());
	if (fileAttr == INVALID_FILE_ATTRIBUTES) {
		DWORD dwError = GetLastError();
		logw(L"Get File Attributes Failed %s code %d", filePath.c_str(), dwError);
		return ToNtStatus(dwError);
	}
	else if (fileAttr & FILE_ATTRIBUTE_DIRECTORY)
		DokanFileInfo->IsDirectory = true;

	if (DokanFileInfo->IsDirectory){
		HANDLE	handle = (HANDLE)DokanFileInfo->Context;
		if (!GetFileInformationByHandle(handle, HandleFileInformation)){
			if (wcslen(FileName) == 1) {
				logw(L"  root dir");
				HandleFileInformation->dwFileAttributes = GetFileAttributes(filePath.c_str());
				return STATUS_SUCCESS;
			}
			logw(L"Error");
		}
		else {
			return STATUS_SUCCESS;
		}
	}

	logw(L"Using Find First File");
	WIN32_FIND_DATAW find;
	ZeroMemory(&find, sizeof(WIN32_FIND_DATAW));

	handle = FindFirstFile(filePath.c_str(), &find);
	if (handle == INVALID_HANDLE_VALUE) {
		DWORD dwError = GetLastError();
		logw(L"FindFirstFile failed(%d)", dwError);
		return ToNtStatus(dwError);
	}
	HandleFileInformation->dwFileAttributes = find.dwFileAttributes;
	HandleFileInformation->ftCreationTime = find.ftCreationTime;
	HandleFileInformation->ftLastAccessTime = find.ftLastAccessTime;
	HandleFileInformation->ftLastWriteTime = find.ftLastWriteTime;

	FindClose(handle);

	if ((fileAttr != INVALID_FILE_ATTRIBUTES) && (fileAttr & FILE_ATTRIBUTE_DIRECTORY)) {
		DokanFileInfo->IsDirectory = true;
	}
	else {
		uint32_t fileId = checkNameSpace(FileName);
		if (fileId == 0) {
			logw(L"No File ID Recorded for %s", filePath.c_str());
			return STATUS_OBJECT_NAME_NOT_FOUND;
		}
		FileMetaData fileMetaData = getAndCacheFileMetaData(fileId);
		HandleFileInformation->nFileSizeHigh = fileMetaData._size >> 32;
		HandleFileInformation->nFileSizeLow = fileMetaData._size & 0xFFFFFFFF;


	}
	logw(L"File Size %d", HandleFileInformation->nFileSizeLow);
	//CloseHandle(handle);

    return STATUS_SUCCESS;
}

NTSTATUS CodFsFindFiles(
    LPCWSTR				FileName,
    PFillFindData		FillFindData, // function pointer
    PDOKAN_FILE_INFO	DokanFileInfo)
{

	readLock readlock(*_namespaceMutex);
    HANDLE				hFind;
    WIN32_FIND_DATAW	findData;
    DWORD				error;
    PWCHAR				yenStar = L"\\*";
    int count = 0;
	
    std::wstring filePath = GetFilePath(FileName);
    filePath = filePath + yenStar;
    logw(L"FindFiles :%s", filePath.c_str());

    hFind = FindFirstFile(filePath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD dwError = GetLastError();
        logw(L"FindFirstFile failed(%d)", dwError);
        return ToNtStatus(dwError);
    }

	uint32_t fileId;
	struct FileMetaData fileMetaData;
	wstring searchPath = L"\\" + wstring(FileName) + L"\\" + wstring(findData.cFileName);
	fileId = checkNameSpace(searchPath);

	if (fileId != 0) {
		logw(L"Get Meta for %s <%d>", searchPath.c_str(),fileId);
		fileMetaData = getAndCacheFileMetaData(fileId);
		findData.nFileSizeHigh = fileMetaData._size >> 32;
		findData.nFileSizeLow = fileMetaData._size & 0xFFFFFFFF;
	}

    FillFindData(&findData, DokanFileInfo);
    count++;

    while (FindNextFile(hFind, &findData) != 0) {
		searchPath = L"\\" + wstring(FileName) + L"\\" + wstring(findData.cFileName);
		fileId = checkNameSpace(searchPath);
		if (fileId != 0) {
			logw(L"Get Meta for %s <%d>", searchPath.c_str(), fileId);
			fileMetaData = getAndCacheFileMetaData(fileId);
			findData.nFileSizeHigh = fileMetaData._size >> 32;
			findData.nFileSizeLow = fileMetaData._size & 0xFFFFFFFF;
		}
        FillFindData(&findData, DokanFileInfo);
        count++;
    }
    
    error = GetLastError();
    FindClose(hFind);

    if (error != ERROR_NO_MORE_FILES) {
        logw(L"FindFirstFile failed not ERROR_NO_MORE_FILES(%d)", error);
        return ToNtStatus(error);
    }

    logw(L"FindFiles return %d entries in %s", count, filePath.c_str());

    return STATUS_SUCCESS;
}


NTSTATUS CodFsDeleteFile(
    LPCWSTR				FileName,
    PDOKAN_FILE_INFO	DokanFileInfo)
{
	writeLock writelock(*_namespaceMutex);
    UNREFERENCED_PARAMETER(DokanFileInfo);
    //HANDLE	handle = (HANDLE)DokanFileInfo->Context;

    //std::wstring filePath = GetFilePath(FileName);

    logw(L"DeleteFile %s", FileName);
	uint32_t fileId = removeNameSpace(FileName);
	if (fileId != 0) {
		_fileMetaDataCache->removeMetaData(fileId);
		fileIdMap.erase(FileName);
	}

    return STATUS_SUCCESS;
}

NTSTATUS CodFsDeleteDirectory(
    LPCWSTR				FileName,
    PDOKAN_FILE_INFO	DokanFileInfo)
{

	writeLock writelock(*_namespaceMutex);
    UNREFERENCED_PARAMETER(DokanFileInfo);
    logw(L"Start<%s>", FileName);
//    HANDLE	handle = (HANDLE)DokanFileInfo->Context;
    HANDLE	hFind;
    WIN32_FIND_DATAW findData;
    std::wstring filePath = GetFilePath(FileName);

    logw(L"DeleteDirectory %s", filePath.c_str());

    filePath = AppendPathSeperatorIfNotExist(filePath, L'\\');
    filePath = filePath + L"*";

    hFind = FindFirstFile(filePath.c_str(), &findData);
    while (hFind != INVALID_HANDLE_VALUE) {
        if (wcscmp(findData.cFileName, L"..") != 0 &&
            wcscmp(findData.cFileName, L".") != 0) {
            FindClose(hFind);
            logw(L"  Directory is not empty: %s", findData.cFileName);
            return -(int)ERROR_DIR_NOT_EMPTY;
        }
        if (!FindNextFile(hFind, &findData)) {
            break;
        }
    }
    FindClose(hFind);

    DWORD dwError = GetLastError();
    if (dwError == ERROR_NO_MORE_FILES) {
        return STATUS_SUCCESS;
    } else {
        logw(L"FindFirstFile failed(%d)", dwError);
        return ToNtStatus(dwError);
    }
}


NTSTATUS CodFsMoveFile(
    LPCWSTR				FileName, // existing file name
    LPCWSTR				NewFileName,
    BOOL				ReplaceIfExisting,
    PDOKAN_FILE_INFO	DokanFileInfo)
{

	writeLock writelock(*_namespaceMutex);
    logw(L"Start. Origin<%s> Target<%s>", FileName, NewFileName);
    BOOL status;

    std::wstring filePath = GetFilePath(FileName);
    std::wstring newFilePath = GetFilePath(NewFileName);

    logw(L"MoveFile %s -> %s", filePath.c_str(), newFilePath.c_str());

	DWORD fileAttr = GetFileAttributes(filePath.c_str());
	logw(L"File Attributes = 0x%08X", fileAttr);
	if (fileAttr & FILE_ATTRIBUTE_DIRECTORY)
		DokanFileInfo->IsDirectory = true;

	if (DokanFileInfo->IsDirectory){
		if (DokanFileInfo->Context) {
			// should close? or rename at closing?
			CloseHandle((HANDLE)DokanFileInfo->Context);
			DokanFileInfo->Context = 0;
		}
	}

    if (ReplaceIfExisting)
        status = MoveFileEx(filePath.c_str(), newFilePath.c_str(), MOVEFILE_REPLACE_EXISTING);
    else
        status = MoveFile(filePath.c_str(), newFilePath.c_str());

    if (status == FALSE) {
        DWORD error = GetLastError();
        logw(L"MoveFile failed code = %d", error);
        return ToNtStatus(error);
    } else if (!DokanFileInfo->IsDirectory) {
		uint32_t fileId = checkNameSpace(NewFileName);
		wstring NewFileName_w(NewFileName);
		string newFilePath_s(NewFileName_w.begin(), NewFileName_w.end());
		_fileMetaDataCache->renameMetaData(fileId, newFilePath_s);
		fileIdMap.erase(FileName);
		fileIdMap[NewFileName] = fileId;
		if (fileId != 0)
			client->renameFileRequest(fileId, newFilePath_s);
        return STATUS_SUCCESS;
    }

	return STATUS_SUCCESS;
}

NTSTATUS CodFsLockFile(
    LPCWSTR				FileName,
    LONGLONG			ByteOffset,
    LONGLONG			Length,
    PDOKAN_FILE_INFO	DokanFileInfo)
{
	///TODO: Lock / Unlock File
	return STATUS_SUCCESS;

    HANDLE	handle;
    LARGE_INTEGER offset;
    LARGE_INTEGER length;

    std::wstring filePath = GetFilePath(FileName);

    logw(L"LockFile %s", filePath.c_str());

    handle = (HANDLE)DokanFileInfo->Context;
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        return STATUS_INVALID_HANDLE;
    }

    length.QuadPart = Length;
    offset.QuadPart = ByteOffset;

    if (LockFile(handle, offset.HighPart, offset.LowPart, length.HighPart, length.LowPart)) {
        logw(L"success");
        return STATUS_SUCCESS;
    } else {
        DWORD dwError = GetLastError();
        logw(L"failed(%d)", dwError);
        return ToNtStatus(dwError);
    }
}

NTSTATUS CodFsSetEndOfFile(
    LPCWSTR				FileName,
    LONGLONG			ByteOffset,
    PDOKAN_FILE_INFO	DokanFileInfo)
{
	readLock readlock(*_namespaceMutex);
    HANDLE			handle;

    std::wstring filePath = GetFilePath(FileName);

    logw(L"SetEndOfFile %s, %I64d", filePath.c_str(), ByteOffset);

    handle = (HANDLE)DokanFileInfo->Context;
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        return STATUS_INVALID_HANDLE;
    }

	uint32_t fileId = (uint32_t)DokanFileInfo->Context;
	writeLock wtLock(*obtainFileRWMutex(fileId));
	struct FileMetaData fileMetaData = getAndCacheFileMetaData(fileId);
	uint32_t fillSize = _segmentSize;
	if ((uint64_t)ByteOffset > fileMetaData._size) {
		fileMetaData._size = (uint64_t)ByteOffset;
		uint32_t segmentNum = getSegmentNum(ByteOffset);
		while (segmentNum > fileMetaData._segmentList.size()) {
			fileMetaData = getAndCacheFileMetaData(fileId);
			if (segmentNum > fileMetaData._segmentList.size()) {
				//fileMetaData = getAndCacheFileMetaData(fileId);
				struct SegmentMetaData segmentMetaData = allocateSegmentMetaData();
				fileMetaData._segmentList.push_back(segmentMetaData._id);
				fileMetaData._primaryList.push_back(segmentMetaData._primary);
				_fileMetaDataCache->saveMetaData(fileMetaData);
				if (segmentNum == fileMetaData._segmentList.size())
					fillSize = ByteOffset - ((segmentNum - 1)* _segmentSize);
				_fileDataCache->writeDataCache(segmentMetaData._id, segmentMetaData._primary, fillbuf, fillSize, 0, NORMAL);
			} // else someone else has already allocate for this offset
		}
	}
	else {
		fileMetaData._size = (uint64_t)ByteOffset;
		uint32_t segmentNum = getSegmentNum(ByteOffset);
		fileMetaData._segmentList.resize(segmentNum);
	}
	_fileMetaDataCache->saveMetaData(fileMetaData);

    return STATUS_SUCCESS;
}


NTSTATUS CodFsSetAllocationSize(
    LPCWSTR				FileName,
    LONGLONG			AllocSize,
    PDOKAN_FILE_INFO	DokanFileInfo)
{
	readLock readlock(*_namespaceMutex);
    HANDLE			handle;

    std::wstring filePath = GetFilePath(FileName);

    logw(L"SetAllocationSize %s, %I64d", filePath.c_str(), AllocSize);

    handle = (HANDLE)DokanFileInfo->Context;
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        return STATUS_INVALID_HANDLE;
    }

	uint32_t fileId = (uint32_t)DokanFileInfo->Context;
	writeLock wtLock(*obtainFileRWMutex(fileId));
	struct FileMetaData fileMetaData = getAndCacheFileMetaData(fileId);
	uint32_t fillSize = _segmentSize;
	if ((uint64_t)AllocSize > fileMetaData._size) {
		fileMetaData._size = (uint64_t)AllocSize;
		uint32_t segmentNum = getSegmentNum(AllocSize);
		while (segmentNum > fileMetaData._segmentList.size()) {
			fileMetaData = getAndCacheFileMetaData(fileId);
			if (segmentNum > fileMetaData._segmentList.size()) {
				//fileMetaData = getAndCacheFileMetaData(fileId);
				struct SegmentMetaData segmentMetaData = allocateSegmentMetaData();
				fileMetaData._segmentList.push_back(segmentMetaData._id);
				fileMetaData._primaryList.push_back(segmentMetaData._primary);
				_fileMetaDataCache->saveMetaData(fileMetaData);
				if (segmentNum == fileMetaData._segmentList.size())
					fillSize = AllocSize - ((segmentNum - 1)* _segmentSize);
				_fileDataCache->writeDataCache(segmentMetaData._id, segmentMetaData._primary, fillbuf, fillSize, 0, NORMAL);
			} // else someone else has already allocate for this offset
		}
		_fileMetaDataCache->saveMetaData(fileMetaData);
	}
    return STATUS_SUCCESS;
}

NTSTATUS CodFsSetFileAttributes(
    LPCWSTR				FileName,
    DWORD				FileAttributes,
    PDOKAN_FILE_INFO	DokanFileInfo)
{
	readLock readlock(*_namespaceMutex);
    UNREFERENCED_PARAMETER(DokanFileInfo);

    std::wstring filePath = GetFilePath(FileName);

    logw(L"SetFileAttributes %s", filePath.c_str());

    if (!SetFileAttributes(filePath.c_str(), FileAttributes)) {
        DWORD error = GetLastError();
        logw(L"error code = %d", error);
        return ToNtStatus(error);
    }

    logw(L"");
    return STATUS_SUCCESS;
}

NTSTATUS CodFsSetFileTime(
    LPCWSTR				FileName,
    CONST FILETIME*		CreationTime,
    CONST FILETIME*		LastAccessTime,
    CONST FILETIME*		LastWriteTime,
    PDOKAN_FILE_INFO	DokanFileInfo)
{
	readLock readlock(*_namespaceMutex);
    HANDLE	handle;

    std::wstring filePath = GetFilePath(FileName);

    logw(L"SetFileTime %s", filePath.c_str());
	
	bool opened = false;
	if (checkNameSpace(FileName) > 0){
		handle = CreateFile(filePath.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
		opened = true;
	}
	else {
		handle = (HANDLE)DokanFileInfo->Context;
	}

	if (!handle || handle == INVALID_HANDLE_VALUE) {
		return STATUS_INVALID_HANDLE;
	}
	if (!SetFileTime(handle, CreationTime, LastAccessTime, LastWriteTime)) {
		DWORD error = GetLastError();
		logw(L"error code = %d", error);
		if (opened)
			CloseHandle(handle);
		return ToNtStatus(error);
	}

	if (opened)
		CloseHandle(handle);
    logw(L"");
    return STATUS_SUCCESS;
}

NTSTATUS CodFsUnlockFile(
    LPCWSTR				FileName,
    LONGLONG			ByteOffset,
    LONGLONG			Length,
    PDOKAN_FILE_INFO	DokanFileInfo)
{
	///TODO: Lock / Unlock File
	return STATUS_SUCCESS;
	

    HANDLE	handle;
    LARGE_INTEGER	length;
    LARGE_INTEGER	offset;

    std::wstring filePath = GetFilePath(FileName);

    logw(L"UnlockFile %s", filePath.c_str());

    handle = (HANDLE)DokanFileInfo->Context;
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        return STATUS_INVALID_HANDLE;
    }

    length.QuadPart = Length;
    offset.QuadPart = ByteOffset;

    if (UnlockFile(handle, offset.HighPart, offset.LowPart, length.HighPart, length.LowPart)) {
        logw(L"success");
        return STATUS_SUCCESS;
    } else {
        DWORD error = GetLastError();
        logw(L"error code = %d", error);
        return ToNtStatus(error);
    }
}

NTSTATUS CodFsGetFileSecurity(
    LPCWSTR					FileName,
    PSECURITY_INFORMATION	SecurityInformation,
    PSECURITY_DESCRIPTOR	SecurityDescriptor,
    ULONG				BufferLength,
    PULONG				LengthNeeded,
    PDOKAN_FILE_INFO	DokanFileInfo)
{
	readLock readlock(*_namespaceMutex);
    HANDLE	handle;
    std::wstring filePath = GetFilePath(FileName);

    logw(L"GetFileSecurity %s", filePath.c_str());

    handle = (HANDLE)DokanFileInfo->Context;
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        return STATUS_INVALID_HANDLE;
    }

    if (!GetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor,
            BufferLength, LengthNeeded)) {
        int error = GetLastError();
        if (error == ERROR_INSUFFICIENT_BUFFER) {
            logw(L"  GetUserObjectSecurity failed: ERROR_INSUFFICIENT_BUFFER");
            return STATUS_BUFFER_OVERFLOW;
        } else {
            logw(L"  GetUserObjectSecurity failed: %d", error);
            return ToNtStatus(error);
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS CodFsSetFileSecurity(
    LPCWSTR					FileName,
    PSECURITY_INFORMATION	SecurityInformation,
    PSECURITY_DESCRIPTOR	SecurityDescriptor,
    ULONG				/*SecurityDescriptorLength*/,
    PDOKAN_FILE_INFO	DokanFileInfo)
{
	readLock readlock(*_namespaceMutex);
    HANDLE	handle;
    std::wstring filePath = GetFilePath(FileName);

    logw(L"SetFileSecurity %s", filePath.c_str());

    handle = (HANDLE)DokanFileInfo->Context;
    if (!handle || handle == INVALID_HANDLE_VALUE) {
        logw(L"invalid handle");
        return STATUS_INVALID_HANDLE;
    }

    if (!SetUserObjectSecurity(handle, SecurityInformation, SecurityDescriptor)) {
        int error = GetLastError();
        logw(L"  SetUserObjectSecurity failed: %d", error);
        return ToNtStatus(error);
    }
    return STATUS_SUCCESS;
}

NTSTATUS CodFsGetVolumeInformation(
    LPWSTR		VolumeNameBuffer,
    DWORD		VolumeNameSize,
    LPDWORD		VolumeSerialNumber,
    LPDWORD		MaximumComponentLength,
    LPDWORD		FileSystemFlags,
    LPWSTR		FileSystemNameBuffer,
    DWORD		FileSystemNameSize,
    PDOKAN_FILE_INFO	/*DokanFileInfo*/)
{
    wcscpy_s(VolumeNameBuffer, VolumeNameSize / sizeof(WCHAR), L"CodFS");
    *VolumeSerialNumber = 0x19831116;
    *MaximumComponentLength = 256;
    *FileSystemFlags = FILE_CASE_SENSITIVE_SEARCH | 
                        FILE_CASE_PRESERVED_NAMES | 
                        FILE_SUPPORTS_REMOTE_STORAGE |
                        FILE_UNICODE_ON_DISK |
                        FILE_PERSISTENT_ACLS;

    wcscpy_s(FileSystemNameBuffer, FileSystemNameSize / sizeof(WCHAR), L"CodFS");

    return STATUS_SUCCESS;
}

NTSTATUS CodFsUnmount(PDOKAN_FILE_INFO	DokanFileInfo)
{
    UNREFERENCED_PARAMETER(DokanFileInfo);
    logw(L"Unmount");
    return STATUS_SUCCESS;
}

NTSTATUS
CodFsGetDiskFreeSpace(
PULONGLONG freeBytesAvailable,
PULONGLONG totalBytes,
PULONGLONG freeBytes,
PDOKAN_FILE_INFO	FileInfo
) {
	*totalBytes = (ULONGLONG)100 * 1024 * 1024 * 1024; // 100GB
	*freeBytes = *totalBytes;
	*freeBytesAvailable = *totalBytes;
	return STATUS_SUCCESS;
}

int _tmain(int argc, _TCHAR* argv[])
{
    int status;
    int command;
    PDOKAN_OPERATIONS dokanOperations = (PDOKAN_OPERATIONS)malloc(sizeof(DOKAN_OPERATIONS));
    if (dokanOperations == nullptr)
    {
        return EXIT_FAILURE;
    }

    PDOKAN_OPTIONS dokanOptions = (PDOKAN_OPTIONS)malloc(sizeof(DOKAN_OPTIONS));
    if (dokanOperations == nullptr)
    {
        free(dokanOperations);
        return EXIT_FAILURE;
    }

    if (argc < 5) {
        fprintf(stderr, "CodFs.exe\n"
            "  /r RootDirectory (ex. /r c:\\test)\n"
            "  /l DriveLetter (ex. /l m)\n"
            "  /t ThreadCount (ex. /t 5)\n"
            "  /d (enable debug output)\n"
            "  /s (use stderr for output)\n"
            "  /n (use network drive)\n"
            "  /m (use removable drive)");
        return EXIT_FAILURE;
    }

    g_DebugMode = FALSE;
    g_UseStdErr = FALSE;

    ZeroMemory(dokanOptions, sizeof(DOKAN_OPTIONS));
    dokanOptions->Version = DOKAN_VERSION;
    dokanOptions->ThreadCount = 0; // use default

    for (command = 1; command < argc; command++) {
        switch (towlower(argv[command][1])) {
        case L'r':
            command++;
            wcscpy_s(g_RootDirectory, _countof(g_RootDirectory), argv[command]);
            logw(L"RootDirectory: %ls", g_RootDirectory);
            break;
        case L'l':
            command++;
            wcscpy_s(g_MountPoint, _countof(g_MountPoint), argv[command]);
            dokanOptions->MountPoint = g_MountPoint;
            break;
        case L't':
            command++;
            dokanOptions->ThreadCount = (USHORT)_wtoi(argv[command]);
            break;
        case L'd':
            g_DebugMode = TRUE;
            break;
        case L's':
            g_UseStdErr = TRUE;
            break;
        case L'n':
            dokanOptions->Options |= DOKAN_OPTION_NETWORK;
            break;
        case L'm':
            dokanOptions->Options |= DOKAN_OPTION_REMOVABLE;
            break;
        default:
            fwprintf(stderr, L"unknown command: %s", argv[command]);
            free(dokanOperations);
            free(dokanOptions);
            return EXIT_FAILURE;
        }
    }

    if (g_DebugMode) {
        dokanOptions->Options |= DOKAN_OPTION_DEBUG;
    }
    if (g_UseStdErr) {
        dokanOptions->Options |= DOKAN_OPTION_STDERR;
    }

    dokanOptions->Options |= DOKAN_OPTION_KEEP_ALIVE;

    ZeroMemory(dokanOperations, sizeof(DOKAN_OPERATIONS));
    dokanOperations->CreateFile = CodFsCreateFile;
    dokanOperations->OpenDirectory = CodFsOpenDirectory;
    dokanOperations->CreateDirectory = CodFsCreateDirectory;
    dokanOperations->Cleanup = CodFsCleanup;
    dokanOperations->CloseFile = CodFsCloseFile;
    dokanOperations->ReadFile = CodFsReadFile;
    dokanOperations->WriteFile = CodFsWriteFile;
    dokanOperations->FlushFileBuffers = CodFsFlushFileBuffers;
    dokanOperations->GetFileInformation = CodFsGetFileInformation;
    dokanOperations->FindFiles = CodFsFindFiles;
    dokanOperations->FindFilesWithPattern = nullptr;
    dokanOperations->SetFileAttributes = CodFsSetFileAttributes;
    dokanOperations->SetFileTime = CodFsSetFileTime;
    dokanOperations->DeleteFile = CodFsDeleteFile;
    dokanOperations->DeleteDirectory = CodFsDeleteDirectory;
    dokanOperations->MoveFile = CodFsMoveFile;
    dokanOperations->SetEndOfFile = CodFsSetEndOfFile;
    dokanOperations->SetAllocationSize = CodFsSetAllocationSize;
    dokanOperations->LockFile = CodFsLockFile;
    dokanOperations->UnlockFile = CodFsUnlockFile;
    dokanOperations->GetFileSecurity = CodFsGetFileSecurity;
    dokanOperations->SetFileSecurity = CodFsSetFileSecurity;
	//dokanOperations->GetDiskFreeSpace = nullptr;
	dokanOperations->GetDiskFreeSpace = CodFsGetDiskFreeSpace;
    dokanOperations->GetVolumeInformation = CodFsGetVolumeInformation;
    dokanOperations->Unmount = CodFsUnmount;

	codfs_init();
    status = DokanMain(dokanOptions, dokanOperations);
    switch (status) {
    case DOKAN_SUCCESS:
        fprintf(stderr, "Success");
        break;
    case DOKAN_ERROR:
        fprintf(stderr, "Error");
        break;
    case DOKAN_DRIVE_LETTER_ERROR:
        fprintf(stderr, "Bad Drive letter");
        break;
    case DOKAN_DRIVER_INSTALL_ERROR:
        fprintf(stderr, "Can't install driver");
        break;
    case DOKAN_START_ERROR:
        fprintf(stderr, "Driver something wrong");
        break;
    case DOKAN_MOUNT_ERROR:
        fprintf(stderr, "Can't assign a drive letter");
        break;
    case DOKAN_MOUNT_POINT_ERROR:
        fprintf(stderr, "Mount point error");
        break;
    default:
        fprintf(stderr, "Unknown error: %d", status);
        break;
    }

    free(dokanOptions);
    free(dokanOperations);

    return 0;
}