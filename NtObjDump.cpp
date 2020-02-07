// NtObjDump.cpp : Defines the entry point for the console application.
//
// todo: 
//	- windowstation handle support is currently br0ken 
//	- ALPC ports are currently not supported 
//  - registry objects currently not supported (should it be?)


#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <sddl.h>

#if defined(DEBUGLVL)
#define DBGPRINT(x) (x)
#else
#define DBGPRINT(x)
#endif

#pragma comment(lib, "User32")
#pragma comment(lib, "Advapi32")

/*  ----------/ structs and defines to make this all work /---------- */
typedef struct
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJDIR_INFORMATION {
	UNICODE_STRING          ObjectName;
	UNICODE_STRING          ObjectTypeName;
	BYTE                    Data[1];
} OBJDIR_INFORMATION;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	UNICODE_STRING *ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof(OBJECT_ATTRIBUTES);          \
	(p)->RootDirectory = r;                             \
	(p)->Attributes = a;                                \
	(p)->ObjectName = n;                                \
	(p)->SecurityDescriptor = s;                        \
	(p)->SecurityQualityOfService = NULL;               \
}


#define InitializeUnicodeStr(p,s) { \
	(p)->Length = wcslen(s) * 2;			\
	(p)->MaximumLength = wcslen(s) * 2 + 2; \
	(p)->Buffer = s;					\
}

#define SYMBOLIC_LINK_QUERY 1

#define FILE_SUPERSEDE                  0x00000000
#define FILE_OPEN                       0x00000001
#define FILE_CREATE                     0x00000002
#define FILE_OPEN_IF                    0x00000003
#define FILE_OVERWRITE                  0x00000004
#define FILE_OVERWRITE_IF               0x00000005
#define FILE_MAXIMUM_DISPOSITION        0x00000005

typedef struct _STRING64 {
	USHORT   Length;
	USHORT   MaximumLength;
	ULONGLONG  Buffer;
} STRING64;
typedef STRING64 *PSTRING64;

typedef STRING64 UNICODE_STRING64;
typedef UNICODE_STRING64 *PUNICODE_STRING64;

typedef struct _FILE_FULL_EA_INFORMATION {
	ULONG NextEntryOffset;
	UCHAR Flags;
	UCHAR EaNameLength;
	USHORT EaValueLength;
	CHAR EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef struct _FLT_CONNECT_CONTEXT  {
	PUNICODE_STRING PortName;
	PUNICODE_STRING64 PortName64;
	USHORT SizeOfContext;
	DECLSPEC_ALIGN(8) UCHAR Context[1];
} FLT_CONNECT_CONTEXT, *PFLT_CONNECT_CONTEXT;

#define FLT_CONNECT_CONTEXT_STRING  "FLTPORT"
#define FLT_PORT_FLAG_SYNC_HANDLE       0x00000001
#define FLT_PORT_FLAG_VALID_FLAGS   (FLT_PORT_FLAG_SYNC_HANDLE)
#define FLTMSG_NT_NAME           L"\\Global\?\?\\FltMgrMsg"

#define FilterAlloc(N) malloc(N)
#define FilterFree(P)  free(P)

#define MAXUSHORT   0xffff
#define MAX_USTRING ( sizeof(WCHAR) * (MAXUSHORT/sizeof(WCHAR)) )

#define OBJ_INHERIT             0x00000002L
#define OBJ_CASE_INSENSITIVE    0x00000040L

typedef struct _GENERIC_OBJECT {
	unsigned int len;
	BYTE *sd;
}GENERIC_OBJECT, *PGENERIC_OBJECT;

typedef struct _SYMLINK_OBJECT {
	PGENERIC_OBJECT go;
	WCHAR *link;
}SYMLINK_OBJECT, *PSYMLINK_OBJECT;


typedef struct _OBJECT {
	struct _OBJECT *next;
	WCHAR *name;
	WCHAR *type;

	// union in case we need more object specific stuff 
	union {
		PGENERIC_OBJECT obj;
		PSYMLINK_OBJECT sym;
	};

} OBJECT, *POBJECT;

/*  ----------/ Function typedefs /---------- */

typedef DWORD(WINAPI* NTQUERYDIRECTORYOBJECT)(HANDLE, OBJDIR_INFORMATION*, DWORD, DWORD, DWORD, DWORD*, DWORD*);
NTQUERYDIRECTORYOBJECT NtQueryDirectoryObject;

typedef DWORD(WINAPI* NTOPENDIRECTORYOBJECT)(HANDLE *, DWORD, OBJECT_ATTRIBUTES*);
NTOPENDIRECTORYOBJECT  NtOpenDirectoryObject;

typedef DWORD(WINAPI* NTQUERYSECURITYOBJECT)(HANDLE Handle, SECURITY_INFORMATION SecurityInformation, PSECURITY_DESCRIPTOR SecurityDescriptor, ULONG Length, PULONG LengthNeeded);
NTQUERYSECURITYOBJECT NtQuerySecurityObject;

typedef DWORD(WINAPI* NTOPENFILE)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);
NTOPENFILE NtOpenFile;

typedef DWORD(WINAPI* NTQUERYSYMBOLICLINKOBJECT)(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength);
NTQUERYSYMBOLICLINKOBJECT NtQuerySymbolicLinkObject;

typedef NTSTATUS(WINAPI * NTCREATEFILE)(PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,PLARGE_INTEGER AllocationSize,ULONG FileAttributes,ULONG ShareAccess,ULONG CreateDisposition,ULONG CreateOptions,PVOID EaBuffer,ULONG EaLength);
NTCREATEFILE NtCreateFile;


typedef DWORD(WINAPI* NTOPENOBJECT)(PHANDLE Handle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
NTOPENOBJECT NtOpenMutant;
NTOPENOBJECT NtOpenEvent;
NTOPENOBJECT NtOpenSection;
NTOPENOBJECT NtOpenSymbolicLinkObject;
NTOPENOBJECT NtOpenSemaphore;
NTOPENOBJECT NtOpenJobObject;
NTOPENOBJECT NtOpenTimer;
NTOPENOBJECT NtOpenKeyedEvent;
NTOPENOBJECT NtOpenSession;

/*  ----------/ Cruft needed for connection ports /---------- */

// needed, called by FilterConnectCommunicationPort
VOID RtlInitUnicodeString(PUNICODE_STRING DestinationString, PCWSTR SourceString){
	SIZE_T Length;
	DestinationString->MaximumLength = 0;
	DestinationString->Length = 0;
	DestinationString->Buffer = (PWSTR)SourceString;
	if ((SourceString)) {
		Length = wcslen(SourceString) * sizeof(WCHAR);
		if (Length >= MAX_USTRING) {
			Length = MAX_USTRING - sizeof(UNICODE_NULL);
		}
		DestinationString->Length = (USHORT)Length;
		DestinationString->MaximumLength = (USHORT)(Length + sizeof(UNICODE_NULL));
	}
	return;
}

// can't just call this API since I need READ_CONTROL, 
// which the API doesn't offer, hence copied it over. 
HRESULT WINAPI FilterConnectCommunicationPort(
	LPCWSTR lpPortName,
	DWORD dwOptions,
	LPCVOID lpContext,
	WORD wSizeOfContext,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	HANDLE *hPort
	){
	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK ioStatus;
	HANDLE port = INVALID_HANDLE_VALUE;
	HRESULT returnValue = S_OK;
	UNICODE_STRING deviceName;
	UNICODE_STRING portName;
	UNICODE_STRING64 portName64;
	PFILE_FULL_EA_INFORMATION eaBuffer = NULL;
	PFLT_CONNECT_CONTEXT connectContext;
	NTSTATUS status;
	ULONG eaLength = 0;
	UCHAR strLength;
	USHORT valLength;
	ULONG createOptions = 0;

	if (((lpContext) && (wSizeOfContext == 0)) ||
		(!(lpContext) && (wSizeOfContext != 0))) {

		return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
	}

	if (dwOptions & ~FLT_PORT_FLAG_VALID_FLAGS) {

		return HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER);
	}

	strLength = (UCHAR)strlen(FLT_CONNECT_CONTEXT_STRING);
	valLength = FIELD_OFFSET(FLT_CONNECT_CONTEXT, Context) + wSizeOfContext;
	eaLength = sizeof(FILE_FULL_EA_INFORMATION)+valLength + strLength;
	eaBuffer = (PFILE_FULL_EA_INFORMATION)FilterAlloc(eaLength);

	if (NULL == eaBuffer){
		return HRESULT_FROM_WIN32(ERROR_OUTOFMEMORY);
	}

	eaBuffer->NextEntryOffset = 0;
	eaBuffer->Flags = 0;
	eaBuffer->EaNameLength = strLength;
	eaBuffer->EaValueLength = valLength;

	RtlCopyMemory(eaBuffer->EaName, FLT_CONNECT_CONTEXT_STRING, strLength + 1);
	connectContext = (PFLT_CONNECT_CONTEXT)(eaBuffer->EaName + eaBuffer->EaNameLength + 1);

	RtlInitUnicodeString(&portName, lpPortName);

	portName64.Buffer = (ULONGLONG)(ULONG_PTR)portName.Buffer;
	portName64.Length = portName.Length;
	portName64.MaximumLength = portName.MaximumLength;

	connectContext->PortName = &portName;
	connectContext->PortName64 = &portName64;
	connectContext->SizeOfContext = wSizeOfContext;

	if (wSizeOfContext > 0) {
		RtlCopyMemory(connectContext->Context, lpContext, wSizeOfContext);
	}

	RtlInitUnicodeString(&deviceName, FLTMSG_NT_NAME);

	InitializeObjectAttributes(&oa,
		&deviceName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		NULL);

	if ((lpSecurityAttributes)) {

		oa.SecurityDescriptor = lpSecurityAttributes->lpSecurityDescriptor;

		if (lpSecurityAttributes->bInheritHandle) {

			oa.Attributes |= OBJ_INHERIT;
		}
	}

	status = NtCreateFile(&port,
		FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE | READ_CONTROL,  // default implementation doesn't give READ_CONTROL
		&oa,
		&ioStatus,
		NULL,
		0,
		0,
		FILE_OPEN_IF,
		createOptions,
		eaBuffer,
		eaLength);


	FilterFree(eaBuffer);

	if (status != 0) {
		port = INVALID_HANDLE_VALUE;
	}
	*hPort = port;
	return returnValue;
}

//	POBJECT rootObject = NULL;

/*  ----------/ creating objects /---------- */

PGENERIC_OBJECT	newSecurityObject(BYTE *sd, ULONG len){
	PGENERIC_OBJECT go = (PGENERIC_OBJECT)calloc(sizeof(GENERIC_OBJECT), 1);
	if (!go) return NULL;

	go->sd = (BYTE *)calloc(len, 1);
	if (!go->sd) {
		free(go);
		return NULL;
	}

	memcpy(go->sd, sd, len);
	go->len = len;
	return go;
}

PSYMLINK_OBJECT newSymlinkObject(WCHAR *link) {
	PSYMLINK_OBJECT so = (PSYMLINK_OBJECT)calloc(sizeof(SYMLINK_OBJECT), 1);
	if (!so) return NULL;
	so->link = (WCHAR *)_wcsdup(link);
	if (!so->link) {
		free(so);
		return NULL;
	}
	return so;

}

POBJECT newObject(WCHAR *name, WCHAR *type, PGENERIC_OBJECT go, PSYMLINK_OBJECT so) {
	POBJECT po = (POBJECT)calloc(sizeof(OBJECT), 1);
	if (!po) return NULL;

	po->name = _wcsdup(name);
	po->type = _wcsdup(type);
	if (!po->name || !po->type) {
		free(po->name);
		free(po->type);
		free(po);
		return NULL;
	}
	if (so) {
		po->sym = so;
	}
	else {
		po->obj = go;
	}

	return po;
}

void freeSecurityObject(PGENERIC_OBJECT go) {
	if (go) {
		free(go->sd);
		free(go);
	}
	return;
}

void freeSymlinkObject(PSYMLINK_OBJECT so) {
	if (so) {
		free(so->link);
		freeSecurityObject(so->go);
		free(so);
	}
	return;
}

POBJECT last(POBJECT po){
	if (!po) return NULL;

	while (po->next) {
		po = po->next;
	}

	return po;
}

/*  ----------/ Query routines /---------- */

PGENERIC_OBJECT querySecurityDescriptor(HANDLE h, WCHAR *typeName) {
	ULONG ln = 0;
	SECURITY_INFORMATION si;
	BYTE sd[1000];

	si = OWNER_SECURITY_INFORMATION |
		GROUP_SECURITY_INFORMATION |
		DACL_SECURITY_INFORMATION; // | SACL_SECURITY_INFORMATION ;

	DWORD rr = NtQuerySecurityObject(h, si, (PSECURITY_DESCRIPTOR)sd, sizeof(sd), &ln);
	if (rr == 0) {
		LPWSTR SddlString;
		if (ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, si, &SddlString, NULL)){
			DBGPRINT(printf("SDDL string: %ws\n", SddlString);)
			LocalFree(SddlString);
		}
		return newSecurityObject(sd, ln);
	}
	else {
		DBGPRINT(printf("!!!!! NtQuerySecurityObject(%S) failed (rr=0x%x) [0x%x] length needed: %u!!!!!\n", typeName, rr, GetLastError(), ln);)
	}
	return NULL;
}

PGENERIC_OBJECT querySecurity(WCHAR *path, NTOPENOBJECT OpenObject, WCHAR *typeName) {
	HANDLE h;
	OBJECT_ATTRIBUTES lobj;
	UNICODE_STRING lstr;
	SECURITY_INFORMATION si;
	UNICODE_STRING str;
	BYTE sd[1000];
	PGENERIC_OBJECT go;

	InitializeUnicodeStr(&str, path);
	InitializeObjectAttributes(&lobj, &str, 0, 0, 00);
	DWORD rr = OpenObject(&h, READ_CONTROL /* | ACCESS_SYSTEM_SECURITY */, &lobj);
	if (rr == 0) {
		go = querySecurityDescriptor(h, typeName);
		CloseHandle(h); 
		return go;
	}
	else {
		DBGPRINT(printf("!!!!! OpenObject(%S) failed (rr=0x%x) [0x%x] !!!!!\n", typeName, rr, GetLastError());)
	}
	return NULL;
}

PSYMLINK_OBJECT queryLink(WCHAR *path) {
	HANDLE h;
	OBJECT_ATTRIBUTES lobj;
	UNICODE_STRING lstr, outstr;
	WCHAR link[2000];
	memset(link, 0x00, sizeof(link));
	PSYMLINK_OBJECT so = NULL;
	InitializeUnicodeStr(&lstr, path);
	InitializeObjectAttributes(&lobj, &lstr, 0, 0, 00);

	DWORD rr = NtOpenSymbolicLinkObject(&h, READ_CONTROL | SYMBOLIC_LINK_QUERY, &lobj);
	if (rr == 0) {
		ULONG ln = 0;
		outstr.Buffer = link;
		outstr.Length = 0;
		outstr.MaximumLength = sizeof(link) / sizeof(link[0]);
		rr = NtQuerySymbolicLinkObject(h, &outstr, &ln);
		if (rr == 0) {
			DBGPRINT(printf("!!!!! symlink to: %S\n", link);)
			so = newSymlinkObject(link);
		}
		else {
			DBGPRINT(printf("NtQuerySymbolicLinkObject() rr=0x%x, gle=0x%x, ln=%u failed\n", rr, GetLastError(), ln);)
		}
		CloseHandle(h);
	}
	else {
		DBGPRINT(printf("NtOpenSymbolicLinkObject() failed\n");)
	}

	return so;
}

/*
 using NtOpenFile() with pretty standard arguments to open devices. 
 A fair amount crap out with all sorts of error codes (see below), 
 even when done as admin.  This is likely because any drivers create 
 dispatch can handle the open any way it sees fit, and as such there 
 isn't much consistency between the return values. 

 There might be a better way to open devices. Need to look into this. 
*/
PGENERIC_OBJECT queryDevice(WCHAR *path) {
	HANDLE h;
	OBJECT_ATTRIBUTES lobj;
	UNICODE_STRING lstr, outstr;
	WCHAR link[2000];
	SECURITY_INFORMATION si;
	UNICODE_STRING str;
	BYTE sd[1000];


	memset(link, 0x00, sizeof(link));

	InitializeUnicodeStr(&lstr, path);
	InitializeObjectAttributes(&lobj, &lstr, 0, 0, 00);
	IO_STATUS_BLOCK isb;
	memset(&isb, 0x00, sizeof(isb));

	DWORD rr = NtOpenFile(&h, FILE_GENERIC_READ, &lobj, &isb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN);
	if (rr == 0) {
		PGENERIC_OBJECT go = querySecurityDescriptor(h, L"Device");
		CloseHandle(h);
		return go;
	}
	else {
		/* common error return values: 
			0xc0000001 (STATUS_UNSUCCESSFUL)
			0xc0000002 (STATUS_NOT_IMPLEMENTED)
			0xc000000d (STATUS_INVALID_PARAMETER)
			0xc000000e (STATUS_NO_SUCH_DEVICE)
			0xc0000010 (STATUS_INVALID_DEVICE_REQUEST)
			0xc0000022 (STATUS_ACCESS_DENIED)
			0xc0000034 (STATUS_OBJECT_NAME_NOT_FOUND)
			0xc0000061 (STATUS_PRIVILEGE_NOT_HELD)
			0xc0000103 (STATUS_NOT_A_DIRECTORY)
			0xc0000225 (STATUS_NOT_FOUND) 
			0xc0010019 (??? NDIS_STATUS_UNSUPPORTED_MEDIA ???)
			*/
		DBGPRINT(printf("NtOpenFile(Device) failed: 0x%x\n", rr);)
	}

	return NULL;
}

// TODO. this is currently broken. 
void queryWindowStation(WCHAR *path) {
	HANDLE h;
	OBJECT_ATTRIBUTES lobj;
	UNICODE_STRING lstr, outstr;
	SECURITY_INFORMATION si;
	UNICODE_STRING str;
	BYTE sd[1000];

	InitializeUnicodeStr(&lstr, path);
	InitializeObjectAttributes(&lobj, &lstr, 0, 0, 00);

	// gdi32.dll has NtOpenWindowStation() but it's not exported ... 
	h = (HANDLE)OpenWindowStationW(path, FALSE, WINSTA_ENUMDESKTOPS);
	if (h) {
		querySecurityDescriptor(h, L"WindowStation");
		CloseHandle(h);
	}
	else {
		DBGPRINT(printf("NtUserOpenWindowStation() failed: 0x%x\n", GetLastError());)
	}
}

PGENERIC_OBJECT queryConnectionPort(WCHAR *path) {
	HANDLE h;
	HRESULT r = FilterConnectCommunicationPort(path, 0, NULL, 0, NULL, &h);
	if (r == 0) {
		PGENERIC_OBJECT go = querySecurityDescriptor(h, L"FilterConnectionPort");
		CloseHandle(h);
		return go;
	}
	else {
		DBGPRINT(printf("FilterConnectCommunicationPort() failed, hresult: 0x%x, getlasterror: 0x%x\n", r, GetLastError());)
	}
	return NULL;
}

/*  ----------/ Enum routines /---------- */

POBJECT enumObjectDirectory(WCHAR *path, int root) {
	OBJDIR_INFORMATION *ssinfo = (OBJDIR_INFORMATION*)HeapAlloc(GetProcessHeap(), 0, 0x800);
	static int depth;
	HANDLE hFile;
	OBJECT_ATTRIBUTES obj;
	WCHAR  pString[6000];
	char tabs[100];
	UNICODE_STRING str;
	DWORD i = 0, a, b = 0;
	POBJECT current = NULL, rootObject = NULL, po = NULL;
	PGENERIC_OBJECT go = NULL;
	PSYMLINK_OBJECT so = NULL;

	if (root) {
		depth = 0;
	}
	else depth++;

	if (!ssinfo) goto END;

	InitializeUnicodeStr(&str, path);
	InitializeObjectAttributes(&obj, &str, 0, 0, 00);

	NTSTATUS r = NtOpenDirectoryObject(&hFile, 0x20001, &obj);
	if (r != 0) {
		goto END;
	}

	memset(tabs, 0x00, sizeof(tabs));
	if (depth < 100)
		memset(tabs, '\t', depth);

	if (NtQueryDirectoryObject(hFile, ssinfo, 0x800, TRUE, TRUE, &b, &a) == 0){
		while (NtQueryDirectoryObject(hFile, ssinfo, 0x800, TRUE, FALSE, &b, &a) == 0) {
			so = NULL;
			go = NULL;
			if (root) {
				DBGPRINT(printf("%s%S%S [%S] \n", tabs, path, ssinfo->ObjectName.Buffer, ssinfo->ObjectTypeName.Buffer);)
				swprintf_s(pString, L"%ws%ws", path, ssinfo->ObjectName.Buffer);
			}
			else {
				DBGPRINT(printf("%s%S\\%S [%S] \n", tabs, path, ssinfo->ObjectName.Buffer, ssinfo->ObjectTypeName.Buffer);)
				swprintf_s(pString, L"%ws\\%ws", path, ssinfo->ObjectName.Buffer);
			}


			if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"Directory")) {
				po = enumObjectDirectory(pString, 0);
				if (po) {
					if (current) {
						current->next = po;
						current = last(current); // skip all over it, append at the end
					}
					else {
						if (!rootObject) rootObject = po;
						current = po;
						current = last(current);
					}
				}
				continue;
			}

			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"Mutant")) {
				go = querySecurity(pString, NtOpenMutant, ssinfo->ObjectTypeName.Buffer);
			}
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"Event")) {
				go = querySecurity(pString, NtOpenEvent, ssinfo->ObjectTypeName.Buffer);

			}
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"FilterConnectionPort")) {
				go = queryConnectionPort(pString);
			}
			// TODO 
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"ALPC Port")) {
		//		printf("ALPC Port\n");
				// open ALPC handle? get security object? 
				// NtAlpcConnectPort
				// NtAlpcDisconnectPort
				// NtAlpcQueryInformation <-- AlpcConnectedSIDInformation
				// NtAlpcQueryInformationMessage
			}
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"Section")) {
				go = querySecurity(pString, NtOpenSection, ssinfo->ObjectTypeName.Buffer);
			}
			// TODO
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"Key")) {
				//printf("Key\n");
				// get security object 
				// NtOpenKey
				// NtOpenKeyEx
				// NtQueryKey
			}
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"SymbolicLink")) {
				go = querySecurity(pString, NtOpenSymbolicLinkObject, ssinfo->ObjectTypeName.Buffer);
				so = queryLink(pString);
				if (so) {
					so->go = go;
				}
				else {
					freeSecurityObject(go);
				}
				go = NULL;
			}

			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"Device")) {
				go = queryDevice(pString);
			}
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"Driver")) {
		//		printf("Driver\n");
				// no info to get. could correlate with registry .... 
			}
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"Semaphore")) {
				go = querySecurity(pString, NtOpenSemaphore, ssinfo->ObjectTypeName.Buffer);
			}
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"Job")) {
				go = querySecurity(pString, NtOpenJobObject, ssinfo->ObjectTypeName.Buffer);
			}
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"Timer")) {
				go = querySecurity(pString, NtOpenTimer, ssinfo->ObjectTypeName.Buffer);
			}
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"Partition")) {
				// do nothing
			}
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"KeyedEvent")) {
				go = querySecurity(pString, NtOpenKeyedEvent, ssinfo->ObjectTypeName.Buffer);
			}
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"Callback")) {
				// do nothing 
			}
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"Type")) {
				// do nothing 
			}
			// TODO: FIX
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"WindowStation")) {
				queryWindowStation(ssinfo->ObjectName.Buffer);
			}
			else if (!wcscmp(ssinfo->ObjectTypeName.Buffer, L"Session")) {
				go = querySecurity(pString, NtOpenSession, ssinfo->ObjectTypeName.Buffer);
			}

			else {
				printf("!!!!! unknown type: %S \n", ssinfo->ObjectTypeName.Buffer);
			}

			POBJECT po = newObject(pString, ssinfo->ObjectTypeName.Buffer, go, so);
			if (!po) {
				freeSecurityObject(go);
				freeSymlinkObject(so);
				continue;
			}

			if (current) {
				current->next = po;
				current = po;
			}
			else {
				rootObject = current = po;
			}
		}
	}
	else {
		DBGPRINT(printf("NtQueryDirectoryObject failed for: %S\n", path);)
	}

END:
	if (ssinfo) {
		HeapFree(GetProcessHeap(), 0, ssinfo);
	}
	if (!root) depth--;
	return rootObject;
}

/*  ----------/ init routines /---------- */

void init() {
	HMODULE hNtdll;

	hNtdll = LoadLibraryW(L"ntdll.dll");
	if (hNtdll == NULL) {
		printf("LoadLibrary(ntdll.dll) failed\n");
		exit(0);
	}

	NtQueryDirectoryObject = (NTQUERYDIRECTORYOBJECT)GetProcAddress(hNtdll, "NtQueryDirectoryObject");
	NtOpenDirectoryObject = (NTOPENDIRECTORYOBJECT)GetProcAddress(hNtdll, "NtOpenDirectoryObject");
	NtOpenMutant = (NTOPENOBJECT)GetProcAddress(hNtdll, "NtOpenMutant");
	NtQuerySecurityObject = (NTQUERYSECURITYOBJECT)GetProcAddress(hNtdll, "NtQuerySecurityObject");
	NtOpenEvent = (NTOPENOBJECT)GetProcAddress(hNtdll, "NtOpenEvent");
	NtOpenSection = (NTOPENOBJECT)GetProcAddress(hNtdll, "NtOpenSection");
	NtOpenSymbolicLinkObject = (NTOPENOBJECT)GetProcAddress(hNtdll, "NtOpenSymbolicLinkObject");
	NtOpenSemaphore = (NTOPENOBJECT)GetProcAddress(hNtdll, "NtOpenSemaphore");
	NtOpenJobObject = (NTOPENOBJECT)GetProcAddress(hNtdll, "NtOpenJobObject");
	NtOpenTimer = (NTOPENOBJECT)GetProcAddress(hNtdll, "NtOpenTimer");
	NtOpenKeyedEvent = (NTOPENOBJECT)GetProcAddress(hNtdll, "NtOpenKeyedEvent");
	NtOpenSession = (NTOPENOBJECT)GetProcAddress(hNtdll, "NtOpenSession");
	NtOpenFile = (NTOPENFILE)GetProcAddress(hNtdll, "NtOpenFile");
	NtQuerySymbolicLinkObject = (NTQUERYSYMBOLICLINKOBJECT)GetProcAddress(hNtdll, "NtQuerySymbolicLinkObject");
	NtCreateFile = (NTCREATEFILE)GetProcAddress(hNtdll, "NtCreateFile");


	if (!NtQueryDirectoryObject 
		|| !NtOpenDirectoryObject 
		|| !NtOpenMutant 
		|| !NtQuerySecurityObject 
		|| !NtOpenEvent 
		|| !NtOpenSection 
		|| !NtOpenSymbolicLinkObject
		|| !NtOpenSemaphore 
		|| !NtOpenJobObject
		|| !NtOpenTimer
		|| !NtOpenKeyedEvent
		|| !NtOpenSession
		|| !NtOpenFile
		|| !NtQuerySymbolicLinkObject
		|| !NtCreateFile) {
		printf("GetProcAddress() of system call(s) failed\n");
		exit(0);
	}
	return;
}

/*  ----------/ test code /---------- */

void dumpObjectsCsv(POBJECT po) {
	printf("Name, type, SDDL, link\n");
	if (!po) return;
	do {
		if (!wcscmp(po->type, L"SymbolicLink")) {
			LPWSTR SddlString = NULL;
			SECURITY_INFORMATION si;

			si = OWNER_SECURITY_INFORMATION |
				GROUP_SECURITY_INFORMATION |
				DACL_SECURITY_INFORMATION;

			if (po->sym && po->sym->go && po->sym->go->sd &&  ConvertSecurityDescriptorToStringSecurityDescriptorW(po->sym->go->sd, SDDL_REVISION_1, si, &SddlString, NULL)){
				//	printf("SDDL string: %ws\n", SddlString);
			}

			WCHAR *ptr = L"";
			if (po->sym && po->sym->link) {
				ptr = po->sym->link;
			}

			printf("%S, %S, \"%S\", %S\n", po->name, po->type, SddlString ? SddlString : L"", ptr);
			if (SddlString) LocalFree(SddlString);

		}
		else {
			LPWSTR SddlString = NULL;
			SECURITY_INFORMATION si;

			si = OWNER_SECURITY_INFORMATION |
				GROUP_SECURITY_INFORMATION |
				DACL_SECURITY_INFORMATION; 

			if (po->obj && po->obj->sd &&  ConvertSecurityDescriptorToStringSecurityDescriptorW(po->obj->sd, SDDL_REVISION_1, si, &SddlString, NULL)){
			//	printf("SDDL string: %ws\n", SddlString);
			}

			printf("%S, %S, \"%S\", %S\n", po->name, po->type, SddlString ? SddlString : L"", L"");
			if (SddlString) LocalFree(SddlString);

		}
		po = po->next;
	} while (po);
}

/*  ----------/ main /---------- */

int main(int argc, CHAR* argv[])
{
	POBJECT po = NULL;
	init();
	po = enumObjectDirectory(L"\\", 1);
	dumpObjectsCsv(po);
	getchar();
	return 0;
}