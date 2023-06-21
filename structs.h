#pragma once
#include <Windows.h>

#define RTL_USER_PROC_PARAMS_NORMALIZED     0x00000001

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	WCHAR* Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		LONG Status;
		VOID* Pointer;
	};
	ULONGLONG Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	VOID* RootDirectory;
	struct _UNICODE_STRING* ObjectName;
	ULONG Attributes;
	VOID* SecurityDescriptor;
	VOID* SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CURDIR
{
	UNICODE_STRING DosPath;
	HANDLE Handle;

} CURDIR, * PCURDIR;

typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	union
	{
		UCHAR BitField;
		struct
		{
			UCHAR ImageUsesLargePages : 1;
			UCHAR IsProtectedProcess : 1;
			UCHAR IsImageDynamicallyRelocated : 1;
			UCHAR SkipPatchingUser32Forwarders : 1;
			UCHAR IsPackagedProcess : 1;
			UCHAR IsAppContainer : 1;
			UCHAR IsProtectedProcessLight : 1;
			UCHAR IsLongPathAwareProcess : 1;
		};
	};
	UCHAR Padding0[4];
	VOID* Mutant;
	VOID* ImageBaseAddress;
	struct _PEB_LDR_DATA* Ldr;
	struct _RTTL_USER_PROCESS_PARAMETERS* ProcessParameters;
	VOID* SubSystemData;
	VOID* ProcessHeap;
	struct _RTL_CRITICAL_SECTION* FastPebLock;
	union _SLIST_HEADER* volatile AtlThunkSListPtr;
	VOID* IFEOKey;
	union
	{
		ULONG CrossProcessFlags;
		struct
		{
			ULONG ProcessInJob : 1;
			ULONG ProcessInitializing : 1;
			ULONG ProcessUsingVEH : 1;
			ULONG ProcessUsingVCH : 1;
			ULONG ProcessUsingFTH : 1;
			ULONG ProcessPreviouslyThrottled : 1;
			ULONG ProcessCurrentlyThrottled : 1;
			ULONG ProcessImagesHotPatched : 1;
			ULONG ReservedBits0 : 24;
		};
	};
	UCHAR Padding1[4];
	union
	{
		VOID* KernelCallbackTable;
		VOID* UserSharedInfoPtr;
	};
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	VOID* ApiSetMap;
	ULONG TlsExpansionCounter;
	UCHAR Padding2[4];
	VOID* TlsBitmap;
	ULONG TlsBitmapBits[2];
	VOID* ReadOnlySharedMemoryBase;
	VOID* SharedData;
	VOID** ReadOnlyStaticServerData;
	VOID* AnsiCodePageData;
	VOID* OemCodePageData;
	VOID* UnicodeCaseTableData;
	ULONG NumberOfProcessors;
	ULONG NtGlobalFlag;
	union _LARGE_INTEGER CriticalSectionTimeout;
	ULONGLONG HeapSegmentReserve;
	ULONGLONG HeapSegmentCommit;
	ULONGLONG HeapDeCommitTotalFreeThreshold;
	ULONGLONG HeapDeCommitFreeBlockThreshold;
	ULONG NumberOfHeaps;
	ULONG MaximumNumberOfHeaps;
	VOID** ProcessHeaps;
	VOID* GdiSharedHandleTable;
	VOID* ProcessStarterHelper;
	ULONG GdiDCAttributeList;
	UCHAR Padding3[4];
	struct _RTL_CRITICAL_SECTION* LoaderLock;
	ULONG OSMajorVersion;
	ULONG OSMinorVersion;
	USHORT OSBuildNumber;
	USHORT OSCSDVersion;
	ULONG OSPlatformId;
	ULONG ImageSubsystem;
	ULONG ImageSubsystemMajorVersion;
	ULONG ImageSubsystemMinorVersion;
	UCHAR Padding4[4];
	ULONGLONG ActiveProcessAffinityMask;
	ULONG GdiHandleBuffer[60];
	VOID(*PostProcessInitRoutine)();
	VOID* TlsExpansionBitmap;
	ULONG TlsExpansionBitmapBits[32];
	ULONG SessionId;
	UCHAR Padding5[4];
	union _ULARGE_INTEGER AppCompatFlags;
	union _ULARGE_INTEGER AppCompatFlagsUser;
	VOID* pShimData;
	VOID* AppCompatInfo;
	struct _UNICODE_STRING CSDVersion;
	struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;
	struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;
	struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;
	struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;
	ULONGLONG MinimumStackCommit;
	VOID* SparePointers[4];
	ULONG SpareUlongs[5];
	VOID* WerRegistrationData;
	VOID* WerShipAssertPtr;
	VOID* pUnused;
	VOID* pImageHeaderHash;
	union
	{
		ULONG TracingFlags;
		struct
		{
			ULONG HeapTracingEnabled : 1;
			ULONG CritSecTracingEnabled : 1;
			ULONG LibLoaderTracingEnabled : 1;
			ULONG SpareTracingBits : 29;
		};
	};
	UCHAR Padding6[4];
	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	ULONGLONG TppWorkerpListLock;
	struct _LIST_ENTRY TppWorkerpList;
	VOID* WaitOnAddressHashTable[128];
	VOID* TelemetryCoverageHeader;
	ULONG CloudFileFlags;
	ULONG CloudFileDiagFlags;
	CHAR PlaceholderCompatibilityMode;
	CHAR PlaceholderCompatibilityModeReserved[7];
	struct _LEAP_SECOND_DATA* LeapSecondData;
	union
	{
		ULONG LeapSecondFlags;
		struct
		{
			ULONG SixtySecondEnabled : 1;
			ULONG Reserved : 31;
		};
	};
	ULONG NtGlobalFlag2;
} PEB, * PPEB;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	VOID* SsHandle;
	struct _LIST_ENTRY InLoadOrderModuleList;
	struct _LIST_ENTRY InMemoryOrderModuleList;
	struct _LIST_ENTRY InInitializationOrderModuleList;
	VOID* EntryInProgress;
	UCHAR ShutdownInProgress;
	VOID* ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE* Children[2];
		struct
		{
			struct _RTL_BALANCED_NODE* Left;
			struct _RTL_BALANCED_NODE* Right;
		};
	};
	union
	{
		struct
		{
			UCHAR Red : 1;
			UCHAR Balance : 2;
		};
		ULONGLONG ParentValue;
	};
};

typedef struct _LDR_DATA_TABLE_ENTRY2
{
	struct _LIST_ENTRY InLoadOrderLinks;
	struct _LIST_ENTRY InMemoryOrderLinks;
	struct _LIST_ENTRY InInitializationOrderLinks;
	VOID* DllBase;
	VOID* EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	union
	{
		UCHAR FlagGroup[4];
		ULONG Flags;
		struct
		{
			ULONG PackagedBinary : 1;
			ULONG MarkedForRemoval : 1;
			ULONG ImageDll : 1;
			ULONG LoadNotificationsSent : 1;
			ULONG TelemetryEntryProcessed : 1;
			ULONG ProcessStaticImport : 1;
			ULONG InLegacyLists : 1;
			ULONG InIndexes : 1;
			ULONG ShimDll : 1;
			ULONG InExceptionTable : 1;
			ULONG ReservedFlags1 : 2;
			ULONG LoadInProgress : 1;
			ULONG LoadConfigProcessed : 1;
			ULONG EntryProcessed : 1;
			ULONG ProtectDelayLoad : 1;
			ULONG ReservedFlags3 : 2;
			ULONG DontCallForThreads : 1;
			ULONG ProcessAttachCalled : 1;
			ULONG ProcessAttachFailed : 1;
			ULONG CorDeferredValidate : 1;
			ULONG CorImage : 1;
			ULONG DontRelocate : 1;
			ULONG CorILOnly : 1;
			ULONG ChpeImage : 1;
			ULONG ReservedFlags5 : 2;
			ULONG Redirected : 1;
			ULONG ReservedFlags6 : 2;
			ULONG CompatDatabaseProcessed : 1;
		};
	};
	USHORT ObsoleteLoadCount;
	USHORT TlsIndex;
	struct _LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
	struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	VOID* Lock;
	struct _LDR_DDAG_NODE* DdagNode;
	struct _LIST_ENTRY NodeModuleLink;
	struct _LDRP_LOAD_CONTEXT* LoadContext;
	VOID* ParentDllBase;
	VOID* SwitchBackContext;
	struct _RTL_BALANCED_NODE BaseAddressIndexNode;
	struct _RTL_BALANCED_NODE MappingInfoIndexNode;
	ULONG_PTR OriginalBase;
	union _LARGE_INTEGER LoadTime;
	ULONG BaseNameHashValue;
	enum _LDR_DLL_LOAD_REASON LoadReason;
	ULONG ImplicitPathOptions;
	ULONG ReferenceCount;
	ULONG DependentLoadFlags;
	UCHAR SigningLevel;
} LDR_DATA_TABLE_ENTRY2, * PLDR_DATA_TABLE_ENTRY2;

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

EXTERN_C NTSTATUS MyNtCreateSection(
	PHANDLE,
	ACCESS_MASK,
	POBJECT_ATTRIBUTES,
	PLARGE_INTEGER,
	ULONG,
	ULONG,
	HANDLE
	);

EXTERN_C NTSTATUS MyNtCreateProcessEx(
	PHANDLE,
	ACCESS_MASK,
	POBJECT_ATTRIBUTES,
	HANDLE,
	ULONG,
	HANDLE,
	HANDLE,
	HANDLE,
	ULONG
	);

EXTERN_C NTSTATUS MyNtCreateFile(
	PHANDLE,
	ACCESS_MASK,
	POBJECT_ATTRIBUTES,
	PIO_STATUS_BLOCK,
	PLARGE_INTEGER,
	ULONG,
	ULONG,
	ULONG,
	ULONG,
	PVOID,
	ULONG
	);

typedef VOID (NTAPI* _RtlInitUnicodeString)(
	PUNICODE_STRING,
	PCWSTR
	);

EXTERN_C NTSTATUS MyNtAllocateVirtualMemory(
	HANDLE,
	PVOID*,
	ULONG_PTR,
	PSIZE_T,
	ULONG,
	ULONG
	);

EXTERN_C NTSTATUS MyNtReadVirtualMemory(
	HANDLE,
	PVOID,
	PVOID,
	SIZE_T,
	PSIZE_T
	);

EXTERN_C NTSTATUS MyNtFreeVirtualMemory(
	HANDLE,
	PVOID*,
	PSIZE_T,
	ULONG
	);

EXTERN_C NTSTATUS MyNtTerminateProcess(
	HANDLE,
	NTSTATUS
	);

EXTERN_C NTSTATUS MyNtProtectVirtualMemory(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	PSIZE_T RegionSize,
	ULONG NewProtect,
	PULONG OldProtect
	);

EXTERN_C NTSTATUS MyNtMapViewOfSection(
	HANDLE,
	HANDLE,
	PVOID,
	ULONG,
	SIZE_T,
	PLARGE_INTEGER,
	PSIZE_T,
	SECTION_INHERIT,
	ULONG,
	ULONG
);

EXTERN_C BYTE sysCallNum(DWORD func);
EXTERN_C PVOID SysAddr(DWORD func);

PVOID ntdllAddr = NULL;
PDWORD funcAddr = NULL;
_RtlInitUnicodeString RtlInitUnicodeString = NULL;

size_t _strnlen(const char* s, size_t n) {
	size_t i;
	for (i = 0; i < n && s[i] != '\0'; i++)
		continue;
	return i;
}

DWORD dohash(char* string)
{
	size_t strLen = _strnlen(string, 50);
	DWORD hash = 0x498157;
	for (int i = 0; i < strLen; i++) {

		hash += (hash * 0x4625aecf + string[i]) & 0xbcedfa;

	}
	return hash;
}
