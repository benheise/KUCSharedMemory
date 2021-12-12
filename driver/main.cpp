#include "common.hpp"

#define RVA(addr, size) (BYTE*)addr + *(INT*)((BYTE*)addr + ((size) - 4)) + size

typedef struct _MM_UNLOADED_DRIVER
{
	UNICODE_STRING 	Name;
	PVOID 			ModuleStart;
	PVOID 			ModuleEnd;
	ULONG64 		UnloadTime;
} MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;

typedef struct PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
}PIDCacheobj;

PMM_UNLOADED_DRIVER MmUnloadedDrivers;
PULONG MmLastUnloadedDriver;
ERESOURCE PsLoadedModuleResource;
UINT64 ntoskrnlBase = 0, ntoskrnlSize = 0;

BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;

	return (*szMask) == 0;
}

UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE* bMask, char* szMask)
{
	for (UINT64 i = 0; i < dwLen; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (UINT64)(dwAddress + i);

	return 0;
}

PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

LONG RetrieveMmUnloadedDriversData(VOID)
{
	ULONG bytes = 0;

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
	if (!bytes) return 1;
	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x504D5448);
	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);
	if (!NT_SUCCESS(status)) return 2;
	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		if (!strcmp((char*)module[i].FullPathName, "\\SystemRoot\\system32\\ntoskrnl.exe"))
		{
			ntoskrnlBase = (UINT64)module[i].ImageBase;
			ntoskrnlSize = (UINT64)module[i].ImageSize;
			break;
		}
	}
	if (modules) ExFreePoolWithTag(modules, 0);

	UINT64 MmUnloadedDriversInstr = FindPattern((UINT64)ntoskrnlBase, (UINT64)ntoskrnlSize, (BYTE*)"\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74", "xx?????xxxxx?x");
	if (MmUnloadedDriversInstr == NULL) return 3;

	UINT64 MmLastUnloadedDriverInstr = FindPattern((UINT64)ntoskrnlBase, (UINT64)ntoskrnlSize, (BYTE*)"\x8B\x05\x00\x00\x00\x00\x83\xF8\x32", "xx????xxx");
	if (MmLastUnloadedDriverInstr == NULL) return 4;

	MmUnloadedDrivers = *(PMM_UNLOADED_DRIVER*)ResolveRelativeAddress((PVOID)MmUnloadedDriversInstr, 3, 7);
	MmLastUnloadedDriver = (PULONG)ResolveRelativeAddress((PVOID)MmLastUnloadedDriverInstr, 2, 6);

	return 0;
}

extern "C" NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(IN PVOID                ModuleAddress);

NTSTATUS PatternScan(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL) return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}
		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS ScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL);
	if (ppFound == NULL) return STATUS_INVALID_PARAMETER;

	PVOID base = (PVOID)ntoskrnlBase;
	if (!base) return STATUS_NOT_FOUND;

	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr) return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if (RtlCompareString(&s1, &s2, TRUE) == 0)
		{
			PVOID ptr = NULL;
			NTSTATUS status = PatternScan(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status)) *(PULONG)ppFound = (ULONG)((PUCHAR)ptr - (PUCHAR)base);
			return status;
		}
	}
	return STATUS_NOT_FOUND;
}

BOOLEAN LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table)
{
	UCHAR PiDDBLockPtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x48\x8B\x0D\xCC\xCC\xCC\xCC\x33\xDB";
	UCHAR PiDTablePtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x3D\xCC\xCC\xCC\xCC\x0F\x83\xCC\xCC\xCC\xCC";

	PVOID PiDDBLockPtr = NULL;
	if (!NT_SUCCESS(ScanSection("PAGE", PiDDBLockPtr_sig, 0xCC, sizeof(PiDDBLockPtr_sig) - 1, (&PiDDBLockPtr)))) return FALSE;
	RtlZeroMemory(PiDDBLockPtr_sig, sizeof(PiDDBLockPtr_sig) - 1);

	PVOID PiDTablePtr = NULL;
	if (!NT_SUCCESS(ScanSection("PAGE", PiDTablePtr_sig, 0xCC, sizeof(PiDTablePtr_sig) - 1, (&PiDTablePtr)))) return FALSE;
	RtlZeroMemory(PiDTablePtr_sig, sizeof(PiDTablePtr_sig) - 1);


	UINT64 RealPtrPIDLock = NULL;
	RealPtrPIDLock = (UINT64)ntoskrnlBase + (UINT64)PiDDBLockPtr;
	*lock = (PERESOURCE)ResolveRelativeAddress((PVOID)RealPtrPIDLock, 3, 7);

	UINT64 RealPtrPIDTable = NULL;
	RealPtrPIDTable = (UINT64)(UINT64)ntoskrnlBase + (UINT64)PiDTablePtr;
	*table = (PRTL_AVL_TABLE)(ResolveRelativeAddress((PVOID)RealPtrPIDTable, 3, 7));

	return TRUE;
}

LONG ClearPiDDBCacheTable()
{
	PERESOURCE PiDDBLock = NULL;
	PRTL_AVL_TABLE PiDDBCacheTable = NULL;
	if (!LocatePiDDB(&PiDDBLock, &PiDDBCacheTable) && PiDDBLock == NULL && PiDDBCacheTable == NULL) return 1;

	PIDCacheobj iqvw64e;
	iqvw64e.DriverName = RTL_CONSTANT_STRING(L"iqvw64e.sys");
	iqvw64e.TimeDateStamp = 0x5284F8FA;

	ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

	PIDCacheobj* pFoundEntry = (PIDCacheobj*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &iqvw64e);
	if (pFoundEntry == NULL)
	{
		ExReleaseResourceLite(PiDDBLock);
		return 2;
	}
	else
	{
		RemoveEntryList(&pFoundEntry->List);
		RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry);
		ExReleaseResourceLite(PiDDBLock);
		return 0;
	}
}

#define MM_UNLOADED_DRIVERS_SIZE 50

BOOLEAN IsUnloadedDriverEntryEmpty(_In_ PMM_UNLOADED_DRIVER Entry)
{
	if (Entry->Name.MaximumLength == 0 || Entry->Name.Length == 0 || Entry->Name.Buffer == NULL)
		return TRUE;
	else
		return FALSE;
}

BOOLEAN IsMmUnloadedDriversFilled(VOID)
{
	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
	{
		PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
		if (IsUnloadedDriverEntryEmpty(Entry)) return FALSE;
	}
	return TRUE;
}

LONG ClearMmUnloadedDrivers(_In_ PUNICODE_STRING DriverName, _In_ BOOLEAN AccquireResource)
{
	if (AccquireResource) ExAcquireResourceExclusiveLite(&PsLoadedModuleResource, TRUE);
	BOOLEAN Modified = FALSE;
	BOOLEAN Filled = IsMmUnloadedDriversFilled();
	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
	{
		PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
		if (Modified)
		{
			PMM_UNLOADED_DRIVER PrevEntry = &MmUnloadedDrivers[Index - 1];
			RtlCopyMemory(PrevEntry, Entry, sizeof(MM_UNLOADED_DRIVER));
			if (Index == MM_UNLOADED_DRIVERS_SIZE - 1) RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
		}
		else if (RtlEqualUnicodeString(DriverName, &Entry->Name, TRUE))
		{
			PVOID BufferPool = Entry->Name.Buffer;
			RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
			ExFreePoolWithTag(BufferPool, 0x504D5448);
			*MmLastUnloadedDriver = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *MmLastUnloadedDriver) - 1;
			Modified = TRUE;
		}
	}
	if (Modified)
	{
		ULONG64 PreviousTime = 0;
		for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index)
		{
			PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
			if (IsUnloadedDriverEntryEmpty(Entry)) continue;
			if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime) Entry->UnloadTime = PreviousTime - 48;
			PreviousTime = Entry->UnloadTime;
		}
		ClearMmUnloadedDrivers(DriverName, FALSE);
	}

	if (AccquireResource) ExReleaseResourceLite(&PsLoadedModuleResource);

	return Modified ? 0 : 1;
}

VOID thread_entry(PVOID context)
{
	UNREFERENCED_PARAMETER(context);

	RetrieveMmUnloadedDriversData();
	ClearPiDDBCacheTable();

	UNICODE_STRING iqvw64e = RTL_CONSTANT_STRING(L"iqvw64e.sys");
	ClearMmUnloadedDrivers(&iqvw64e, true);

	/*
	* Get the client's PEPROCESS, it is vital to continue the execution.
	*/
	if (NT_SUCCESS(PsLookupProcessByProcessId(HANDLE(comms::client_pid), &comms::client_peprocess)))
	{
#ifdef DEBUG_MODE
		DbgPrintEx(0, 0, "gathered client_peprocess\n");
#endif
		
		/*
		* Attach to the process to get the shared memory structure's physical address to map it.
		*/
		KAPC_STATE apc_state;
		KeStackAttachProcess(comms::client_peprocess, &apc_state);
		{
			/*
			* Gather the physical address.
			*/
			auto shared_memory_physical = MmGetPhysicalAddress(reinterpret_cast<PVOID>(comms::shared_memory_address));
			
#ifdef DEBUG_MODE
			DbgPrintEx(0, 0, "shared memory physical address %p\n", shared_memory_physical);
#endif

			if (shared_memory_physical.QuadPart)
			{
				/*
				* If we got a physical address, we can now map it and save it, we now have access to the same structure
				* the usermode client has access to, and communication can now start.
				*/
				comms::remapped_memory = 
					reinterpret_cast<comms::mapped_memory*>(MmMapIoSpace(shared_memory_physical, sizeof(comms::mapped_memory),
					MmNonCached));

				if (comms::remapped_memory)
				{
#ifdef DEBUG_MODE
					DbgPrintEx(0, 0, "mapped physical address at %p\n", comms::remapped_memory);
#endif
				}
			}
		}
		KeUnstackDetachProcess(&apc_state);

		if (comms::remapped_memory)
		{
			while (true)
			{
				if (!comms::loop())
				{
					break;
				}
			}
		}

		ObDereferenceObject(comms::client_peprocess);
	}
	else
	{
#ifdef DEBUG_MODE
		DbgPrintEx(0, 0, "couldn't gather client's peprocess...\n");
#endif
	}

#ifdef DEBUG_MODE
	DbgPrintEx(0, 0, "preparing to self destruct...\n");
#endif


	if (comms::remapped_memory)
	{
		MmUnmapIoSpace(reinterpret_cast<PVOID>(comms::remapped_memory), sizeof(comms::mapped_memory));
	}


	jmp_to_ex_free_pool(reinterpret_cast<void*>(utils::driver_pool_base));
}

extern "C" NTSTATUS driver_main(uint64_t pool_base, uint32_t pool_size, uint32_t client_pid, uint64_t shared_memory_address)
{
	/*
	* Save all the data for initialization and communication purposes (utils::driver_pool_size will stay unused for now).
	*/
	utils::driver_pool_base = pool_base;
	utils::driver_pool_size = pool_size;
	comms::client_pid = client_pid;
	comms::shared_memory_address = shared_memory_address;

#ifdef DEBUG_MODE
	DbgPrintEx(0, 0, "driver was mapped at %p - %p\n", pool_base, pool_size);
	DbgPrintEx(0, 0, "client process data %d - %p\n", client_pid, shared_memory_address);
#endif

	/*
	* Spawn a thread and let this function return to usermode, the client can continue its execution and clean up the hook
	* while we setup our payload. Even if it may not look clear from the kdmapper's source, right now we're executing as
	* a hook on a routine.
	*/
	HANDLE system_thread_handle;
	PsCreateSystemThread(&system_thread_handle, THREAD_ALL_ACCESS, NULL, NULL, NULL, thread_entry, NULL);

	return STATUS_SUCCESS;
}