#pragma once
#include "stadixf.h"

typedef struct
{
	UCHAR Buffer[PAGE_SIZE];
	SIZE_T bufSize;
}READ_BUFFER,*PREAD_BUFFER;

HANDLE g_handle;
int ReadReaMemory(ULONG pid, ULONG64 addr,PREAD_BUFFER buf) 
{
	PEPROCESS pEprocess = NULL;
	NTSTATUS status = STATUS_SUCCESS;

	if (pid==NULL)
	{
		DbgPrint("Target process pid is Null");
		return 0;
	}

	if (buf==NULL)
	{
		DbgPrint("BUF is Null");
		return 0;
	}

	if (buf->bufSize>PAGE_SIZE)
	{
		buf->bufSize = PAGE_SIZE;
	}

	status=PsLookupProcessByProcessId(&pid, &pEprocess);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("PsLookupProcessByProcessId failed, status: 0x%X\n", status);
		return 0;
	}

	PRTL_OSVERSIONINFOW OsIfo = {0};
	status=RtlGetVersion(&OsIfo);
	if (!NT_SUCCESS(status))
	{
		return 0;
	}

	ULONG CR3Offset;
	if (OsIfo->dwMajorVersion == 10 && OsIfo->dwMinorVersion == 0) {
		switch (OsIfo->dwBuildNumber)
		{
		case 15063:
		case 16299:
		case 17134:
		case 17763:
		case 18362:
		case 18363:
		case 19041:
		case 19044:
		case 19045:
			CR3Offset = 0x28;
			break;

		case 22000:
		case 22621:
		case 22631:
		case 25981:
			CR3Offset = 0x28;
			break;
		case 25982:
		case 26099:
		case 26100:
		case 26200:
			CR3Offset = 0x30;
			break;
		default:
			return 0x30;

		}
		CR3Offset = 0x28;
	}
	


	ULONG64 cr3 = *(PULONG64)((PUCHAR)pEprocess + CR3Offset);

	DbgPrint("Target Process CR3: 0x%llX\n", cr3);

	ULONG64 offset = addr & 0xfff;

	ULONG64 pml4_idex = (addr >> 39) & 0x1FFll;
	ULONG64 pdpt_idex = (addr >> 30) & 0x1FFll;
	ULONG64 pde_idex = (addr >> 21) & 0x1FFll;
	ULONG64 pte_idex = (addr >> 12) & 0x1FFll;

	OBJECT_ATTRIBUTES ob = { 0 };
	UNICODE_STRING phy = { 0 };

	RtlInitUnicodeString(&phy, L"\\Device\\PhysicalMemory");

	InitializeObjectAttributes(&ob, &phy, 0, 0, 0);

	status = ZwOpenSection(&g_handle, SECTION_ALL_ACCESS, &ob);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(pEprocess);
		return 0;
	}

	LARGE_INTEGER offset_pa = { 0 };
	offset_pa.QuadPart = cr3;
	PULONG64 pm14_va = 0;
	PULONG64 pdpt_va = 0;
	PULONG64 pde_va = 0;
	PULONG64 pte_va = 0;
	
	SIZE_T map_size = PAGE_SIZE;
	status=ZwMapViewOfSection(g_handle, NtCurrentProcess(), (PVOID*)pm14_va, 0, PAGE_SIZE, &offset_pa, &map_size, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(pEprocess);
		ZwClose(g_handle);
		return 0;
	}
	ULONG64 plm4e = pm14_va[pml4_idex];

	if (!(plm4e&1))
	{
		ObDereferenceObject(pEprocess);
		ZwUnmapViewOfSection(g_handle, pm14_va);
		ZwClose(g_handle);
		return 0;
	}
	offset_pa.QuadPart = (plm4e & 0x000FFFFFFFFFF000);

	status = ZwMapViewOfSection(g_handle, NtCurrentProcess(), (PVOID*)pdpt_va, 0, PAGE_SIZE, &offset_pa, &map_size, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(pEprocess);
		ZwUnmapViewOfSection(g_handle, pm14_va);
		ZwClose(g_handle);
		return 0;
	}
	ULONG64 pdpte = pdpt_va[pdpt_idex];

	if (!(pdpte&1))
	{
		ObDereferenceObject(pEprocess);
		ZwUnmapViewOfSection(g_handle, pdpt_va);
		ZwUnmapViewOfSection(g_handle, pm14_va);
		ZwClose(g_handle);
		return 0;
	}
	offset_pa.QuadPart = (pdpte& 0x000FFFFFFFFFF000);

	status = ZwMapViewOfSection(g_handle, NtCurrentProcess(), (PVOID*)pde_va, 0, PAGE_SIZE, &offset_pa, &map_size, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(pEprocess);
		ZwUnmapViewOfSection(g_handle, pdpt_va);
		ZwUnmapViewOfSection(g_handle, pm14_va);
		ZwClose(g_handle);
		return 0;
	}
	ULONG64 pde = pde_va[pde_idex];
	if (!(pde&1))
	{
		ObDereferenceObject(pEprocess);
		ZwUnmapViewOfSection(g_handle, pde_va);
		ZwUnmapViewOfSection(g_handle, pdpt_va);
		ZwUnmapViewOfSection(g_handle, pm14_va);
		ZwClose(g_handle);
		return 0;
	}
	offset_pa.QuadPart = (pde & 0x000FFFFFFFFFF000);

	status = ZwMapViewOfSection(g_handle, NtCurrentProcess(), (PVOID*)pte_va, 0, PAGE_SIZE, &offset_pa, &map_size, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(pEprocess);
		ZwUnmapViewOfSection(g_handle, pde_va);
		ZwUnmapViewOfSection(g_handle, pdpt_va);
		ZwUnmapViewOfSection(g_handle, pm14_va);
		ZwClose(g_handle);
		return 0;
	}
	ULONG64 pte = pte_va[pte_idex];
	if (!(pte&1))
	{
		ObDereferenceObject(pEprocess);
		ZwUnmapViewOfSection(g_handle, pte_va);
		ZwUnmapViewOfSection(g_handle, pde_va);
		ZwUnmapViewOfSection(g_handle, pdpt_va);
		ZwUnmapViewOfSection(g_handle, pm14_va);
		ZwClose(g_handle);
		return 0;
	}
	offset_pa.QuadPart = (pte& 0x000FFFFFFFFFF000);

	PUCHAR pa_akb = { 0 };
	DbgBreakPoint();
	status = ZwMapViewOfSection(g_handle, NtCurrentProcess(), (PVOID*)pa_akb, 0, PAGE_SIZE, &offset_pa, &map_size, ViewUnmap, MEM_TOP_DOWN, PAGE_READWRITE);
	if (!NT_SUCCESS(status))
	{
		ObDereferenceObject(pEprocess);
		ZwUnmapViewOfSection(g_handle, pte_va);
		ZwUnmapViewOfSection(g_handle, pde_va);
		ZwUnmapViewOfSection(g_handle, pdpt_va);
		ZwUnmapViewOfSection(g_handle, pm14_va);
		ZwClose(g_handle);
		return 0;
	}

	RtlZeroMemory(buf->Buffer, PAGE_SIZE);
	RtlCopyMemory(buf->Buffer, pa_akb + offset, buf->bufSize);


	ObDereferenceObject(pEprocess);
	if (pa_akb)
	{
		ZwUnmapViewOfSection(g_handle, pa_akb);
	}

	if (pte_va)
	{
		ZwUnmapViewOfSection(g_handle, pte_va);
	}

	if (pde_va)
	{
		ZwUnmapViewOfSection(g_handle, pde_va);
	}

	if (pdpt_va)
	{
		ZwUnmapViewOfSection(g_handle, pdpt_va);
	}

	if (pm14_va)
	{
		ZwUnmapViewOfSection(g_handle, pm14_va);
	}
	ZwClose(g_handle);

	return NT_SUCCESS(status) ? 1 : 0;
}