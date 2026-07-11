#include "stadixf.h"
#include "CR3.h"

VOID DriverUnLoad(PDRIVER_OBJECT pDriver) 
{
	UNREFERENCED_PARAMETER(pDriver);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg) 
{
	UNREFERENCED_PARAMETER(pDriver);
	UNREFERENCED_PARAMETER(pReg);
	PREAD_BUFFER buf = { 0 };
	ReadReaMemory(2524, 0x007100A0, buf);
	ULONG buffer = buf->Buffer;
	DbgBreakPoint();
	pDriver->DriverUnload = DriverUnLoad;
	return STATUS_SUCCESS;
}