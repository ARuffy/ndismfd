/*++
 *
 * The file contains the routines to create a device and handle ioctls
 *
-- */

#include "precomp.h"

#pragma NDIS_INIT_FUNCTION(ndismfdRegisterDevice)


_IRQL_requires_max_(PASSIVE_LEVEL)
NDIS_STATUS
ndismfdRegisterDevice(
	VOID
)
{
	NDIS_STATUS            Status = NDIS_STATUS_SUCCESS;
	UNICODE_STRING         DeviceName;
	UNICODE_STRING         DeviceLinkUnicodeString;
	PDRIVER_DISPATCH       DispatchTable[IRP_MJ_MAXIMUM_FUNCTION + 1];
	NDIS_DEVICE_OBJECT_ATTRIBUTES   DeviceAttribute;
	PFILTER_DEVICE_EXTENSION        FilterDeviceExtension;
	PDRIVER_OBJECT                  DriverObject;

	DEBUGP(DL_TRACE, "==> ndismfdRegisterDevice\n");


	NdisZeroMemory(DispatchTable, (IRP_MJ_MAXIMUM_FUNCTION + 1) * sizeof(PDRIVER_DISPATCH));

	DispatchTable[IRP_MJ_CREATE] = ndismfdDispatch;
	DispatchTable[IRP_MJ_CLEANUP] = ndismfdDispatch;
	DispatchTable[IRP_MJ_CLOSE] = ndismfdDispatch;
	DispatchTable[IRP_MJ_DEVICE_CONTROL] = ndismfdDeviceIoControl;


	NdisInitUnicodeString(&DeviceName, NTDEVICE_STRING);
	NdisInitUnicodeString(&DeviceLinkUnicodeString, LINKNAME_STRING);

	//
	// Create a device object and register our dispatch handlers
	//
	NdisZeroMemory(&DeviceAttribute, sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES));

	DeviceAttribute.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
	DeviceAttribute.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
	DeviceAttribute.Header.Size = sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES);

	DeviceAttribute.DeviceName = &DeviceName;
	DeviceAttribute.SymbolicName = &DeviceLinkUnicodeString;
	DeviceAttribute.MajorFunctions = &DispatchTable[0];
	DeviceAttribute.ExtensionSize = sizeof(FILTER_DEVICE_EXTENSION);

	Status = NdisRegisterDeviceEx(
		FilterDriverHandle,
		&DeviceAttribute,
		&NdisDeviceObject,
		&NdisFilterDeviceHandle
	);


	if (Status == NDIS_STATUS_SUCCESS)
	{
		FilterDeviceExtension = (PFILTER_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(NdisDeviceObject);

		FilterDeviceExtension->Signature = 'FTDR';
		FilterDeviceExtension->Handle = FilterDriverHandle;

		//
		// Workaround NDIS bug
		//
		DriverObject = (PDRIVER_OBJECT)FilterDriverObject;
	}


	DEBUGP(DL_TRACE, "<== ndismfdRegisterDevice: %x\n", Status);

	return (Status);

}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
ndismfdDeregisterDevice(
	VOID
)

{
	if (NdisFilterDeviceHandle != NULL)
	{
		NdisDeregisterDeviceEx(NdisFilterDeviceHandle);
	}

	NdisFilterDeviceHandle = NULL;

}

_Use_decl_annotations_
NTSTATUS
ndismfdDispatch(
	PDEVICE_OBJECT       DeviceObject,
	PIRP                 Irp
)
{
	PIO_STACK_LOCATION       IrpStack;
	NTSTATUS                 Status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(DeviceObject);

	IrpStack = IoGetCurrentIrpStackLocation(Irp);

	switch (IrpStack->MajorFunction)
	{
	case IRP_MJ_CREATE:
		break;

	case IRP_MJ_CLEANUP:
		break;

	case IRP_MJ_CLOSE:
		break;

	default:
		break;
	}

	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

static
BOOLEAN
_PushBlockTableEntry(
	_Inout_  PFILTER_BLOCK_TABLE Table,
	_In_     PFILTER_BLOCK_TABLE_ENTRY Entry)
{
	ULONG i, portIndex;
	if (Table->IpAddressNumber >= FILTER_MAX_LOCK_IP_ADDRESS_NUM) {
		return FALSE;
	}

	if (Entry->BlockType) {
		// NOT_IMPLEMENTED
		return FALSE;
	}

	// TODO: Find if alderady exists
	Table->IpAddress[Table->IpAddressNumber] = RtlUlongByteSwap(Entry->IpAddr);
	portIndex = FILTER_MAX_LOCK_PORT_NUM * Table->IpAddressNumber;
	Table->IpAddressNumber++;

	if (Entry->Port == 0)
	{
		Table->Port[portIndex] = 0;
		return TRUE;
	}

	for (i = 0; i < FILTER_MAX_LOCK_PORT_NUM; i++, portIndex++)
	{
		if (Table->Port[portIndex] == 0)
		{
			Table->Port[portIndex] = Entry->Port;
			return TRUE;
		}
	}

	return FALSE;
}

_Use_decl_annotations_
NTSTATUS
ndismfdDeviceIoControl(
	PDEVICE_OBJECT        DeviceObject,
	PIRP                  Irp
)
{
	PIO_STACK_LOCATION          IrpSp;
	NTSTATUS                    Status = STATUS_SUCCESS;
	PFILTER_DEVICE_EXTENSION    FilterDeviceExtension;
	PUCHAR                      InputBuffer;
	PUCHAR                      OutputBuffer;
	ULONG                       InputBufferLength, OutputBufferLength;
	PLIST_ENTRY                 Link;
	PUCHAR                      pInfo;
	ULONG                       InfoLength = 0;
	PMS_FILTER                  pFilter = NULL;
	BOOLEAN                     bFalse = FALSE;


	IrpSp = IoGetCurrentIrpStackLocation(Irp);
	if (IrpSp->FileObject == NULL)
	{
		return(STATUS_UNSUCCESSFUL);
	}

	FilterDeviceExtension = (PFILTER_DEVICE_EXTENSION)NdisGetDeviceReservedExtension(DeviceObject);
	ASSERT(FilterDeviceExtension->Signature == 'FTDR');

	Irp->IoStatus.Information = 0;

	switch (IrpSp->Parameters.DeviceIoControl.IoControlCode)
	{

	case IOCTL_FILTER_RESTART_ALL:
		break;

	case IOCTL_FILTER_RESTART_ONE_INSTANCE:
		InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
		InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;

		pFilter = filterFindFilterModule(InputBuffer, InputBufferLength);
		if (pFilter == NULL)
		{
			break;
		}

		NdisFRestartFilter(pFilter->FilterHandle);
		break;

	case IOCTL_FILTER_ENUMERATE_ALL_INSTANCES:
		InputBuffer = OutputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
		InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
		OutputBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

		pInfo = OutputBuffer;

		FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);

		Link = FilterModuleList.Flink;
		while (Link != &FilterModuleList)
		{
			pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

			InfoLength += (pFilter->FilterModuleName.Length + sizeof(USHORT));
			if (InfoLength <= OutputBufferLength)
			{
				*(PUSHORT)pInfo = pFilter->FilterModuleName.Length;
				NdisMoveMemory(pInfo + sizeof(USHORT),
					(PUCHAR)(pFilter->FilterModuleName.Buffer),
					pFilter->FilterModuleName.Length);

				pInfo += (pFilter->FilterModuleName.Length + sizeof(USHORT));
			}

			Link = Link->Flink;
		}

		FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
		if (InfoLength <= OutputBufferLength)
		{

			Status = NDIS_STATUS_SUCCESS;
		}
		//
		// Buffer is small
		//
		else
		{
			Status = STATUS_BUFFER_TOO_SMALL;
		}
		break;

	case IOCTL_FILTER_MODIFY_BLOCK_TABLE:
		InputBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
		InputBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
		if (InputBufferLength < sizeof(ULONG))
		{
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		// Read number of entries
		ULONG entryCount = *(ULONG*)InputBuffer;
		PUCHAR entryPtr = InputBuffer + sizeof(ULONG);
		ULONG expectedLength = sizeof(ULONG) + entryCount * sizeof(FILTER_BLOCK_TABLE_ENTRY);

		if (InputBufferLength < expectedLength)
		{
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		FILTER_ACQUIRE_LOCK(&FilterTableLock, bFalse);
		for (ULONG i = 0; i < entryCount; ++i)
		{
			PFILTER_BLOCK_TABLE_ENTRY entry = (PFILTER_BLOCK_TABLE_ENTRY)entryPtr;
			if (_PushBlockTableEntry(&FilterBlockTable, entry)) {
				DEBUGP(DL_TRACE, "> Added block table entry: Ip=0x%x Port=%d\n", RtlUlongByteSwap(entry->IpAddr), entry->Port);
			}
			entryPtr += sizeof(FILTER_BLOCK_TABLE_ENTRY);
		}
		FILTER_RELEASE_LOCK(&FilterTableLock, bFalse);

		Status = STATUS_SUCCESS;
		break;


	default:
		break;
	}

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = InfoLength;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;


}


_IRQL_requires_max_(DISPATCH_LEVEL)
PMS_FILTER
filterFindFilterModule(
	_In_reads_bytes_(BufferLength)
	PUCHAR                   Buffer,
	_In_ ULONG                    BufferLength
)
{

	PMS_FILTER              pFilter;
	PLIST_ENTRY             Link;
	BOOLEAN                  bFalse = FALSE;

	FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);

	Link = FilterModuleList.Flink;

	while (Link != &FilterModuleList)
	{
		pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

		if (BufferLength >= pFilter->FilterModuleName.Length)
		{
			if (NdisEqualMemory(Buffer, pFilter->FilterModuleName.Buffer, pFilter->FilterModuleName.Length))
			{
				FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
				return pFilter;
			}
		}

		Link = Link->Flink;
	}

	FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
	return NULL;
}




