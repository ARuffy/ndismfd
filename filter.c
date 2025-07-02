/*++

Module Name:

	Filter.c

Abstract:

	Sample NDIS Lightweight filter driver

--*/

#include "precomp.h"

#define __FILENUMBER    'PNPF'

// This directive puts the DriverEntry function into the INIT segment of the
// driver.  To conserve memory, the code will be discarded when the driver's
// DriverEntry function returns.  You can declare other functions used only
// during initialization here.
#pragma NDIS_INIT_FUNCTION(DriverEntry)

//
// Global variables
//
NDIS_HANDLE         FilterDriverHandle; // NDIS handle for filter driver
NDIS_HANDLE         FilterDriverObject; // NDIS driver object
NDIS_HANDLE         NdisFilterDeviceHandle = NULL;
PDEVICE_OBJECT      NdisDeviceObject = NULL;

FILTER_LOCK         FilterListLock;
LIST_ENTRY          FilterModuleList;

// Thread
HANDLE FilterThreadHandle = NULL;
KEVENT FilterThreadStopEvent;

NDIS_FILTER_PARTIAL_CHARACTERISTICS DefaultChars = {
{ 0, 0, 0},
	  0,
	  NULL,
	  NULL,
	  NULL,
	  FilterReceiveNetBufferLists,
	  FilterReturnNetBufferLists
};

_Use_decl_annotations_
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT      DriverObject,
	PUNICODE_STRING     RegistryPath
)
/*++

Routine Description:

	First entry point to be called, when this driver is loaded.
	Register with NDIS as a filter driver and create a device
	for communication with user-mode.

Arguments:

	DriverObject - pointer to the system's driver object structure
				   for this driver

	RegistryPath - system's registry path for this driver

Return Value:

	STATUS_SUCCESS if all initialization is successful, STATUS_XXX
	error code if not.

--*/
{
	NDIS_STATUS Status;
	NDIS_FILTER_DRIVER_CHARACTERISTICS      FChars;
	NDIS_STRING ServiceName = RTL_CONSTANT_STRING(FILTER_SERVICE_NAME);
	NDIS_STRING UniqueName = RTL_CONSTANT_STRING(FILTER_UNIQUE_NAME);
	NDIS_STRING FriendlyName = RTL_CONSTANT_STRING(FILTER_FRIENDLY_NAME);
	BOOLEAN bFalse = FALSE;

	UNREFERENCED_PARAMETER(RegistryPath);
	DEBUGP(DL_TRACE, "===> DriverEntry...\n");

	FilterDriverObject = DriverObject;

	do
	{
		NdisZeroMemory(&FChars, sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS));
		FChars.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
		FChars.Header.Size = sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS);
#if NDIS_SUPPORT_NDIS61
		FChars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
#else
		FChars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_1;
#endif
		FChars.MajorNdisVersion = FILTER_MAJOR_NDIS_VERSION;
		FChars.MinorNdisVersion = FILTER_MINOR_NDIS_VERSION;
		FChars.MajorDriverVersion = 1;
		FChars.MinorDriverVersion = 0;
		FChars.Flags = 0;

		FChars.FriendlyName = FriendlyName;
		FChars.UniqueName = UniqueName;
		FChars.ServiceName = ServiceName;

		FChars.SetOptionsHandler = FilterRegisterOptions;
		FChars.AttachHandler = FilterAttach;
		FChars.DetachHandler = FilterDetach;
		FChars.RestartHandler = FilterRestart;
		FChars.PauseHandler = FilterPause;
		FChars.SetFilterModuleOptionsHandler = NULL;

		// OID request handlers
		FChars.OidRequestHandler = NULL;
		FChars.OidRequestCompleteHandler = NULL;
		FChars.CancelOidRequestHandler = NULL;
		// NBL Send/Receive handlers
		FChars.SendNetBufferListsHandler = NULL;
		FChars.SendNetBufferListsCompleteHandler = NULL;
		FChars.CancelSendNetBufferListsHandler = NULL;
		FChars.ReceiveNetBufferListsHandler = FilterReceiveNetBufferLists;
		FChars.ReturnNetBufferListsHandler = FilterReturnNetBufferLists;
		// PNP handlers
		FChars.DevicePnPEventNotifyHandler = NULL;
		FChars.NetPnPEventHandler = NULL;
		// Status handlers
		FChars.StatusHandler = NULL;

		DriverObject->DriverUnload = FilterUnload;
		FilterDriverHandle = NULL;

		FILTER_INIT_LOCK(&FilterListLock);

		InitializeListHead(&FilterModuleList);

		Status = NdisFRegisterFilterDriver(DriverObject,
			(NDIS_HANDLE)FilterDriverObject,
			&FChars,
			&FilterDriverHandle);
		if (Status != NDIS_STATUS_SUCCESS)
		{
			DEBUGP(DL_WARN, "Register filter driver failed.\n");
			break;
		}

		Status = ndismfdRegisterDevice();

		if (Status != NDIS_STATUS_SUCCESS)
		{
			NdisFDeregisterFilterDriver(FilterDriverHandle);
			FILTER_FREE_LOCK(&FilterListLock);
			DEBUGP(DL_WARN, "Register device for the filter driver failed.\n");
			break;
		}

	} while (bFalse);


	DEBUGP(DL_TRACE, "<=== DriverEntry, Status = %x\n", Status);
	return Status;
}

_Use_decl_annotations_
NDIS_STATUS
FilterRegisterOptions(
	NDIS_HANDLE  NdisFilterDriverHandle,
	NDIS_HANDLE  FilterDriverContext
)
/*++

Routine Description:
	Register optional handlers with NDIS.

Arguments:
	NdisFilterDriverHandle - pointer the driver handle received from
							 NdisFRegisterFilterDriver

	FilterDriverContext    - pointer to our context passed into
							 NdisFRegisterFilterDriver

Return Value:

	NDIS_STATUS_SUCCESS

--*/
{
	DEBUGP(DL_TRACE, "===> FilterRegisterOptions\n");

	ASSERT(NdisFilterDriverHandle == FilterDriverHandle);
	ASSERT(FilterDriverContext == (NDIS_HANDLE)FilterDriverObject);

	if ((NdisFilterDriverHandle != (NDIS_HANDLE)FilterDriverHandle) ||
		(FilterDriverContext != (NDIS_HANDLE)FilterDriverObject))
	{
		return NDIS_STATUS_INVALID_PARAMETER;
	}

	DEBUGP(DL_TRACE, "<=== FilterRegisterOptions\n");

	return NDIS_STATUS_SUCCESS;
}

static VOID _FreeFilterNetPools(PMS_FILTER pFilter)
{
	DEBUGP(DL_TRACE, "===> _FreeFilterNetPools: pFilter %p\n", pFilter);

	if (pFilter->NetBufferListPool != NULL)
	{
		NdisFreeNetBufferListPool(pFilter->NetBufferListPool);
		pFilter->NetBufferListPool = NULL;
	}
	if (pFilter->NetBufferPool != NULL)
	{
		NdisFreeNetBufferPool(pFilter->NetBufferPool);
		pFilter->NetBufferPool = NULL;
	}

	DEBUGP(DL_TRACE, "<=== _FreeFilterNetPools\n");
}

static NDIS_STATUS _AllocFilterNetPools(PMS_FILTER pFilter)
{
	DEBUGP(DL_TRACE, "===> _AllocFilterNetPools: pFilter %p\n", pFilter);

	NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
	NET_BUFFER_POOL_PARAMETERS PoolParameters;
	NET_BUFFER_LIST_POOL_PARAMETERS ListPoolParameters;

	do {
		NdisZeroMemory(&PoolParameters, sizeof(NET_BUFFER_POOL_PARAMETERS));
		PoolParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
		PoolParameters.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
		PoolParameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;
		PoolParameters.PoolTag = FILTER_ALLOC_TAG;
		PoolParameters.DataSize = 0;

		pFilter->NetBufferPool = NdisAllocateNetBufferPool(pFilter->FilterHandle, &PoolParameters);
		if (pFilter->NetBufferPool == NULL)
		{
			DEBUGP(DL_ERROR, "Failed to allocate NetBufferPool.\n");
			Status = NDIS_STATUS_RESOURCES;
			break;
		}

		NdisZeroMappedMemory(&ListPoolParameters, sizeof(NET_BUFFER_LIST_POOL_PARAMETERS));
		ListPoolParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
		ListPoolParameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
		ListPoolParameters.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
		ListPoolParameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
		ListPoolParameters.fAllocateNetBuffer = FALSE; //  TRUE;
		ListPoolParameters.ContextSize = FILTER_MEMORY_ALIGNMENT(sizeof(NET_BUFFER_LIST_CONTEXT));
		ListPoolParameters.PoolTag = FILTER_ALLOC_TAG;
		ListPoolParameters.DataSize = 0; // 1500 + 14 + 4; // Ethernet TODO: Dynamic Allocation

		pFilter->NetBufferListPool = NdisAllocateNetBufferListPool(pFilter->FilterHandle, &ListPoolParameters);
		if (pFilter->NetBufferListPool == NULL)
		{
			DEBUGP(DL_ERROR, "Failed to allocate NetBufferListPool.\n");
			Status = NDIS_STATUS_RESOURCES;
			break;
		}
	} while (FALSE);

	if (Status != NDIS_STATUS_SUCCESS)
	{
		_FreeFilterNetPools(pFilter);
	}

	DEBUGP(DL_TRACE, "<=== _AllocFilterNetPools: Status %x\n", Status);
	return Status;
}

static NTSTATUS
_StartFilterThread(
	_In_ PMS_FILTER pFilter
) {
	NTSTATUS Status = STATUS_SUCCESS;

	DEBUGP(DL_TRACE, "===> _StartFilterThread: pFilter %p\n", pFilter);

	KeInitializeEvent(&FilterThreadStopEvent, NotificationEvent, FALSE);

	Status = PsCreateSystemThread(
		&FilterThreadHandle,       // Handle to the thread
		THREAD_ALL_ACCESS,     // Access mask
		NULL,                  // Object attributes
		NULL,                  // Process handle
		NULL,                  // Client ID
		FilterThreadRoutine,         // Start routine
		(PVOID)pFilter                   // Start context
	);

	if (!NT_SUCCESS(Status))
	{
		DEBUGP(DL_ERROR, "Failed to create filter thread. Status %x\n", Status);
		FilterThreadHandle = NULL;
	}

	DEBUGP(DL_TRACE, "<=== _StartFilterThread: Status %x\n", Status);
	return Status;
}

static VOID
_StopFilterThread() {
	NTSTATUS Status;
	PKTHREAD FilterThreadObject = NULL;

	DEBUGP(DL_TRACE, "===> _StopFilterThread\n");

	if (FilterThreadHandle)
	{
		Status = ObReferenceObjectByHandle(
			FilterThreadHandle,
			THREAD_ALL_ACCESS,
			*PsThreadType,
			KernelMode,
			(PVOID*)&FilterThreadObject,
			NULL
		);

		KeSetEvent(&FilterThreadStopEvent, IO_NO_INCREMENT, FALSE);

		if (Status == STATUS_SUCCESS) {
			KeWaitForSingleObject(
				FilterThreadObject,
				Executive,
				KernelMode,
				FALSE,
				NULL
			);

			ObDereferenceObject(FilterThreadObject);
			FilterThreadObject = NULL;
		}

		ZwClose(FilterThreadHandle);
		FilterThreadHandle = NULL;
	}

	DEBUGP(DL_TRACE, "<=== _StopFilterThread\n");
}

_Use_decl_annotations_
NDIS_STATUS
FilterAttach(
	NDIS_HANDLE                     NdisFilterHandle,
	NDIS_HANDLE                     FilterDriverContext,
	PNDIS_FILTER_ATTACH_PARAMETERS  AttachParameters
)
/*++
Routine Description:
	Filter attach routine.
	Create filter's context, allocate NetBufferLists and NetBuffer pools and any
	other resources, and read configuration if needed.

Arguments:
	NdisFilterHandle - Specify a handle identifying this instance of the filter. FilterAttach
					   should save this handle. It is a required  parameter in subsequent calls
					   to NdisFxxx functions.
	FilterDriverContext - Filter driver context passed to NdisFRegisterFilterDriver.
	AttachParameters - attach parameters

Return Value:
	NDIS_STATUS_SUCCESS: FilterAttach successfully allocated and initialize data structures
						 for this filter instance.
	NDIS_STATUS_RESOURCES: FilterAttach failed due to insufficient resources.
	NDIS_STATUS_FAILURE: FilterAttach could not set up this instance of this filter and it has called
						 NdisWriteErrorLogEntry with parameters specifying the reason for failure.

N.B.:  FILTER can use NdisRegisterDeviceEx to create a device, so the upper
	layer can send Irps to the filter.

--*/
{
	PMS_FILTER              pFilter = NULL;
	NDIS_STATUS             Status = NDIS_STATUS_SUCCESS;
	NDIS_FILTER_ATTRIBUTES  FilterAttributes;
	ULONG                   Size;
	BOOLEAN                 bFalse = FALSE;
	NTSTATUS NtStatus;

	DEBUGP(DL_TRACE, "===> FilterAttach: NdisFilterHandle %p\n", NdisFilterHandle);

	do
	{
		ASSERT(FilterDriverContext == (NDIS_HANDLE)FilterDriverObject);
		if (FilterDriverContext != (NDIS_HANDLE)FilterDriverObject)
		{
			Status = NDIS_STATUS_INVALID_PARAMETER;
			break;
		}

		// Verify the media type is supported.  This is a last resort; the
		// the filter should never have been bound to an unsupported miniport
		// to begin with.  If this driver is marked as a Mandatory filter (which
		// is the default for this sample; see the INF file), failing to attach
		// here will leave the network adapter in an unusable state.
		if ((AttachParameters->MiniportMediaType != NdisMedium802_3)
			&& (AttachParameters->MiniportMediaType != NdisMediumWan)
			&& (AttachParameters->MiniportMediaType != NdisMediumWirelessWan))
		{
			DEBUGP(DL_ERROR, "Unsupported miniport media type: %i\n", AttachParameters->MiniportMediaType);

			Status = NDIS_STATUS_INVALID_PARAMETER;
			break;
		}

		Size = sizeof(MS_FILTER) +
			AttachParameters->FilterModuleGuidName->Length +
			AttachParameters->BaseMiniportInstanceName->Length +
			AttachParameters->BaseMiniportName->Length;

		pFilter = (PMS_FILTER)FILTER_ALLOC_MEM(NdisFilterHandle, Size);
		if (pFilter == NULL)
		{
			DEBUGP(DL_WARN, "Failed to allocate context structure.\n");
			Status = NDIS_STATUS_RESOURCES;
			break;
		}

		NdisZeroMemory(pFilter, sizeof(MS_FILTER));

		pFilter->FilterModuleName.Length = pFilter->FilterModuleName.MaximumLength = AttachParameters->FilterModuleGuidName->Length;
		pFilter->FilterModuleName.Buffer = (PWSTR)((PUCHAR)pFilter + sizeof(MS_FILTER));
		NdisMoveMemory(pFilter->FilterModuleName.Buffer,
			AttachParameters->FilterModuleGuidName->Buffer,
			pFilter->FilterModuleName.Length);

		pFilter->MiniportFriendlyName.Length = pFilter->MiniportFriendlyName.MaximumLength = AttachParameters->BaseMiniportInstanceName->Length;
		pFilter->MiniportFriendlyName.Buffer = (PWSTR)((PUCHAR)pFilter->FilterModuleName.Buffer + pFilter->FilterModuleName.Length);
		NdisMoveMemory(pFilter->MiniportFriendlyName.Buffer,
			AttachParameters->BaseMiniportInstanceName->Buffer,
			pFilter->MiniportFriendlyName.Length);


		pFilter->MiniportName.Length = pFilter->MiniportName.MaximumLength = AttachParameters->BaseMiniportName->Length;
		pFilter->MiniportName.Buffer = (PWSTR)((PUCHAR)pFilter->MiniportFriendlyName.Buffer +
			pFilter->MiniportFriendlyName.Length);
		NdisMoveMemory(pFilter->MiniportName.Buffer,
			AttachParameters->BaseMiniportName->Buffer,
			pFilter->MiniportName.Length);

		pFilter->MiniportIfIndex = AttachParameters->BaseMiniportIfIndex;
		pFilter->FilterHandle = NdisFilterHandle;

		NdisZeroMemory(&FilterAttributes, sizeof(NDIS_FILTER_ATTRIBUTES));
		FilterAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
		FilterAttributes.Header.Size = sizeof(NDIS_FILTER_ATTRIBUTES);
		FilterAttributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
		FilterAttributes.Flags = 0;

		NDIS_DECLARE_FILTER_MODULE_CONTEXT(MS_FILTER);
		Status = NdisFSetAttributes(NdisFilterHandle,
			pFilter,
			&FilterAttributes);
		if (Status != NDIS_STATUS_SUCCESS)
		{
			DEBUGP(DL_WARN, "Failed to set attributes.\n");
			break;
		}

		Status = _AllocFilterNetPools(pFilter);
		if (Status != NDIS_STATUS_SUCCESS) {
			DEBUGP(DL_WARN, "Failed to initialize filter pools.\n");
			break;
		}

		NtStatus = _StartFilterThread(pFilter);
		if (!NT_SUCCESS(NtStatus)) {
			DEBUGP(DL_WARN, "Failed to start filter thread.\n");
			break;
		}

		InitializeQueueHeader(&pFilter->NetBufferListsQueue);
		pFilter->State = FilterPaused;

		FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
		InsertHeadList(&FilterModuleList, &pFilter->FilterModuleLink);
		FILTER_RELEASE_LOCK(&FilterListLock, bFalse);

	} while (bFalse);

	if (Status != NDIS_STATUS_SUCCESS)
	{
		if (pFilter != NULL)
		{
			_FreeFilterNetPools(pFilter);
			FILTER_FREE_MEM(pFilter);
		}
	}

	DEBUGP(DL_TRACE, "<=== FilterAttach:\tStatus %x\n", Status);
	return Status;
}

_Use_decl_annotations_
NDIS_STATUS
FilterPause(
	NDIS_HANDLE                     FilterModuleContext,
	PNDIS_FILTER_PAUSE_PARAMETERS   PauseParameters
)
/*++

Routine Description:

	Filter pause routine.
	Complete all the outstanding sends and queued sends,
	wait for all the outstanding recvs to be returned
	and return all the queued receives.

Arguments:

	FilterModuleContext - pointer to the filter context stucture
	PauseParameters     - additional information about the pause

Return Value:

	NDIS_STATUS_SUCCESS if filter pauses successfully, NDIS_STATUS_PENDING
	if not.  No other return value is allowed (pause must succeed, eventually).

N.B.: When the filter is in Pausing state, it can still process OID requests,
	complete sending, and returning packets to NDIS, and also indicate status.
	After this function completes, the filter must not attempt to send or
	receive packets, but it may still process OID requests and status
	indications.

--*/
{
	PMS_FILTER          pFilter = (PMS_FILTER)(FilterModuleContext);
	NDIS_STATUS         Status;
	BOOLEAN               bFalse = FALSE;

	UNREFERENCED_PARAMETER(PauseParameters);

	DEBUGP(DL_TRACE, "===> FilterPause:\tFilterInstance %p\n", FilterModuleContext);

	//
	// Set the flag that the filter is going to pause
	//
	FILTER_ASSERT(pFilter->State == FilterRunning);

	FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);
	pFilter->State = FilterPausing;
	FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);

	//
	// Do whatever work is required to bring the filter into the Paused state.
	//
	// If you have diverted and queued any send or receive NBLs, return them
	// now.
	//
	// If you send or receive original NBLs, stop doing that and wait for your
	// NBLs to return to you now.
	//

	Status = NDIS_STATUS_SUCCESS;

	pFilter->State = FilterPaused;

	DEBUGP(DL_TRACE, "<=== FilterPause:  Status %x\n", Status);
	return Status;
}

_Use_decl_annotations_
NDIS_STATUS
FilterRestart(
	NDIS_HANDLE                     FilterModuleContext,
	PNDIS_FILTER_RESTART_PARAMETERS RestartParameters
)
/*++

Routine Description:

	Filter restart routine.
	Start the datapath - begin sending and receiving NBLs.

Arguments:

	FilterModuleContext - pointer to the filter context stucture.
	RestartParameters   - additional information about the restart operation.

Return Value:

	NDIS_STATUS_SUCCESS: if filter restarts successfully
	NDIS_STATUS_XXX: Otherwise.

--*/
{
	NDIS_STATUS     Status;
	PMS_FILTER      pFilter = (PMS_FILTER)FilterModuleContext;

	PNDIS_RESTART_GENERAL_ATTRIBUTES NdisGeneralAttributes;
	PNDIS_RESTART_ATTRIBUTES         NdisRestartAttributes = RestartParameters->RestartAttributes;
	PNDIS_RESTART_ATTRIBUTES         NextAttributes;

	DEBUGP(DL_TRACE, "===> FilterRestart:\tFilterModuleContext %p\n", FilterModuleContext);
	FILTER_ASSERT(pFilter->State == FilterPaused);

	// If NdisRestartAttributes is not NULL, then the filter can modify generic
	// attributes and add new media specific info attributes at the end.
	// Otherwise, if NdisRestartAttributes is NULL, the filter should not try to
	// modify/add attributes.
	if (NdisRestartAttributes != NULL)
	{
		ASSERT(NdisRestartAttributes->Oid == OID_GEN_MINIPORT_RESTART_ATTRIBUTES);

		NdisGeneralAttributes = (PNDIS_RESTART_GENERAL_ATTRIBUTES)NdisRestartAttributes->Data;

		// Check to see if we need to change any attributes. For example, the
		// driver can change the current MAC address here. Or the driver can add
		// media specific info attributes.
		NdisGeneralAttributes->LookaheadSize = 128;
		NextAttributes = NdisRestartAttributes->Next;

		while (NextAttributes != NULL)
		{
			// If somehow the filter needs to change a attributes which requires more space then
			// the current attributes:
			// 1. Remove the attribute from the Attributes list:
			//    TempAttributes = NextAttributes;
			//    NextAttributes = NextAttributes->Next;
			// 2. Free the memory for the current attributes: NdisFreeMemory(TempAttributes, 0 , 0);
			// 3. Dynamically allocate the memory for the new attributes by calling
			//    NdisAllocateMemoryWithTagPriority:
			//    NewAttributes = NdisAllocateMemoryWithTagPriority(Handle, size, Priority);
			// 4. Fill in the new attribute
			// 5. NewAttributes->Next = NextAttributes;
			// 6. NextAttributes = NewAttributes; // Just to make the next statement work.
			//
			NextAttributes = NextAttributes->Next;
		}

		//
		// Add a new attributes at the end
		// 1. Dynamically allocate the memory for the new attributes by calling
		//    NdisAllocateMemoryWithTagPriority.
		// 2. Fill in the new attribute
		// 3. NextAttributes->Next = NewAttributes;
		// 4. NewAttributes->Next = NULL;
	}

	// If everything is OK, set the filter in running state.
	Status = NDIS_STATUS_SUCCESS;
	pFilter->State = FilterRunning;

	if (Status != NDIS_STATUS_SUCCESS)
	{
		pFilter->State = FilterPaused;
	}

	DEBUGP(DL_TRACE, "<=== FilterRestart:\tFilterModuleContext %p, Status %x\n", FilterModuleContext, Status);
	return Status;
}


_Use_decl_annotations_
VOID
FilterDetach(
	NDIS_HANDLE     FilterModuleContext
)
/*++

Routine Description:
	Filter detach routine.
	This is a required function that will deallocate all the resources allocated during
	FilterAttach. NDIS calls FilterAttach to remove a filter instance from a filter stack.

Arguments:
	FilterModuleContext - pointer to the filter context area.

Return Value:
	None.

NOTE: Called at PASSIVE_LEVEL and the filter is in paused state

--*/
{
	PMS_FILTER                  pFilter = (PMS_FILTER)FilterModuleContext;
	BOOLEAN                      bFalse = FALSE;


	DEBUGP(DL_TRACE, "===> FilterDetach:\tFilterInstance %p\n", FilterModuleContext);
	FILTER_ASSERT(pFilter->State == FilterPaused);

	// @NOTE: Detach must not fail, so do not put any code here that can possibly fail.
	// @TODO: Check if we need to free other Buffers?
	if (pFilter->FilterName.Buffer != NULL)
	{
		FILTER_FREE_MEM(pFilter->FilterName.Buffer);
	}

	_StopFilterThread();
	_FreeFilterNetPools(pFilter);

	FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
	RemoveEntryList(&pFilter->FilterModuleLink);
	FILTER_RELEASE_LOCK(&FilterListLock, bFalse);

	FILTER_FREE_MEM(pFilter);

	DEBUGP(DL_TRACE, "<=== FilterDetach Successfully\n");
	return;
}

_Use_decl_annotations_
VOID
FilterUnload(
	PDRIVER_OBJECT      DriverObject
)
/*++

Routine Description:
	Filter driver's unload routine.
	Deregister the driver from NDIS.

Arguments:
	DriverObject - pointer to the system's driver object structure
				   for this driver

--*/
{
#if DBG
	BOOLEAN               bFalse = FALSE;
#endif

	UNREFERENCED_PARAMETER(DriverObject);

	DEBUGP(DL_TRACE, "===> FilterUnload\n");

	//
	// Should free the filter context list
	//
	ndismfdDeregisterDevice();
	NdisFDeregisterFilterDriver(FilterDriverHandle);

#if DBG
	FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
	ASSERT(IsListEmpty(&FilterModuleList));

	FILTER_RELEASE_LOCK(&FilterListLock, bFalse);

#endif

	FILTER_FREE_LOCK(&FilterListLock);

	DEBUGP(DL_TRACE, "<=== FilterUnload\n");

	return;
}

_Use_decl_annotations_
VOID
FilterReturnNetBufferLists(
	NDIS_HANDLE         FilterModuleContext,
	PNET_BUFFER_LIST    NetBufferLists,
	ULONG               ReturnFlags
)
/*++
Routine Description:
	FilterReturnNetBufferLists handler.
	FilterReturnNetBufferLists is an optional function. If provided, NDIS calls
	FilterReturnNetBufferLists to return the ownership of one or more NetBufferLists
	and their embedded NetBuffers to the filter driver. If this handler is NULL, NDIS
	will skip calling this filter when returning NetBufferLists to the underlying
	miniport and will call the next lower driver in the stack. A filter that doesn't
	provide a FilterReturnNetBufferLists handler cannot originate a receive indication
	on its own.

Arguments:

	FilterInstanceContext       - our filter context area
	NetBufferLists              - a linked list of NetBufferLists that this
								  filter driver indicated in a previous call to
								  NdisFIndicateReceiveNetBufferLists
	ReturnFlags                 - flags specifying if the caller is at DISPATCH_LEVEL

--*/
{
	// PMS_FILTER          pFilter = (PMS_FILTER)FilterModuleContext;
	PNET_BUFFER_LIST    CurrNbl = NetBufferLists;
	PNET_BUFFER_LIST    NextNbl = NULL;
	UINT                NumOfNetBufferLists = 0;

	UNREFERENCED_PARAMETER(FilterModuleContext);
	UNREFERENCED_PARAMETER(ReturnFlags);
	DEBUGP(DL_TRACE, "===> ReturnNetBufferLists, NetBufferLists is %p.\n", NetBufferLists);

	// If your filter injected any receive packets into the datapath to be
	// received, you must identify their NBLs here and remove them from the
	// chain.  Do not attempt to receive-return your NBLs down to the lower
	// layer.

	// If your filter has modified any NBLs (or NBs, MDLs, etc) in your
	// FilterReceiveNetBufferLists handler, you must undo the modifications here.
	// In general, NBLs must be returned in the same condition in which you had
	// you received them.  (Exceptions: the NBLs can be re-ordered on the linked
	// list, and the scratch fields are don't-care).

	while (CurrNbl)
	{
		NumOfNetBufferLists++;
		NextNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl);
		NET_BUFFER_LIST_NEXT_NBL(CurrNbl) = NULL;
		NdisFreeCloneNetBufferList(CurrNbl, 0);
		CurrNbl = NextNbl;
	}

	DEBUGP(DL_TRACE, "<<< Return NBLs number = %d\n", NumOfNetBufferLists);

	DEBUGP(DL_TRACE, "<=== ReturnNetBufferLists.\n");
}

_Use_decl_annotations_
VOID
FilterReceiveNetBufferLists(
	NDIS_HANDLE         FilterModuleContext,
	PNET_BUFFER_LIST    NetBufferLists,
	NDIS_PORT_NUMBER    PortNumber,
	ULONG               NumberOfNetBufferLists,
	ULONG               ReceiveFlags
)
/*++
Routine Description:
	FilerReceiveNetBufferLists is an optional function for filter drivers.
	If provided, this function processes receive indications made by underlying
	NIC or lower level filter drivers. This function  can also be called as a
	result of loopback. If this handler is NULL, NDIS will skip calling this
	filter when processing a receive indication and will call the next higher
	driver in the stack. A filter that doesn't provide a
	FilterReceiveNetBufferLists handler cannot provide a
	FilterReturnNetBufferLists handler and cannot a initiate an original receive
	indication on its own.

Arguments:
	FilterModuleContext      - our filter context area.
	NetBufferLists           - a linked list of NetBufferLists
	PortNumber               - Port on which the receive is indicated
	ReceiveFlags             -

N.B.: It is important to check the ReceiveFlags in NDIS_TEST_RECEIVE_CANNOT_PEND.
	This controls whether the receive indication is an synchronous or
	asynchronous function call.
--*/
{

	PMS_FILTER          pFilter = (PMS_FILTER)FilterModuleContext;
	BOOLEAN             DispatchLevel;
	BOOLEAN             bFalse = FALSE;
	PNET_BUFFER_LIST    CurrNbl = NULL;
	PNET_BUFFER_LIST    DupNbl = NULL;
	PFILTER_QUEUE_ENTRY pFilterQueue;
	PQUEUE_ENTRY	    pQueueEntry;
#if DBG
	ULONG               ReturnFlags;
#endif

	DispatchLevel = NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags);
	DEBUGP(DL_TRACE, "===> ReceiveNetBufferList: NetBufferLists = %p DispatchLevel = %i.\n", NetBufferLists, DispatchLevel);
	do
	{
#if DBG
		FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);

		if (pFilter->State != FilterRunning)
		{
			FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);

			if (NDIS_TEST_RECEIVE_CAN_PEND(ReceiveFlags))
			{
				ReturnFlags = 0;
				if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags))
				{
					NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
				}

				NdisFReturnNetBufferLists(pFilter->FilterHandle, NetBufferLists, ReturnFlags);
			}
			break;
		}
		FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
#endif

		ASSERT(NumberOfNetBufferLists >= 1);

		//
		// If you would like to drop a received packet, then you must carefully
		// modify the NBL chain as follows:
		//
		//     if NDIS_TEST_RECEIVE_CANNOT_PEND(ReceiveFlags):
		//         For each NBL that is NOT dropped, temporarily unlink it from
		//         the linked list, and indicate it up alone with
		//         NdisFIndicateReceiveNetBufferLists and the
		//         NDIS_RECEIVE_FLAGS_RESOURCES flag set.  Then immediately
		//         relink the NBL back into the chain.  When all NBLs have been
		//         indicated up, you may return from this function.
		//     otherwise (NDIS_TEST_RECEIVE_CANNOT_PEND is FALSE):
		//         Divide the linked list of NBLs into two chains: one chain
		//         of packets to drop, and everything else in another chain.
		//         Return the first chain with NdisFReturnNetBufferLists, and
		//         indicate up the rest with NdisFIndicateReceiveNetBufferLists.
		//
		// Note: on the receive path for Ethernet packets, one NBL will have
		// exactly one NB.  So (assuming you are receiving on Ethernet, or are
		// attached above Native WiFi) you do not need to worry about dropping
		// one NB, but trying to indicate up the remaining NBs on the same NBL.
		// In other words, if the first NB should be dropped, drop the whole NBL.
		//

		//
		// If you would like to modify a packet, and can do so quickly, you may
		// do it here.  However, make sure you save enough information to undo
		// your modification in the FilterReturnNetBufferLists handler.
		//

		//
		// If necessary, queue the NetBufferLists in a local structure for later
		// processing.  However, do not queue them for "too long", or else the
		// system's performance may be degraded.  If you need to hold onto an
		// NBL for an unbounded amount of time, then allocate memory, perform a
		// deep copy, and return the original NBL.
		//

		pFilterQueue = (FILTER_QUEUE_ENTRY*)FILTER_ALLOC_MEM(pFilter->FilterHandle, sizeof(FILTER_QUEUE_ENTRY));
		NdisZeroMemory(pFilterQueue, sizeof(FILTER_QUEUE_ENTRY));
		ASSERT(pFilterQueue); // FIXME: Add error handling
		InitializeQueueHeader(&pFilterQueue->NetBufferLists);
		pFilterQueue->PortNumber = PortNumber;
		pFilterQueue->ReceiveFlags = ReceiveFlags;
		pFilterQueue->NumberOfNetBufferLists = 0;
		pFilterQueue->Next = NULL;

		CurrNbl = NetBufferLists;
		while (CurrNbl != NULL)
		{
			// TODO: Check if applicable NDIS_CLONE_FLAGS_USE_ORIGINAL_MDLS
			DupNbl = NdisAllocateCloneNetBufferList(CurrNbl, pFilter->NetBufferListPool, 0, 0);
			ASSERT(DupNbl);
			if (DupNbl) {
				pQueueEntry = QUEUE_LINK_NET_BUFFER_LIST(DupNbl);
				InsertTailQueue(&pFilterQueue->NetBufferLists, pQueueEntry);
				pFilterQueue->NumberOfNetBufferLists++;

				CurrNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl);
			}
			// @FIXME: Add error handling
		}

		NdisFReturnNetBufferLists(pFilter->FilterHandle, NetBufferLists, 0);

		// Push the cloned NBLs to the filtering queue
		DEBUGP(DL_TRACE, "+++ Queue COPIED NBLs, number = %d\n", NumberOfNetBufferLists);
		FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
		pQueueEntry = QUEUE_LINK_TO_ENTRY(pFilterQueue);
		InsertTailQueue(&pFilter->NetBufferListsQueue, pQueueEntry);
		FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);

	} while (bFalse);

	DEBUGP(DL_TRACE, "<=== ReceiveNetBufferList: Flags = 0x%8x.\n", ReceiveFlags);

}

_IRQL_requires_max_(DISPATCH_LEVEL)
NDIS_STATUS
filterDoInternalRequest(
	_In_ PMS_FILTER                   FilterModuleContext,
	_In_ NDIS_REQUEST_TYPE            RequestType,
	_In_ NDIS_OID                     Oid,
	_Inout_updates_bytes_to_(InformationBufferLength, *pBytesProcessed)
	PVOID                        InformationBuffer,
	_In_ ULONG                        InformationBufferLength,
	_In_opt_ ULONG                    OutputBufferLength,
	_In_ ULONG                        MethodId,
	_Out_ PULONG                      pBytesProcessed
)
/*++

Routine Description:

	Utility routine that forms and sends an NDIS_OID_REQUEST to the
	miniport, waits for it to complete, and returns status
	to the caller.

	NOTE: this assumes that the calling routine ensures validity
	of the filter handle until this returns.

Arguments:

	FilterModuleContext - pointer to our filter module context
	RequestType - NdisRequest[Set|Query|method]Information
	Oid - the object being set/queried
	InformationBuffer - data for the request
	InformationBufferLength - length of the above
	OutputBufferLength  - valid only for method request
	MethodId - valid only for method request
	pBytesProcessed - place to return bytes read/written

Return Value:

	Status of the set/query request

--*/
{
	FILTER_REQUEST              FilterRequest;
	PNDIS_OID_REQUEST           NdisRequest = &FilterRequest.Request;
	NDIS_STATUS                 Status;

	ASSERT(pBytesProcessed != NULL);

	*pBytesProcessed = 0;

	NdisZeroMemory(NdisRequest, sizeof(NDIS_OID_REQUEST));

	NdisInitializeEvent(&FilterRequest.ReqEvent);

	NdisRequest->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
	NdisRequest->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
	NdisRequest->Header.Size = sizeof(NDIS_OID_REQUEST);
	NdisRequest->RequestType = RequestType;

	switch (RequestType)
	{
	case NdisRequestQueryInformation:
		NdisRequest->DATA.QUERY_INFORMATION.Oid = Oid;
		NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer =
			InformationBuffer;
		NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength =
			InformationBufferLength;
		break;

	case NdisRequestSetInformation:
		NdisRequest->DATA.SET_INFORMATION.Oid = Oid;
		NdisRequest->DATA.SET_INFORMATION.InformationBuffer =
			InformationBuffer;
		NdisRequest->DATA.SET_INFORMATION.InformationBufferLength =
			InformationBufferLength;
		break;

	case NdisRequestMethod:
		NdisRequest->DATA.METHOD_INFORMATION.Oid = Oid;
		NdisRequest->DATA.METHOD_INFORMATION.MethodId = MethodId;
		NdisRequest->DATA.METHOD_INFORMATION.InformationBuffer =
			InformationBuffer;
		NdisRequest->DATA.METHOD_INFORMATION.InputBufferLength =
			InformationBufferLength;
		NdisRequest->DATA.METHOD_INFORMATION.OutputBufferLength = OutputBufferLength;
		break;



	default:

		ASSERTMSG("Invalid request type in filterDoInternalRequest",
			FALSE);

		break;
	}

	NdisRequest->RequestId = (PVOID)FILTER_REQUEST_ID;


	Status = NdisFOidRequest(FilterModuleContext->FilterHandle,
		NdisRequest);


	if (Status == NDIS_STATUS_PENDING)
	{
		NdisWaitEvent(&FilterRequest.ReqEvent, 0);
		Status = FilterRequest.Status;
	}



	if (Status == NDIS_STATUS_SUCCESS)
	{
		if (RequestType == NdisRequestSetInformation)
		{
			*pBytesProcessed = NdisRequest->DATA.SET_INFORMATION.BytesRead;
		}

		if (RequestType == NdisRequestQueryInformation)
		{
			*pBytesProcessed = NdisRequest->DATA.QUERY_INFORMATION.BytesWritten;
		}

		if (RequestType == NdisRequestMethod)
		{
			*pBytesProcessed = NdisRequest->DATA.METHOD_INFORMATION.BytesWritten;
		}

		//
		// The driver below should set the correct value to BytesWritten
		// or BytesRead. But now, we just truncate the value to InformationBufferLength
		//
		if (RequestType == NdisRequestMethod)
		{
			if (*pBytesProcessed > OutputBufferLength)
			{
				*pBytesProcessed = OutputBufferLength;
			}
		}
		else
		{

			if (*pBytesProcessed > InformationBufferLength)
			{
				*pBytesProcessed = InformationBufferLength;
			}
		}
	}


	return Status;
}

static BOOLEAN _IsAllowNetBuffer(_In_ MFD_PFSRV_ENTRY ServiceEntry)
{
	UNREFERENCED_PARAMETER(ServiceEntry);
	return TRUE;
}

static LONG _PrepareServiceQueue(_In_ PMS_FILTER Filter, _In_ PFILTER_QUEUE_ENTRY FilterQueueEntry, _Inout_ MFD_PFSRV_QUEUE SrvQueue) {
	ULONG NumberOfNetBuffer = 0;
	PNET_BUFFER pNetBuffer = NET_BUFFER_LIST_FIRST_NB((PNET_BUFFER_LIST)FilterQueueEntry->NetBufferLists.Head);
	ULONG i = 0;

	while (pNetBuffer) {
		NumberOfNetBuffer++;
		pNetBuffer = NET_BUFFER_NEXT_NB(pNetBuffer);
	}

	if (NumberOfNetBuffer <= 0) {
		return 0;
	}

	SrvQueue->Head = (MFD_PFSRV_ENTRY)FILTER_ALLOC_MEM(Filter->FilterHandle,
		sizeof(MFD_FSRV_ENTRY) * NumberOfNetBuffer);
	SrvQueue->Next = SrvQueue->Head;

	if (SrvQueue->Head == NULL) {
		DEBUGP(DL_WARN, "Alloc Filter Service Entry failed, number = %d\n", NumberOfNetBuffer);
		return -1;
	}

	NdisZeroMemory(SrvQueue->Head, sizeof(MFD_FSRV_ENTRY) * NumberOfNetBuffer);
	SrvQueue->NetBufferList = (PNET_BUFFER_LIST)FilterQueueEntry->NetBufferLists.Head;

	for (i = 1; i < NumberOfNetBuffer; i++) {
		SrvQueue->Head[i - 1].Next = &SrvQueue->Head[i];
	}
	SrvQueue->Head[NumberOfNetBuffer - 1].Next = NULL;

	return NumberOfNetBuffer;
}

VOID FilterThreadRoutine(_In_ PVOID ThreadContext)
{
	PMS_FILTER          pFilter = (PMS_FILTER)ThreadContext;
	BOOLEAN             DispatchLevel = FALSE;
	NTSTATUS            Status;
	LARGE_INTEGER       SleepTime;

	PFILTER_QUEUE_ENTRY pFilterQueueEntry = NULL;
	PQUEUE_ENTRY        pQueueEntry = NULL;
	PNET_BUFFER_LIST    pNetBufferList = NULL;

	MFD_FSRV_QUEUE      FilterServiceQueue;
	MFD_PFSRV_ENTRY     pSrvEntry;
	BOOLEAN             bResult;
	ULONG               NumberOfServiceEntries = 0;

	DEBUGP(DL_TRACE, "===> FilterThreadRoutine: pFilter %p\n", pFilter);

	NdisZeroMemory(&SleepTime, sizeof(LARGE_INTEGER));
	NdisZeroMemory(&FilterServiceQueue, sizeof(MFD_FSRV_QUEUE));
	while (TRUE)
	{
		SleepTime.QuadPart = 0;
		Status = KeWaitForSingleObject(&FilterThreadStopEvent, Executive, KernelMode, FALSE, &SleepTime);
		if (Status == STATUS_SUCCESS)
		{
			DEBUGP(DL_TRACE, "FilterThreadRoutine: Stop event signaled.\n");
			break;
		}

		// Take the first queued NetBufferLists from the filter queue
		pFilterQueueEntry = NULL;
		FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
		if (!IsQueueEmpty(&pFilter->NetBufferListsQueue)) {
			pQueueEntry = RemoveHeadQueue(&pFilter->NetBufferListsQueue);
			pFilterQueueEntry = QUEUE_UNLINK_FROM_ENTRY(pQueueEntry, FILTER_QUEUE_ENTRY);
		}
		FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);

		// Noting to process, wait for next iteration
		if (pFilterQueueEntry == NULL) {
			SleepTime.QuadPart = TIMER_RELATIVE(MILLISECONDS(100)); // TODO: Use signal event instead of sleep
			KeDelayExecutionThread(KernelMode, FALSE, &SleepTime);
			continue;
		}

		// Prepare the service queue for processing in the filter service
		// @FIXME: Currently we process only the first NBL in the queue, but need to process all of them
		NumberOfServiceEntries = _PrepareServiceQueue(pFilter, pFilterQueueEntry, &FilterServiceQueue);
		ASSERT(NumberOfServiceEntries > 0);

		bResult = TRUE;
		pSrvEntry = FilterServiceQueue.Head;
		// Check Network Buffers
		// @FIXME: If any, drops whole NET_BUFFER_LIST
		while (pSrvEntry) {
			if (!_IsAllowNetBuffer(pSrvEntry)) {
				bResult = FALSE;
				break;
			}
			pSrvEntry = pSrvEntry->Next;
		}

		DEBUGP(DL_TRACE, "??? Processed Service Queue: NetBuffers = %d, bResult = %d\n",
			NumberOfServiceEntries, bResult);

		if (bResult) {
			DEBUGP(DL_TRACE, ">>> Indicate COPIED NBLs, number = %d\n", pFilterQueueEntry->NumberOfNetBufferLists);
			pNetBufferList = QUEUE_UNLINK_NET_BUFFER_LIST(pFilterQueueEntry->NetBufferLists.Head);
			NdisFIndicateReceiveNetBufferLists(pFilter->FilterHandle,
				pNetBufferList,
				pFilterQueueEntry->PortNumber,
				pFilterQueueEntry->NumberOfNetBufferLists,
				pFilterQueueEntry->ReceiveFlags);
		}

		FILTER_FREE_MEM(FilterServiceQueue.Head);
		FILTER_FREE_MEM(pFilterQueueEntry); // Free the filter queue processed entry
		pFilterQueueEntry = NULL;
	}

	DEBUGP(DL_TRACE, "<=== FilterThreadRoutine\n");

	PsTerminateSystemThread(STATUS_SUCCESS);
}