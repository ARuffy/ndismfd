/*++

Module Name:

	Filter.h

Abstract:

	This module contains all prototypes and macros for filter code.

--*/
#ifndef _FILT_H
#define _FILT_H

#pragma warning(disable:28930) // Unused assignment of pointer, by design in samples
#pragma warning(disable:28931) // Unused assignment of variable, by design in samples

// TODO: Customize these to hint at your component for memory leak tracking.
// These should be treated like a pooltag.
#define FILTER_REQUEST_ID          'RTLF'
#define FILTER_ALLOC_TAG           'tliF'
#define FILTER_TAG                 'dnTF'

// TODO: Specify which version of the NDIS contract you will use here.
// In many cases, 6.0 is the best choice.  You only need to select a later
// version if you need a feature that is not available in 6.0.
//
// Legal values include:
//    6.0  Available starting with Windows Vista RTM
//    6.1  Available starting with Windows Vista SP1 / Windows Server 2008
//    6.20 Available starting with Windows 7 / Windows Server 2008 R2
//    6.30 Available starting with Windows 8 / Windows Server "8"
#define FILTER_MAJOR_NDIS_VERSION   6

#if defined(NDIS60)
#define FILTER_MINOR_NDIS_VERSION   0
#elif defined(NDIS620)
#define FILTER_MINOR_NDIS_VERSION   20
#elif defined(NDIS630)
#define FILTER_MINOR_NDIS_VERSION   30
#endif

// TODO: Draft implementation of filtering rules
#define FILTER_MAX_LOCK_IP_ADDRESS_NUM (32)
#define FILTER_MAX_LOCK_PORT_NUM (8)

typedef struct _FILTER_BLOCK_TABLE
{
	ULONG IpAddress[FILTER_MAX_LOCK_IP_ADDRESS_NUM];
	ULONG IpAddressNumber;
	USHORT Port[FILTER_MAX_LOCK_IP_ADDRESS_NUM * FILTER_MAX_LOCK_PORT_NUM];
} FILTER_BLOCK_TABLE, * PFILTER_BLOCK_TABLE;

//
// Global variables
//
extern NDIS_HANDLE         FilterDriverHandle; // NDIS handle for filter driver
extern NDIS_HANDLE         FilterDriverObject;
extern NDIS_HANDLE         NdisFilterDeviceHandle;
extern PDEVICE_OBJECT      NdisDeviceObject;

extern FILTER_LOCK         FilterListLock;
extern LIST_ENTRY          FilterModuleList;

extern FILTER_LOCK         FilterTableLock;
extern FILTER_BLOCK_TABLE  FilterBlockTable;

#define FILTER_FRIENDLY_NAME        L"ndismfd NDIS LightWeight Filter"
#define FILTER_UNIQUE_NAME          L"{c339e1e4-62a0-45a0-8b80-62b0adbb11af}" //unique name, quid name
#define FILTER_SERVICE_NAME         L"ndismfd"

//
// The filter needs to handle IOCTLs
//
#define LINKNAME_STRING             L"\\DosDevices\\ndismfd"
#define NTDEVICE_STRING             L"\\Device\\ndismfd"

#define FILTER_MEMORY_ALIGNMENT(_Bytes) \
    (((_Bytes) + (MEMORY_ALLOCATION_ALIGNMENT - 1)) & ~(MEMORY_ALLOCATION_ALIGNMENT - 1))

//
// DEBUG related macros.
//
#if DBG
#define FILTER_ALLOC_MEM(_NdisHandle, _Size)    \
    filterAuditAllocMem(                        \
            _NdisHandle,                        \
           _Size,                               \
           __FILENUMBER,                        \
           __LINE__);

#define FILTER_FREE_MEM(_pMem)                  \
    filterAuditFreeMem(_pMem);

#else
#define FILTER_ALLOC_MEM(_NdisHandle, _Size)     \
    NdisAllocateMemoryWithTagPriority(_NdisHandle, _Size, FILTER_ALLOC_TAG, LowPoolPriority)

#define FILTER_FREE_MEM(_pMem)    NdisFreeMemory(_pMem, 0, 0)

#endif //DBG

#if DBG_SPIN_LOCK
#define FILTER_INIT_LOCK(_pLock)                          \
    filterAllocateSpinLock(_pLock, __FILENUMBER, __LINE__)

#define FILTER_FREE_LOCK(_pLock)       filterFreeSpinLock(_pLock)


#define FILTER_ACQUIRE_LOCK(_pLock, DispatchLevel)  \
    filterAcquireSpinLock(_pLock, __FILENUMBER, __LINE__, DisaptchLevel)

#define FILTER_RELEASE_LOCK(_pLock, DispatchLevel)      \
    filterReleaseSpinLock(_pLock, __FILENUMBER, __LINE__, DispatchLevel)

#else
#define FILTER_INIT_LOCK(_pLock)      NdisAllocateSpinLock(_pLock)

#define FILTER_FREE_LOCK(_pLock)      NdisFreeSpinLock(_pLock)

#define FILTER_ACQUIRE_LOCK(_pLock, DispatchLevel)              \
    {                                                           \
        if (DispatchLevel)                                      \
        {                                                       \
            NdisDprAcquireSpinLock(_pLock);                     \
        }                                                       \
        else                                                    \
        {                                                       \
            NdisAcquireSpinLock(_pLock);                        \
        }                                                       \
    }

#define FILTER_RELEASE_LOCK(_pLock, DispatchLevel)              \
    {                                                           \
        if (DispatchLevel)                                      \
        {                                                       \
            NdisDprReleaseSpinLock(_pLock);                     \
        }                                                       \
        else                                                    \
        {                                                       \
            NdisReleaseSpinLock(_pLock);                        \
        }                                                       \
    }
#endif //DBG_SPIN_LOCK

#define TIMER_RELATIVE(wait) (-(wait))
#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILLISECONDS(1000L))

//
// Enum of filter's states
// Filter can only be in one state at one time
//
typedef enum _FILTER_STATE
{
	FilterStateUnspecified,
	FilterInitialized,
	FilterPausing,
	FilterPaused,
	FilterRunning,
	FilterRestarting,
	FilterDetaching
} FILTER_STATE;

typedef struct _MS_FILTER
{
	LIST_ENTRY                      FilterModuleLink;
	ULONG                           RefCount;     // Reference to this filter

	NDIS_HANDLE                     FilterHandle;
	NDIS_STRING                     FilterModuleName;
	NDIS_STRING                     MiniportFriendlyName;
	NDIS_STRING                     MiniportName;
	NET_IFINDEX                     MiniportIfIndex;

	NDIS_STATUS                     Status;

	FILTER_LOCK                     Lock;    // Lock for protection of state and outstanding sends and recvs
	FILTER_STATE                    State;   // Which state the filter is in

	NDIS_STRING                     FilterName;

	// NBL Pool
	NDIS_HANDLE                     NetBufferPool;
	NDIS_HANDLE                     NetBufferListPool;

	QUEUE_HEADER                    NetBufferListsQueue; // NetBufferLists that are queued for processing
	FILTER_RING_BUFFER              ServiceEntryRingBuffer; // Ring buffer for Service Entries
} MS_FILTER, * PMS_FILTER;


typedef struct _FILTER_DEVICE_EXTENSION
{
	ULONG            Signature;
	NDIS_HANDLE      Handle;
} FILTER_DEVICE_EXTENSION, * PFILTER_DEVICE_EXTENSION;


#define FILTER_READY_TO_PAUSE(_Filter)      \
    ((_Filter)->State == FilterPausing)

//
// The driver should maintain a list of NDIS filter handles
//
typedef struct _FL_NDIS_FILTER_LIST
{
	LIST_ENTRY              Link;
	NDIS_HANDLE             ContextHandle;
	NDIS_STRING             FilterInstanceName;
} FL_NDIS_FILTER_LIST, * PFL_NDIS_FILTER_LIST;

//
// The context inside a cloned request
//
typedef struct _NDIS_OID_REQUEST* FILTER_REQUEST_CONTEXT, ** PFILTER_REQUEST_CONTEXT;


//
// function prototypes
//

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;

FILTER_ATTACH FilterAttach;
FILTER_DETACH FilterDetach;
DRIVER_UNLOAD FilterUnload;
FILTER_RESTART FilterRestart;
FILTER_PAUSE FilterPause;

FILTER_SET_OPTIONS FilterRegisterOptions;

FILTER_RETURN_NET_BUFFER_LISTS FilterReturnNetBufferLists;
FILTER_RECEIVE_NET_BUFFER_LISTS FilterReceiveNetBufferLists;

VOID FilterThreadRoutine(_In_ PVOID ThreadContext);

_IRQL_requires_max_(PASSIVE_LEVEL)
NDIS_STATUS
ndismfdRegisterDevice(
	VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
ndismfdDeregisterDevice(
	VOID
);

DRIVER_DISPATCH ndismfdDispatch;

DRIVER_DISPATCH ndismfdDeviceIoControl;

_IRQL_requires_max_(DISPATCH_LEVEL)
PMS_FILTER
filterFindFilterModule(
	_In_reads_bytes_(BufferLength)
	PUCHAR                   Buffer,
	_In_ ULONG                    BufferLength
);
EXTERN_C_END

#endif  //_FILT_H


