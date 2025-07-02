#ifndef _FILT_QUEUE_H
#define _FILT_QUEUE_H

//
// Types and macros to manipulate packet queue
//
typedef struct _QUEUE_ENTRY
{
	struct _QUEUE_ENTRY* Next;
}QUEUE_ENTRY, * PQUEUE_ENTRY;

typedef struct _QUEUE_HEADER
{
	PQUEUE_ENTRY     Head;
	PQUEUE_ENTRY     Tail;
} QUEUE_HEADER, * PQUEUE_HEADER;

//
// Macros for queue operations
//
#define InitializeQueueHeader(_QueueHeader)             \
{                                                       \
    (_QueueHeader)->Head = (_QueueHeader)->Tail = NULL; \
}

#define IsQueueEmpty(_QueueHeader)      ((_QueueHeader)->Head == NULL)

#define RemoveHeadQueue(_QueueHeader)                   \
    (_QueueHeader)->Head;                               \
    {                                                   \
        PQUEUE_ENTRY pNext;                             \
        ASSERT((_QueueHeader)->Head);                   \
        pNext = (_QueueHeader)->Head->Next;             \
        (_QueueHeader)->Head = pNext;                   \
        if (pNext == NULL)                              \
            (_QueueHeader)->Tail = NULL;                \
    }

#define InsertHeadQueue(_QueueHeader, _QueueEntry)                  \
    {                                                               \
        ((PQUEUE_ENTRY)(_QueueEntry))->Next = (_QueueHeader)->Head; \
        (_QueueHeader)->Head = (PQUEUE_ENTRY)(_QueueEntry);         \
        if ((_QueueHeader)->Tail == NULL)                           \
            (_QueueHeader)->Tail = (PQUEUE_ENTRY)(_QueueEntry);     \
    }

#define InsertTailQueue(_QueueHeader, _QueueEntry)                      \
    {                                                                   \
        ((PQUEUE_ENTRY)(_QueueEntry))->Next = NULL;                     \
        if ((_QueueHeader)->Tail)                                       \
            (_QueueHeader)->Tail->Next = (PQUEUE_ENTRY)(_QueueEntry);   \
        else                                                            \
            (_QueueHeader)->Head = (PQUEUE_ENTRY)(_QueueEntry);         \
        (_QueueHeader)->Tail = (PQUEUE_ENTRY)(_QueueEntry);             \
    }

#define QUEUE_LINK_FIELD_TO_ENTRY(_pNextField) ((PQUEUE_ENTRY)(&(_pNextField)))
#define QUEUE_LINK_NET_BUFFER_LIST(_pNBL) QUEUE_LINK_FIELD_TO_ENTRY(NET_BUFFER_LIST_NEXT_NBL(_pNBL))
#define QUEUE_LINK_TO_ENTRY(_pObj) QUEUE_LINK_FIELD_TO_ENTRY((_pObj)->Next)

#define QUEUE_UNLINK_FROM_ENTRY(_pEnt, _Type)           (CONTAINING_RECORD((_pEnt), _Type, Next))
#define QUEUE_UNLINK_NET_BUFFER_LIST(_pEnt)         QUEUE_UNLINK_FROM_ENTRY(_pEnt, NET_BUFFER_LIST)

// Filter Buffer Lists Queue

typedef struct _MFD_FILTER_QUEUE_ENTRY {
	struct _MFD_FILTER_QUEUE_ENTRY* Next;

	QUEUE_HEADER     NetBufferLists;
	ULONG            NumberOfNetBufferLists;
	NDIS_PORT_NUMBER PortNumber;
	ULONG            ReceiveFlags;
} FILTER_QUEUE_ENTRY, * PFILTER_QUEUE_ENTRY;

// TODO ==============================================

typedef struct _MFD_FILTER_SERVICE_ENTRY
{
	ULONG      Length;
	USHORT     Port;
	ULONGLONG  NetBufferId;
	STRING     IpAddr;

	struct _MFD_FILTER_SERVICE_ENTRY* Next;
} MFD_FSRV_ENTRY, * MFD_PFSRV_ENTRY;

typedef struct _MFD_FILTER_SERVICE_QUEUE {
	PNET_BUFFER_LIST NetBufferList;
	MFD_PFSRV_ENTRY Head;
	MFD_PFSRV_ENTRY Next; // Next Buffer To Process
} MFD_FSRV_QUEUE, * MFD_PFSRV_QUEUE;

#endif // _FILT_QUEUE_H
