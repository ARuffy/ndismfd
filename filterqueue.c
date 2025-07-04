#include "precomp.h"

VOID InitializeRingBuffer(
    _Inout_ PFILTER_RING_BUFFER RingBuffer
)
{
    NdisZeroMemory(RingBuffer, sizeof(FILTER_RING_BUFFER));
    RingBuffer->Head = RingBuffer->Current = RingBuffer->Buffer;
    for (ULONG i = 1; i <= FILTER_RING_BUFFER_SIZE; i++)
    {
        RingBuffer->Buffer[i - 1].Next = i < FILTER_RING_BUFFER_SIZE ? &RingBuffer->Buffer[i] : &RingBuffer->Buffer[0];
    }
}

VOID FreeRingBuffer(
    _Inout_ PFILTER_RING_BUFFER RingBuffer
)
{
    for (ULONG i = 0; i < FILTER_RING_BUFFER_SIZE; i++)
    {
        if (RingBuffer->Buffer[i].ServiceItems)
            FILTER_FREE_MEM(RingBuffer->Buffer[i].ServiceItems);
    }
}

VOID PushToRingBuffer(
    _Inout_ PFILTER_RING_BUFFER RingBuffer,
    _In_ PFILTER_SERVICE_ENTRY ServiceEntry
)
{
    if (RingBuffer->Current->ServiceItems)
    {
        FILTER_FREE_MEM(RingBuffer->Current->ServiceItems);
    }

    RingBuffer->Current->NetBufferListId = ServiceEntry->NetBufferListId;
    RingBuffer->Current->NumberOfServiceItems = ServiceEntry->NumberOfServiceItems;
    RingBuffer->Current->ServiceItems = ServiceEntry->ServiceItems;

    RingBuffer->Current = RingBuffer->Current->Next;
    if (RingBuffer->Head == RingBuffer->Current)
        RingBuffer->Head = RingBuffer->Head->Next;
}