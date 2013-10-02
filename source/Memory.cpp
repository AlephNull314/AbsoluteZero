#include "MainHeader.h"


HANDLE global_heap=NULL;
bool init_heap=false;


HANDLE Heap_init (void)
{
	HANDLE result_heap=NULL;

	if (init_heap!=true)
	{
		global_heap=HeapCreate(0,HEAP_SIZE,0);
		if (global_heap!=NULL)
		{
			result_heap=global_heap;
			init_heap=true;
		}
	}
	else
		result_heap=global_heap;
	return result_heap;	
}
void Heap_Destroy (void)
{
	if (init_heap!=false)
	{
		HeapDestroy(global_heap);
		global_heap=NULL;
		init_heap=false;
	}
}