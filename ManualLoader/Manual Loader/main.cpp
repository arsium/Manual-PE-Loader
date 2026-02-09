#include "Loader.h"

//Function pointer

int main()
{
	const auto lpModule = MemoryLoader::LoadDLL((LPSTR)"DelayLoad.dll");

	if (lpModule == nullptr)
		return -1;

	/*auto MessageFnc = (MessageFncPtr)MemoryLoader::GetFunctionAddress((LPVOID)lpModule, (const LPSTR)"Message");
	if (MessageFnc == nullptr)
		return -1;

	MessageFnc();

	MessageFnc = (MessageFncPtr)MemoryLoader::GetFunctionAddressByOrdinal((LPVOID)lpModule, 1);
	if (MessageFnc == nullptr)
		return -1;

	MessageFnc();

	MemoryLoader::FreeDLL(lpModule);*/

	system("PAUSE");

	return 0;
}