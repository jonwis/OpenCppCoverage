#include <windows.h>

#ifdef _M_ARM64EC
extern "C" int EmulatedPath();
#endif

extern "C" __declspec(dllexport) __declspec(noinline) int ObservedPath()
{
	return 17;
}

extern "C" __declspec(dllexport) __declspec(noinline) int UnobservedPath()
{
	return 29;
}

extern "C" __declspec(dllexport) __declspec(noinline) int ExceptionPath(int input)
{
	try
	{
		if (input)
			throw input;
	}
	catch (int value)
	{
		return value;
	}
	return 0;
}

int main()
{
#ifdef _M_ARM64EC
	if (EmulatedPath() != 31)
		return 1;
#endif
	if (GetCurrentProcessId() == 0)
		return UnobservedPath();
	return ObservedPath() == 17 && ExceptionPath(1) == 1 ? 0 : 1;
}
