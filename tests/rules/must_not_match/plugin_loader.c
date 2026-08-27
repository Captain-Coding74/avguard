#include <windows.h>
HMODULE h = LoadLibraryA("plugin.dll");
FARPROC init = GetProcAddress(h, "init");
