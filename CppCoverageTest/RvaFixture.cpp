#include <windows.h>
#include <intrin.h>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

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

namespace
{
	volatile LONG applicationBreaks = 0;
	volatile LONG applicationExceptions = 0;

	LONG CALLBACK ApplicationException(EXCEPTION_POINTERS* info)
	{
		const auto code = info->ExceptionRecord->ExceptionCode;
		if (code == 0xe0424343)
		{
			InterlockedIncrement(&applicationExceptions);
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		if (code != EXCEPTION_BREAKPOINT && code != 0x4000001f)
			return EXCEPTION_CONTINUE_SEARCH;
#if defined(_M_ARM64) && !defined(_M_ARM64EC)
		auto& pc = info->ContextRecord->Pc;
#else
		auto& pc = info->ContextRecord->Rip;
#endif
		const auto address = reinterpret_cast<uintptr_t>(info->ExceptionRecord->ExceptionAddress);
		if (pc == address)
		{
			uint32_t instruction = 0;
			std::memcpy(&instruction, reinterpret_cast<void*>(address), sizeof(instruction));
			if ((address & 3) == 0 && (instruction & 0xffe0001f) == 0xd4200000)
				pc += 4;
			else if (*reinterpret_cast<const uint8_t*>(address) == 0xcc)
				++pc;
			else
				return EXCEPTION_CONTINUE_SEARCH;
		}
		InterlockedIncrement(&applicationBreaks);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	struct ImageState
	{
		uint8_t* bytes = nullptr;
		uint32_t size = 0;
		std::vector<DWORD> protections;
		ImageState() = default;
		ImageState(const ImageState&) = delete;
		ImageState(ImageState&& other) noexcept { *this = std::move(other); }
		ImageState& operator=(ImageState&& other) noexcept
		{
			if (bytes)
				VirtualFree(bytes, 0, MEM_RELEASE);
			bytes = other.bytes;
			size = other.size;
			other.bytes = nullptr;
			protections = std::move(other.protections);
			return *this;
		}
		~ImageState()
		{
			if (bytes)
				VirtualFree(bytes, 0, MEM_RELEASE);
		}
		bool operator==(const ImageState& other) const
		{
			return size == other.size && protections == other.protections &&
			    std::memcmp(bytes, other.bytes, size) == 0;
		}
	};

	ImageState Snapshot(HMODULE module)
	{
		ImageState result;
		const auto base = reinterpret_cast<const uint8_t*>(module);
		const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
		const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
		const auto sections = IMAGE_FIRST_SECTION(nt);
		result.size = nt->OptionalHeader.SizeOfImage;
		result.bytes = static_cast<uint8_t*>(VirtualAlloc(
		    nullptr, result.size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
		if (!result.bytes)
			ExitProcess(104);
		for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
		{
			const auto& section = sections[i];
			if (!(section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
				continue;
			const auto code = base + section.VirtualAddress;
			std::memcpy(result.bytes + section.VirtualAddress, code, section.Misc.VirtualSize);
			for (DWORD offset = 0; offset < section.Misc.VirtualSize; offset += 4096)
			{
				MEMORY_BASIC_INFORMATION memory{};
				if (!VirtualQuery(code + offset, &memory, sizeof(memory)))
					ExitProcess(81);
				result.protections.push_back(memory.Protect);
			}
		}
		return result;
	}

	struct WorkerState
	{
		HANDLE work;
		HANDLE stop;
		HANDLE hit;
		bool requireLibrary;
		std::atomic<int(*)()> shared{nullptr};
	};

	DWORD WINAPI Worker(void* parameter)
	{
		auto& state = *static_cast<WorkerState*>(parameter);
		HANDLE waits[]{state.stop, state.work};
		if (WaitForMultipleObjects(2, waits, FALSE, 120000) != WAIT_OBJECT_0 + 1)
			return 0;
		size_t iteration = 0;
		while (WaitForSingleObject(state.stop, 0) == WAIT_TIMEOUT)
		{
			if (ObservedPath() != 17 || ExceptionPath(1) != 1)
				ExitProcess(82);
#ifdef _M_ARM64EC
			if (EmulatedPath() != 31)
				ExitProcess(83);
#endif
			const auto shared = state.shared.load();
			if (shared)
				if (shared() < 17001)
					ExitProcess(84);
			if (shared || !state.requireLibrary)
				SetEvent(state.hit);
			if (!(iteration++ % 128))
			{
				__debugbreak();
				RaiseException(0xe0424343, 0, 0, nullptr);
			}
			if (!(iteration % 32))
			{
				const auto transient = CreateThread(nullptr, 0, [](void*) -> DWORD {
					return ObservedPath() == 17 ? 0 : 1;
				}, nullptr, 0, nullptr);
				if (!transient || WaitForSingleObject(transient, INFINITE) != WAIT_OBJECT_0)
					ExitProcess(102);
				DWORD code = 1;
				GetExitCodeThread(transient, &code);
				CloseHandle(transient);
				if (code)
					ExitProcess(103);
			}
			Sleep(1);
		}
		return 0;
	}

	int ExternalWork(int argc, char** argv)
	{
		if (argc < 3)
			return 85;
		const std::string prefix{argv[2]};
		auto event = [&](const char* suffix) {
			const auto handle = CreateEventA(nullptr, TRUE, FALSE, (prefix + suffix).c_str());
			if (!handle)
				ExitProcess(86);
			return handle;
		};
		HANDLE ready = event("-ready"), work = event("-work"), stop = event("-stop");
		HANDLE load = event("-load"), post = event("-post"), checked = event("-checked");
		HANDLE hit = event("-hit");
		HANDLE locked = event("-locked"), release = event("-release"), unlocked = event("-unlocked");
		WorkerState state{work, stop, hit, argc > 3};
		HMODULE library = nullptr;
		ImageState libraryBefore;
		const bool delayed = argc > 5 && std::strcmp(argv[5], "delayed") == 0;
		auto loadLibrary = [&] {
			library = LoadLibraryA(argv[3]);
			if (!library)
				ExitProcess(87);
			const auto name = argc > 4 && std::strcmp(argv[4], "excluded") == 0
			    ? "?RvaChainExcludedPath@TestCoverageSharedLib@@YAHXZ"
			    : argc > 4 && std::strcmp(argv[4], "b") == 0
			        ? "?RvaChainChildBPath@TestCoverageSharedLib@@YAHXZ"
			        : "?RvaChainChildAPath@TestCoverageSharedLib@@YAHXZ";
			const auto function = reinterpret_cast<int(*)()>(GetProcAddress(library, name));
			if (!function)
				ExitProcess(88);
			state.shared.store(function);
		};
		if (argc > 3 && !delayed)
		{
			loadLibrary();
			libraryBefore = Snapshot(library);
		}
#ifdef _M_ARM64EC
		if (EmulatedPath() != 31)
			return 83;
#endif
		const auto before = Snapshot(GetModuleHandleW(nullptr));
		const auto exceptionHandler = AddVectoredExceptionHandler(1, &ApplicationException);
		if (!exceptionHandler)
			return 89;
		HANDLE threads[3]{};
		for (auto& thread : threads)
		{
			thread = CreateThread(nullptr, 0, &Worker, &state, 0, nullptr);
			if (!thread)
				ExitProcess(90);
		}
		HANDLE loaderThread = nullptr;
		if (argc > 6 && std::strcmp(argv[6], "hold-loader-lock") == 0)
		{
			using Configure = void(*)(HANDLE, HANDLE);
			const auto configure = reinterpret_cast<Configure>(GetProcAddress(library, "RvaHoldThreadAttach"));
			if (!configure)
				ExitProcess(105);
			configure(locked, release);
			loaderThread = CreateThread(nullptr, 0, [](void* acknowledgment) -> DWORD {
				SetEvent(static_cast<HANDLE>(acknowledgment));
				return 0;
			}, unlocked, 0, nullptr);
			if (!loaderThread)
				ExitProcess(106);
		}
		SetEvent(ready);
		const auto deadline = GetTickCount64() + 120000;
		HANDLE waits[]{stop, post, load};
		while (GetTickCount64() < deadline)
		{
			const auto wait = WaitForMultipleObjects(library ? 2 : 3, waits, FALSE, 100);
			if (wait == WAIT_OBJECT_0)
				break;
			if (wait == WAIT_OBJECT_0 + 2 && !library && argc > 3)
				loadLibrary();
			if (wait == WAIT_OBJECT_0 + 1)
			{
				if (!(before == Snapshot(GetModuleHandleW(nullptr))) ||
				    (library && !delayed && !(libraryBefore == Snapshot(library))) ||
				    UnobservedPath() != 29 || !applicationBreaks || !applicationExceptions)
					ExitProcess(91);
				if (library)
				{
					const auto untouched = reinterpret_cast<int(*)()>(GetProcAddress(
					    library, "?RvaChainExcludedPath@TestCoverageSharedLib@@YAHXZ"));
					if (!untouched || untouched() != 17006)
						ExitProcess(92);
				}
				ResetEvent(post);
				SetEvent(checked);
			}
		}
		SetEvent(stop);
		if (WaitForMultipleObjects(3, threads, TRUE, 10000) != WAIT_OBJECT_0)
			return 93;
		for (const auto thread : threads)
			CloseHandle(thread);
		if (loaderThread)
		{
			if (WaitForSingleObject(loaderThread, 10000) != WAIT_OBJECT_0)
				return 107;
			CloseHandle(loaderThread);
		}
		RemoveVectoredExceptionHandler(exceptionHandler);
		if (library)
			FreeLibrary(library);
		for (const auto handle : {ready, work, stop, load, post, checked, hit, locked, release, unlocked})
			CloseHandle(handle);
		return 0;
	}
}

int main(int argc, char** argv)
{
	if (argc > 6 && std::strcmp(argv[1], "--external-console") == 0)
	{
		SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
		HANDLE output = CreateFileA(argv[3], GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		    &security, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		HANDLE error = CreateFileA(argv[4], GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		    &security, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		HANDLE input = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		    &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		HANDLE cancel = OpenEventA(SYNCHRONIZE, FALSE, argv[2]);
		if (output == INVALID_HANDLE_VALUE || error == INVALID_HANDLE_VALUE ||
		    input == INVALID_HANDLE_VALUE || !cancel)
			return 97;
		std::string command;
		for (int i = 5; i < argc; ++i)
		{
			if (std::strchr(argv[i], '"'))
				return 94;
			command += "\"" + std::string{argv[i]} + "\" ";
		}
		STARTUPINFOA startup{};
		startup.cb = sizeof(startup);
		startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
		startup.wShowWindow = SW_HIDE;
		startup.hStdInput = input;
		startup.hStdOutput = output;
		startup.hStdError = error;
		PROCESS_INFORMATION process{};
		if (!CreateProcessA(argv[5], &command[0], nullptr, nullptr, TRUE,
		    CREATE_NEW_CONSOLE, nullptr, nullptr, &startup, &process))
			return 98;
		CloseHandle(process.hThread);
		HANDLE waits[]{process.hProcess, cancel};
		if (WaitForMultipleObjects(2, waits, FALSE, 60000) == WAIT_OBJECT_0 + 1)
		{
			FreeConsole();
			if (!AttachConsole(process.dwProcessId) ||
			    !SetConsoleCtrlHandler(nullptr, TRUE) ||
			    !GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0))
				return 99;
		}
		if (WaitForSingleObject(process.hProcess, 60000) != WAIT_OBJECT_0)
			return 100;
		DWORD code = 101;
		GetExitCodeProcess(process.hProcess, &code);
		for (const auto handle : {process.hProcess, output, error, input, cancel})
			CloseHandle(handle);
		return static_cast<int>(code);
	}
	if (argc > 2 && std::strcmp(argv[1], "--external-spawn") == 0)
	{
		std::string command;
		for (int i = 2; i < argc; ++i)
		{
			if (std::strchr(argv[i], '"'))
				return 94;
			command += "\"" + std::string{argv[i]} + "\" ";
		}
		STARTUPINFOA startup{};
		startup.cb = sizeof(startup);
		PROCESS_INFORMATION process{};
		if (!CreateProcessA(argv[2], &command[0], nullptr, nullptr, TRUE, 0,
		    nullptr, nullptr, &startup, &process))
			return 95;
		CloseHandle(process.hThread);
		WaitForSingleObject(process.hProcess, 130000);
		DWORD code = 96;
		GetExitCodeProcess(process.hProcess, &code);
		CloseHandle(process.hProcess);
		return static_cast<int>(code);
	}
	if (argc > 1 && std::strcmp(argv[1], "--external-work") == 0)
		return ExternalWork(argc, argv);
#ifdef _M_ARM64EC
	if (EmulatedPath() != 31)
		return 1;
#endif
	if (GetCurrentProcessId() == 0)
		return UnobservedPath();
	return ObservedPath() == 17 && ExceptionPath(1) == 1 ? 0 : 1;
}
