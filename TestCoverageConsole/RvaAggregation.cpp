#include "TestBasic.hpp"

#include <Windows.h>
#include <wil/resource.h>
#include <wil/result.h>

#include <cstdint>
#include <array>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

extern "C" __declspec(dllexport) __declspec(noinline) int RvaSharedPath()
{
	return 123;
}

extern "C" __declspec(dllexport) __declspec(noinline) int RvaChildOnlyPath()
{
	return 456;
}

namespace
{
	__declspec(noinline) uint64_t FreshSink(uint64_t value)
	{
		return value ^ 0x5a5a;
	}

	template<size_t Index>
	__declspec(noinline) uint64_t FreshPath(uint64_t seed)
	{
		volatile uint64_t value = seed + Index;
		return FreshSink(value);
	}

	template<size_t... Indices>
	constexpr auto FreshPaths(std::index_sequence<Indices...>)
	{
		return std::array<uint64_t (*)(uint64_t), sizeof...(Indices)>{{&FreshPath<Indices>...}};
	}

	constexpr auto freshPaths = FreshPaths(std::make_index_sequence<1024>{});

	wil::unique_handle Event(
	    const std::wstring& prefix, const wchar_t* suffix, bool create)
	{
		const auto name = prefix + suffix;
		wil::unique_handle event{create
		    ? CreateEventW(nullptr, TRUE, FALSE, name.c_str())
		    : OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, name.c_str())};
		THROW_LAST_ERROR_IF(!event);
		return event;
	}

	void Wait(HANDLE handle)
	{
		const auto result = WaitForSingleObject(handle, 60000);
		THROW_LAST_ERROR_IF(result == WAIT_FAILED);
		THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_TIMEOUT), result != WAIT_OBJECT_0);
	}

	bool SharedPathHasTrap()
	{
		const auto address = GetProcAddress(GetModuleHandleW(nullptr), "RvaSharedPath");
		THROW_LAST_ERROR_IF(!address);
#if defined(_M_ARM64)
		return *reinterpret_cast<const volatile uint32_t*>(address) == 0xd43e0000;
#else
		return *reinterpret_cast<const volatile uint8_t*>(address) == 0xcc;
#endif
	}

	void FreshCode()
	{
		std::array<double, 2> seconds{};
		uint64_t expected = 0;
		for (size_t repeat = 0; repeat < 16; ++repeat)
			for (size_t index = 0; index < freshPaths.size(); ++index)
				expected += (repeat + index) ^ 0x5a5a;
		for (auto& elapsed : seconds)
		{
			wil::unique_handle start{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
			THROW_LAST_ERROR_IF(!start);
			wil::unique_handle ready{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
			THROW_LAST_ERROR_IF(!ready);
			std::array<uint64_t, 4> sums{};
			std::atomic<size_t> waiting{0};
			std::atomic<bool> failed{false};
			std::vector<std::thread> threads;
			auto join = wil::scope_exit([&]
			{
				SetEvent(start.get());
				for (auto& thread : threads)
					if (thread.joinable())
						thread.join();
			});
			for (size_t worker = 0; worker < sums.size(); ++worker)
				threads.emplace_back([&, worker]
				{
					if (++waiting == sums.size() && !SetEvent(ready.get()))
						failed = true;
					if (WaitForSingleObject(start.get(), 60000) != WAIT_OBJECT_0)
					{
						failed = true;
						return;
					}
					uint64_t sum = 0;
					for (uint64_t repeat = 0; repeat < 16; ++repeat)
						for (const auto path : freshPaths)
							sum += path(repeat);
					sums[worker] = sum;
				});
			Wait(ready.get());
			const auto began = std::chrono::steady_clock::now();
			THROW_IF_WIN32_BOOL_FALSE(SetEvent(start.get()));
			for (auto& thread : threads)
				thread.join();
			elapsed = std::chrono::duration<double>(
			    std::chrono::steady_clock::now() - began).count();
			THROW_HR_IF(E_UNEXPECTED, failed);
			for (const auto sum : sums)
				THROW_HR_IF_MSG(E_UNEXPECTED, sum != expected,
				    "Fresh-code checksum mismatch");
		}
		const auto base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
		std::cout << std::setprecision(9) << "{\"freshSeconds\":" << seconds[0]
		          << ",\"warmSeconds\":" << seconds[1] << ",\"workers\":4,\"rvas\":[";
		for (size_t index = 0; index < freshPaths.size(); ++index)
		{
			if (index)
				std::cout << ',';
			std::cout << reinterpret_cast<uintptr_t>(freshPaths[index]) - base;
		}
		std::cout << "]}" << std::endl;
	}
}

namespace TestCoverageConsole
{
	void RunRvaAggregation(int argc, _TCHAR* argv[])
	{
		THROW_HR_IF(E_INVALIDARG, argc < 4);
		const std::wstring mode{argv[3]};
		if (mode == L"fresh")
		{
			THROW_HR_IF(E_INVALIDARG, argc != 4);
			FreshCode();
			return;
		}
		if (mode == L"child")
		{
			THROW_HR_IF(E_INVALIDARG, argc != 6);
			const bool beforeLoad = std::wstring{argv[5]} == L"before-load";
			auto ready = Event(argv[4], L"-ready", false);
			auto go = Event(argv[4], L"-go", false);
			THROW_HR_IF_MSG(E_UNEXPECTED, SharedPathHasTrap() == beforeLoad,
			    "Unexpected initial shared-path instrumentation");
			THROW_IF_WIN32_BOOL_FALSE(SetEvent(ready.get()));
			Wait(go.get());
			OutputDebugStringW(L"RVA aggregation child checkpoint");
			THROW_HR_IF_MSG(E_UNEXPECTED, SharedPathHasTrap(),
			    "Child retained a breakpoint already hit by its parent");
			THROW_HR_IF(E_UNEXPECTED, RvaSharedPath() != 123);
			THROW_HR_IF(E_UNEXPECTED, RvaChildOnlyPath() != 456);
			return;
		}

		THROW_HR_IF(E_INVALIDARG,
		    argc != 4 || (mode != L"before-load" && mode != L"resident"));
		const auto prefix = L"Local\\OpenCppCoverage-Rva-" +
		    std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
		auto ready = Event(prefix, L"-ready", true);
		auto go = Event(prefix, L"-go", true);
		if (mode == L"before-load")
			THROW_HR_IF(E_UNEXPECTED, RvaSharedPath() != 123);

		std::wstring executable(32768, L'\0');
		const auto size = GetModuleFileNameW(
		    nullptr, executable.data(), static_cast<DWORD>(executable.size()));
		THROW_LAST_ERROR_IF(!size);
		THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER), size >= executable.size());
		executable.resize(size);
		auto command = L"\"" + executable + L"\" ChildProcess --rva-aggregate child " +
		    prefix + L" " + mode;
		STARTUPINFOW startup{sizeof(startup)};
		wil::unique_process_information child;
		THROW_IF_WIN32_BOOL_FALSE(CreateProcessW(
		    executable.c_str(), command.data(), nullptr, nullptr, FALSE, 0,
		    nullptr, nullptr, &startup, &child));
		auto terminate = wil::scope_exit([&]
		{
			if (WaitForSingleObject(child.hProcess, 0) == WAIT_TIMEOUT)
			{
				TerminateProcess(child.hProcess, ERROR_PROCESS_ABORTED);
				WaitForSingleObject(child.hProcess, 60000);
			}
		});
		HANDLE started[]{ready.get(), child.hProcess};
		const auto result = WaitForMultipleObjects(2, started, FALSE, 60000);
		THROW_LAST_ERROR_IF(result == WAIT_FAILED);
		THROW_HR_IF_MSG(E_UNEXPECTED, result != WAIT_OBJECT_0,
		    "Child exited or timed out before its ready checkpoint");
		if (mode == L"resident")
			THROW_HR_IF(E_UNEXPECTED, RvaSharedPath() != 123);
		THROW_IF_WIN32_BOOL_FALSE(SetEvent(go.get()));
		Wait(child.hProcess);
		DWORD code = 0;
		THROW_IF_WIN32_BOOL_FALSE(GetExitCodeProcess(child.hProcess, &code));
		THROW_HR_IF_MSG(E_UNEXPECTED, code != 0, "RVA aggregation child exited with %lu", code);
	}
}
