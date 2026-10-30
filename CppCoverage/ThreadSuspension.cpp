// OpenCppCoverage is an open source code coverage for C++.
// Copyright (C) 2026 Jon Wiswall
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "ThreadSuspension.hpp"
#include <TlHelp32.h>
#include <wil/result.h>

namespace CppCoverage
{
	void ThreadSuspension::Hold(HANDLE handle)
	{
		const DWORD id = GetThreadId(handle);
		THROW_LAST_ERROR_IF(!id);
		THROW_HR_IF(E_INVALIDARG, id == GetCurrentThreadId());
		FILETIME created{}, exited{}, kernel{}, user{};
		THROW_LAST_ERROR_IF(!GetThreadTimes(handle, &created, &exited, &kernel, &user));
		auto found = threads_.find(id);
		if (found != threads_.end() &&
		    CompareFileTime(&found->second.created, &created) != 0)
		{
			THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
			    WaitForSingleObject(found->second.handle.get(), 0) != WAIT_OBJECT_0);
			threads_.erase(found);
		}
		auto& thread = threads_[id];
		if (!thread.handle)
		{
			THROW_LAST_ERROR_IF(!DuplicateHandle(GetCurrentProcess(), handle,
			    GetCurrentProcess(), thread.handle.put(), 0, FALSE, DUPLICATE_SAME_ACCESS));
			thread.created = created;
		}
		if (!thread.ownedIncrement && WaitForSingleObject(thread.handle.get(), 0) != WAIT_OBJECT_0)
		{
			using NativeSuspend = LONG(NTAPI*)(HANDLE, PULONG);
			static const auto suspend = reinterpret_cast<NativeSuspend>(
			    GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendThread"));
			THROW_HR_IF_MSG(E_NOTIMPL, !suspend, "NtSuspendThread is unavailable");
			ULONG previous = 0;
			const auto status = suspend(thread.handle.get(), &previous);
			// A terminating thread can await its EXIT_THREAD debug event before its handle is signaled.
			constexpr LONG StatusThreadIsTerminating = static_cast<LONG>(0xc000004b);
			if (status == StatusThreadIsTerminating)
				return;
			if (status < 0)
			{
				using StatusError = ULONG(NTAPI*)(LONG);
				static const auto error = reinterpret_cast<StatusError>(
				    GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError"));
				THROW_HR_IF_MSG(E_NOTIMPL, !error, "RtlNtStatusToDosError is unavailable");
				THROW_WIN32_MSG(error(status), "NtSuspendThread failed (NTSTATUS 0x%08lx)", status);
			}
			thread.ownedIncrement = true;
		}
		Fence(thread);
	}

	void ThreadSuspension::Fence()
	{
		for (auto& pair : threads_)
			Fence(pair.second);
	}

	void ThreadSuspension::Fence(Thread& thread)
	{
		if (!thread.ownedIncrement)
			return;
		if (WaitForSingleObject(thread.handle.get(), 0) == WAIT_OBJECT_0)
		{
			thread.ownedIncrement = false;
			return;
		}
		CONTEXT context{};
		context.ContextFlags = CONTEXT_FULL;
		THROW_LAST_ERROR_IF_MSG(!GetThreadContext(thread.handle.get(), &context),
		    "Synchronously fencing an owned thread suspension");
	}

	void ThreadSuspension::HoldProcess(DWORD process)
	{
		bool fencedSnapshot = false;
		for (;;)
		{
			bool foundNew = false;
			wil::unique_handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)};
			THROW_LAST_ERROR_IF(snapshot.get() == INVALID_HANDLE_VALUE);
			THREADENTRY32 entry{};
			entry.dwSize = sizeof(entry);
			THROW_LAST_ERROR_IF(!Thread32First(snapshot.get(), &entry));
			do
			{
				if (entry.th32OwnerProcessID != process)
					continue;
				const bool known = Contains(entry.th32ThreadID);
				wil::unique_handle thread{OpenThread(
				    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | SYNCHRONIZE,
				    FALSE, entry.th32ThreadID)};
				if (!thread && GetLastError() == ERROR_INVALID_PARAMETER)
					continue;
				THROW_LAST_ERROR_IF(!thread);
				THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
				    GetProcessIdOfThread(thread.get()) != process);
				Hold(thread.get());
				foundNew |= !known;
			} while (Thread32Next(snapshot.get(), &entry));
			THROW_WIN32_IF(GetLastError(), GetLastError() != ERROR_NO_MORE_FILES);
			Fence();
			if (fencedSnapshot && !foundNew)
				return;
			fencedSnapshot = true;
		}
	}

	void ThreadSuspension::Resume()
	{
		for (auto& pair : threads_)
		{
			auto& thread = pair.second;
			if (!thread.ownedIncrement)
				continue;
			if (WaitForSingleObject(thread.handle.get(), 0) == WAIT_OBJECT_0)
			{
				thread.ownedIncrement = false;
				continue;
			}
			const DWORD previous = ResumeThread(thread.handle.get());
			THROW_LAST_ERROR_IF(previous == static_cast<DWORD>(-1));
			thread.ownedIncrement = false;
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !previous,
			    "Another actor removed the collector's thread suspension");
		}
	}

	bool ThreadSuspension::Contains(DWORD id) const
	{
		const auto found = threads_.find(id);
		return found != threads_.end() &&
		    WaitForSingleObject(found->second.handle.get(), 0) == WAIT_TIMEOUT;
	}
}
