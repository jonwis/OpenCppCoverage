// OpenCppCoverage is an open source code coverage for C++.
// Copyright (C) 2014 OpenCppCoverage
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

#pragma once

#include <boost/optional/optional.hpp>

#include <unordered_map>
#include <unordered_set>
#include <Windows.h>
#include <wil/resource.h>
#include "CppCoverageExport.hpp"


namespace CppCoverage
{
	class StartInfo;
	class IDebugEventsHandler;
	class Patterns;

	class CPPCOVERAGE_DLL Debugger
	{
	public:
		Debugger(
			bool coverChildren,
			bool continueAfterCppException,
            bool stopOnAssert);

		int Debug(const StartInfo&, IDebugEventsHandler&);
		int AttachExisting(const Patterns&, unsigned durationSeconds, IDebugEventsHandler&,
		    bool watchProcesses = false);
		static boost::optional<int> RunOwnedHelper(int argc, const char* const* argv);
		static DWORD AttachExceptionDisposition(const EXCEPTION_DEBUG_INFO&,
		    DWORD thread, bool heldOriginalThread, DWORD bootstrapThread, ULONG_PTR bootstrapAddress);
		size_t GetRunningProcesses() const;
		size_t GetRunningThreads() const;

	private:
		Debugger(const Debugger&) = delete;
		Debugger& operator=(const Debugger&) = delete;
	
		void OnCreateProcess(
			const DEBUG_EVENT& debugEvent,
			IDebugEventsHandler& debugEventsHandler);

		int OnExitProcess(
			const DEBUG_EVENT& debugEvent,
			HANDLE hProcess,
			HANDLE hThread,
			IDebugEventsHandler& debugEventsHandler);

		void OnCreateThread(
			HANDLE hThread,
			DWORD dwThreadId);

		void OnExitThread(DWORD dwProcessId);
		void RemoveProcessThreads(DWORD processId);

		HANDLE GetProcessHandle(DWORD dwProcessId) const;
		HANDLE GetThreadHandle(DWORD dwThreadId) const;

		struct ProcessStatus;
		boost::optional<int> ReapExitedProcesses(IDebugEventsHandler&);

		ProcessStatus HandleDebugEvent(const DEBUG_EVENT&, IDebugEventsHandler&);
		DWORD DispatchExternalEvent(const DEBUG_EVENT&, IDebugEventsHandler&);

		ProcessStatus HandleNotCreationalEvent(
			const DEBUG_EVENT& debugEvent,
			IDebugEventsHandler& debugEventsHandler,
			HANDLE hProcess,
			HANDLE hThread,
			DWORD dwThreadId);

		ProcessStatus OnException(const DEBUG_EVENT&, IDebugEventsHandler&, HANDLE hProcess, HANDLE hThread) const;

	private:
		std::unordered_map<DWORD, wil::unique_handle> processHandles_;
		std::unordered_map<DWORD, wil::unique_handle> threadHandles_;
		std::unordered_set<DWORD> completedProcessIds_;
		boost::optional<DWORD> rootProcessId_;
		bool coverChildren_;
		bool external_ = false;
		bool continueAfterCppException_;
        bool stopOnAssert_;
    };
}
