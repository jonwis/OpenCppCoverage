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

#include "stdafx.h"
#include "Debugger.hpp"

#include "tools/Log.hpp"

#include "Process.hpp"
#include "CppCoverageException.hpp"
#include "IDebugEventsHandler.hpp"

#include "Tools/Tool.hpp"

namespace CppCoverage
{
	//-------------------------------------------------------------------------
	namespace
	{
		void OnRip(const RIP_INFO& ripInfo)
		{
			LOG_ERROR << "Debugee process terminate unexpectedly:"
				<< "(type:" << ripInfo.dwType << ")"
				<< GetErrorMessage(ripInfo.dwError);
		}

		wil::unique_handle DuplicateDebugHandle(HANDLE handle)
		{
			wil::unique_handle copy;
			THROW_IF_WIN32_BOOL_FALSE(DuplicateHandle(
				GetCurrentProcess(), handle, GetCurrentProcess(),
				copy.put(), 0, FALSE, DUPLICATE_SAME_ACCESS));
			return copy;
		}
	}	

	//-------------------------------------------------------------------------
	struct Debugger::ProcessStatus
	{
		ProcessStatus() = default;

		ProcessStatus(
			boost::optional<int> exitCode,
			boost::optional<DWORD> continueStatus)
			: exitCode_{ exitCode }
			, continueStatus_{ continueStatus }
		{
		}

		boost::optional<int> exitCode_;
		boost::optional<DWORD> continueStatus_;
	};

	//-------------------------------------------------------------------------
	Debugger::Debugger(
		bool coverChildren,
		bool continueAfterCppException,
        bool stopOnAssert)
		: coverChildren_{ coverChildren }
		, continueAfterCppException_{ continueAfterCppException }
        , stopOnAssert_{ stopOnAssert }
	{
	}

	//-------------------------------------------------------------------------
	int Debugger::Debug(
		const StartInfo& startInfo,
		IDebugEventsHandler& debugEventsHandler)
	{
		Process process(startInfo);
		process.Start((coverChildren_) ? DEBUG_PROCESS: DEBUG_ONLY_THIS_PROCESS);
		
		DEBUG_EVENT debugEvent;
		boost::optional<int> exitCode;

		processHandles_.clear();
		threadHandles_.clear();
		completedProcessIds_.clear();
		rootProcessId_ = boost::none;

		while (!exitCode || !processHandles_.empty())
		{
			if (!WaitForDebugEvent(&debugEvent, 1000))
			{
				const auto error = GetLastError();
				THROW_WIN32_IF(error, error != ERROR_SEM_TIMEOUT);
				const auto completed = ReapExitedProcesses(debugEventsHandler);
				if (completed && !exitCode)
					exitCode = completed;
				continue;
			}

			ProcessStatus processStatus = HandleDebugEvent(debugEvent, debugEventsHandler);
			
			// Get the exit code of the root process
			// Set once as we do not want EXCEPTION_BREAKPOINT to be override
			if (processStatus.exitCode_ && rootProcessId_ == debugEvent.dwProcessId && !exitCode)
				exitCode = processStatus.exitCode_;

			auto continueStatus = boost::get_optional_value_or(processStatus.continueStatus_, DBG_CONTINUE);

			THROW_IF_WIN32_BOOL_FALSE(ContinueDebugEvent(
				debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus));
		}

		return *exitCode;
	}

	boost::optional<int> Debugger::ReapExitedProcesses(IDebugEventsHandler& handler)
	{
		boost::optional<int> rootExitCode;
		for (auto process = processHandles_.begin(); process != processHandles_.end();)
		{
			const auto wait = WaitForSingleObject(process->second.get(), 0);
			THROW_LAST_ERROR_IF(wait == WAIT_FAILED);
			if (wait != WAIT_OBJECT_0)
			{
				++process;
				continue;
			}
			DWORD code = 0;
			THROW_IF_WIN32_BOOL_FALSE(GetExitCodeProcess(process->second.get(), &code));
			const auto id = process->first;
			HANDLE lastThread = nullptr;
			for (const auto& thread : threadHandles_)
				if (GetProcessIdOfThread(thread.second.get()) == id)
					lastThread = thread.second.get();
			EXIT_PROCESS_DEBUG_INFO info{code};
			LOG_WARNING << "Process " << id << " exited without an exit debug event.";
			handler.OnExitProcess(process->second.get(), lastThread, info);
			if (rootProcessId_ == id)
				rootExitCode = static_cast<int>(code);
			DebugActiveProcessStop(id);
			RemoveProcessThreads(id);
			completedProcessIds_.insert(id);
			process = processHandles_.erase(process);
		}
		return rootExitCode;
	}
	
	//-------------------------------------------------------------------------
	Debugger::ProcessStatus Debugger::HandleDebugEvent(
		const DEBUG_EVENT& debugEvent,
		IDebugEventsHandler& debugEventsHandler)
	{
		auto dwProcessId = debugEvent.dwProcessId;
		auto dwThreadId = debugEvent.dwThreadId;

		if (debugEvent.dwDebugEventCode != CREATE_PROCESS_DEBUG_EVENT &&
		    completedProcessIds_.count(dwProcessId))
		{
			if (debugEvent.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
			{
				wil::unique_handle file{debugEvent.u.LoadDll.hFile};
			}
			return {};
		}

		switch (debugEvent.dwDebugEventCode)
		{
			case CREATE_PROCESS_DEBUG_EVENT: OnCreateProcess(debugEvent, debugEventsHandler); break;
			case CREATE_THREAD_DEBUG_EVENT: OnCreateThread(debugEvent.u.CreateThread.hThread, dwThreadId); break;
			default:
			{
				auto hProcess = GetProcessHandle(dwProcessId);
				auto hThread = GetThreadHandle(dwThreadId);
				return HandleNotCreationalEvent(debugEvent, debugEventsHandler, hProcess, hThread, dwThreadId);
			}
		}

		return{};
	}

	//-------------------------------------------------------------------------
	Debugger::ProcessStatus
		Debugger::HandleNotCreationalEvent(
		const DEBUG_EVENT& debugEvent,
		IDebugEventsHandler& debugEventsHandler,
		HANDLE hProcess,
		HANDLE hThread,
		DWORD dwThreadId)
	{
		switch (debugEvent.dwDebugEventCode)
		{
			case EXIT_PROCESS_DEBUG_EVENT:
			{
				auto exitCode = OnExitProcess(debugEvent, hProcess, hThread, debugEventsHandler);
				return ProcessStatus{exitCode, boost::none};
			}
			case EXIT_THREAD_DEBUG_EVENT: OnExitThread(dwThreadId); break;
			case LOAD_DLL_DEBUG_EVENT:
			{
				const auto& loadDll = debugEvent.u.LoadDll;
				wil::unique_handle file{loadDll.hFile};
				debugEventsHandler.OnLoadDll(hProcess, hThread, loadDll);
				break;
			}
			case UNLOAD_DLL_DEBUG_EVENT:
			{
				debugEventsHandler.OnUnloadDll(hProcess, hThread, debugEvent.u.UnloadDll);
				break;
			}
			case EXCEPTION_DEBUG_EVENT: return OnException(debugEvent, debugEventsHandler, hProcess, hThread);
			case RIP_EVENT: OnRip(debugEvent.u.RipInfo); break;
			default: LOG_DEBUG << "Debug event:" << debugEvent.dwDebugEventCode; break;
		}

		return ProcessStatus{};
	}
	
	//-------------------------------------------------------------------------
	Debugger::ProcessStatus
		Debugger::OnException(
		const DEBUG_EVENT& debugEvent,
		IDebugEventsHandler& debugEventsHandler,
		HANDLE hProcess,
		HANDLE hThread) const
	{
		const auto& exception = debugEvent.u.Exception;
		auto exceptionType = debugEventsHandler.OnException(hProcess, hThread, exception);

		switch (exceptionType)
		{
			case IDebugEventsHandler::ExceptionType::BreakPoint:
			{
				return ProcessStatus{ boost::none, DBG_CONTINUE };
			}
			case IDebugEventsHandler::ExceptionType::InvalidBreakPoint:
			{
				LOG_WARNING << Tools::GetSeparatorLine();
				LOG_WARNING << "It seems there is an assertion failure or you call DebugBreak() in your program.";
				LOG_WARNING << Tools::GetSeparatorLine();

                if (stopOnAssert_)
                {
                  LOG_WARNING << "Stop on assertion.";
                  return ProcessStatus{ boost::none, DBG_EXCEPTION_NOT_HANDLED };
                }
                else
                {
                  return ProcessStatus(EXCEPTION_BREAKPOINT, DBG_CONTINUE);
                }
			}
			case IDebugEventsHandler::ExceptionType::NotHandled:
			{
				return ProcessStatus{ boost::none, DBG_EXCEPTION_NOT_HANDLED };
			}
			case IDebugEventsHandler::ExceptionType::Error:
			{
				return ProcessStatus{ boost::none, DBG_EXCEPTION_NOT_HANDLED };
			}
			case IDebugEventsHandler::ExceptionType::CppError:
			{
				if (continueAfterCppException_)
				{
					const auto& exceptionRecord = exception.ExceptionRecord;
					LOG_WARNING << "Continue after a C++ exception.";
					return ProcessStatus{ static_cast<int>(exceptionRecord.ExceptionCode), DBG_CONTINUE };
				}
				return ProcessStatus{ boost::none, DBG_EXCEPTION_NOT_HANDLED };
			}
		}
		THROW("Invalid exception Type.");
	}

	//-------------------------------------------------------------------------
	void Debugger::OnCreateProcess(
		const DEBUG_EVENT& debugEvent,
		IDebugEventsHandler& debugEventsHandler)
	{		
		const auto& processInfo = debugEvent.u.CreateProcessInfo;
		wil::unique_handle file{processInfo.hFile};

		LOG_DEBUG << "Create Process:" << debugEvent.dwProcessId;

		if (!rootProcessId_ && processHandles_.empty())
			rootProcessId_ = debugEvent.dwProcessId;

		completedProcessIds_.erase(debugEvent.dwProcessId);
		if (!processHandles_.emplace(debugEvent.dwProcessId, DuplicateDebugHandle(processInfo.hProcess)).second)
			THROW("Process id already exist");

		OnCreateThread(processInfo.hThread, debugEvent.dwThreadId);
		auto retainedInfo = processInfo;
		retainedInfo.hProcess = GetProcessHandle(debugEvent.dwProcessId);
		retainedInfo.hThread = GetThreadHandle(debugEvent.dwThreadId);
		debugEventsHandler.OnCreateProcess(retainedInfo);
	}

	//-------------------------------------------------------------------------
	int Debugger::OnExitProcess(
		const DEBUG_EVENT& debugEvent,
		HANDLE hProcess,
		HANDLE hThread,
		IDebugEventsHandler& debugEventsHandler)
	{
		auto processId = debugEvent.dwProcessId;

		LOG_DEBUG << "Exit Process:" << processId;

		auto exitProcess = debugEvent.u.ExitProcess;
		debugEventsHandler.OnExitProcess(hProcess, hThread, exitProcess);
		RemoveProcessThreads(processId);
		completedProcessIds_.insert(processId);

		if (processHandles_.erase(processId) != 1)
			THROW("Cannot find exited process.");

		return exitProcess.dwExitCode;
	}

	//-------------------------------------------------------------------------
	void Debugger::OnCreateThread(
		HANDLE hThread,
		DWORD dwThreadId)
	{
		LOG_DEBUG << "Create Thread:" << dwThreadId;

		if (!threadHandles_.emplace(dwThreadId, DuplicateDebugHandle(hThread)).second)
			THROW("Thread id already exist");
	}
	
	//-------------------------------------------------------------------------
	void Debugger::OnExitThread(DWORD dwThreadId)
	{	
		LOG_DEBUG << "Exit thread:" << dwThreadId;

		if (threadHandles_.erase(dwThreadId) != 1)
			THROW("Cannot find exited thread.");
	}

	void Debugger::RemoveProcessThreads(DWORD processId)
	{
		for (auto thread = threadHandles_.begin(); thread != threadHandles_.end();)
		{
			const auto owner = GetProcessIdOfThread(thread->second.get());
			THROW_LAST_ERROR_IF(!owner);
			if (owner == processId)
				thread = threadHandles_.erase(thread);
			else
				++thread;
		}
	}

	//-------------------------------------------------------------------------
	HANDLE Debugger::GetProcessHandle(DWORD dwProcessId) const
	{
		return processHandles_.at(dwProcessId).get();
	}

	//-------------------------------------------------------------------------
	HANDLE Debugger::GetThreadHandle(DWORD dwThreadId) const
	{
		return threadHandles_.at(dwThreadId).get();
	}

	//-------------------------------------------------------------------------
	size_t Debugger::GetRunningProcesses() const
	{
		return processHandles_.size();
	}

	//-------------------------------------------------------------------------
	size_t Debugger::GetRunningThreads() const
	{
		return threadHandles_.size();
	}
}