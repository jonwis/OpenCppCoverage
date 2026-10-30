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

#include "Debugger.hpp"
#include "ArchitectureBreakpoint.hpp"
#include "ExistingProcess.hpp"
#include "HandleInformation.hpp"
#include "IDebugEventsHandler.hpp"
#include "PeImage.hpp"
#include "ProcessWatcher.hpp"
#include "ThreadSuspension.hpp"
#include "Tools/Log.hpp"
#include <atomic>
#include <chrono>
#include <cstring>
#include <deque>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <wil/result.h>

namespace CppCoverage
{
	namespace
	{
		bool Exited(HANDLE process)
		{
			DWORD code = STILL_ACTIVE;
			THROW_LAST_ERROR_IF(!GetExitCodeProcess(process, &code));
			return code != STILL_ACTIVE || WaitForSingleObject(process, 0) == WAIT_OBJECT_0;
		}

		std::atomic<bool> stopRequested{false};
		BOOL WINAPI StopCollection(DWORD reason)
		{
			if (reason != CTRL_C_EVENT && reason != CTRL_BREAK_EVENT)
				return FALSE;
			stopRequested.store(true);
			return TRUE;
		}

		std::wstring ExecutablePath()
		{
			std::wstring path(32768, L'\0');
			const DWORD size = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
			THROW_LAST_ERROR_IF(!size);
			THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER), size >= path.size());
			path.resize(size);
			return path;
		}

		struct OwnedHelper
		{
			wil::unique_handle process;
			wil::unique_handle writer;
			wil::unique_handle started;
			DWORD id = 0;
			bool alive = true;
			bool ready = false;

			explicit OwnedHelper(bool debugLaunch = true)
			{
				SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
				started.reset(CreateEventW(&security, TRUE, FALSE, nullptr));
				THROW_LAST_ERROR_IF(!started);
				wil::unique_handle reader;
				THROW_LAST_ERROR_IF(!CreatePipe(reader.put(), writer.put(), &security, 0));
				THROW_LAST_ERROR_IF(!SetHandleInformation(writer.get(), HANDLE_FLAG_INHERIT, 0));
				SIZE_T bytes = 0;
				InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
				THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !bytes);
				std::vector<uint8_t> attributes(bytes);
				auto list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.data());
				THROW_LAST_ERROR_IF(!InitializeProcThreadAttributeList(list, 1, 0, &bytes));
				auto destroy = wil::scope_exit([&] { DeleteProcThreadAttributeList(list); });
				HANDLE inherited[]{reader.get(), started.get()};
				THROW_LAST_ERROR_IF(!UpdateProcThreadAttribute(list, 0,
				    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr));
				STARTUPINFOEXW startup{};
				startup.StartupInfo.cb = sizeof(startup);
				startup.lpAttributeList = list;
				PROCESS_INFORMATION info{};
				const auto path = ExecutablePath();
				auto command = L"\"" + path + L"\" --internal-debug-owner " +
				    std::to_wstring(reinterpret_cast<uintptr_t>(reader.get())) + L" " +
				    std::to_wstring(reinterpret_cast<uintptr_t>(started.get()));
				THROW_LAST_ERROR_IF(!CreateProcessW(path.c_str(), command.data(), nullptr,
				    nullptr, TRUE, (debugLaunch ? DEBUG_ONLY_THIS_PROCESS : 0) | CREATE_NO_WINDOW |
				    EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup.StartupInfo, &info));
				process.reset(info.hProcess);
				wil::unique_handle thread{info.hThread};
				id = info.dwProcessId;
				if (!DebugSetProcessKillOnExit(FALSE))
				{
					const DWORD error = GetLastError();
					TerminateProcess(process.get(), ERROR_PROCESS_ABORTED);
					THROW_WIN32(error);
				}
			}

			DWORD Dispatch(const DEBUG_EVENT& event)
			{
				if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
				{
					wil::unique_handle file{event.u.CreateProcessInfo.hFile};
				}
				if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
				{
					wil::unique_handle file{event.u.LoadDll.hFile};
				}
				if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
					alive = false;
				if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
				{
					const auto& exception = event.u.Exception;
					if (exception.dwFirstChance &&
					    (exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT ||
					     exception.ExceptionRecord.ExceptionCode == 0x4000001f))
					{
						ready = true;
						return DBG_CONTINUE;
					}
					stopRequested.store(true);
					return DBG_EXCEPTION_NOT_HANDLED;
				}
				return DBG_CONTINUE;
			}
		};

		struct AttachBreakpoint
		{
			std::filesystem::path path;
			PeIdentity identity;
			uint64_t offset = 0;
			std::vector<uint8_t> bytes;

			void ObserveOwned(HANDLE process, const EXCEPTION_DEBUG_INFO& exception)
			{
				const auto address = reinterpret_cast<uint64_t>(
				    exception.ExceptionRecord.ExceptionAddress);
				THROW_HR_IF(E_UNEXPECTED, !exception.dwFirstChance ||
				    (exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT &&
				     exception.ExceptionRecord.ExceptionCode != 0x4000001f));
#if defined(_M_ARM64) && !defined(_M_ARM64EC)
				const auto instructionSet = InstructionSet::Arm64;
#elif defined(_M_AMD64)
				const auto instructionSet = InstructionSet::Amd64;
#else
				THROW_HR(E_NOTIMPL);
				const auto instructionSet = InstructionSet::Amd64;
#endif
				bytes.resize(ArchitectureBreakpoint::Encoding(instructionSet).size);
				SIZE_T count = 0;
				THROW_LAST_ERROR_IF(!ReadProcessMemory(process, reinterpret_cast<void*>(address),
				    bytes.data(), bytes.size(), &count));
				THROW_HR_IF(E_UNEXPECTED, count != bytes.size() ||
				    !ArchitectureBreakpoint::IsApplicationTrap(instructionSet, bytes.data(), bytes.size()));
				MEMORY_BASIC_INFORMATION memory{};
				THROW_LAST_ERROR_IF(!VirtualQueryEx(
				    process, reinterpret_cast<void*>(address), &memory, sizeof(memory)));
				THROW_HR_IF(E_UNEXPECTED, memory.Type != MEM_IMAGE);
				path = HandleInformation{}.ComputeMappedFilename(process, memory.AllocationBase);
				identity = PeImage{path}.Identity();
				offset = address - reinterpret_cast<uint64_t>(memory.AllocationBase);
			}

			uint64_t Match(HANDLE process, HANDLE file, void* base) const
			{
				const std::filesystem::path remote{
				    file && file != INVALID_HANDLE_VALUE ? HandleInformation{}.ComputeFilename(file) :
				    HandleInformation{}.ComputeMappedFilename(process, base)};
				if (_wcsicmp(remote.filename().c_str(), path.filename().c_str()) != 0)
					return 0;
				const auto image = PeImage{remote}.Identity();
				if (image.imageHash != identity.imageHash || image.machine != identity.machine)
					return 0;
				const auto address = reinterpret_cast<uint64_t>(base) + offset;
				std::vector<uint8_t> original(bytes.size());
				SIZE_T read = 0;
				THROW_LAST_ERROR_IF(!ReadProcessMemory(process, reinterpret_cast<void*>(address),
				    original.data(), original.size(), &read));
				THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
				    read != original.size() || original != bytes);
				return address;
			}
		};

		AttachBreakpoint CalibrateBootstrap(OwnedHelper& primer)
		{
			auto pumpPrimer = [&] {
				DEBUG_EVENT event{};
				if (WaitForDebugEvent(&event, 50))
				{
					THROW_HR_IF(E_UNEXPECTED, event.dwProcessId != primer.id);
					const auto disposition = primer.Dispatch(event);
					THROW_LAST_ERROR_IF(!ContinueDebugEvent(
					    event.dwProcessId, event.dwThreadId, disposition));
				}
				else
					THROW_WIN32_IF(GetLastError(), GetLastError() != ERROR_SEM_TIMEOUT);
			};
			const auto deadline = GetTickCount64() + 10000;
			while (WaitForSingleObject(primer.started.get(), 0) != WAIT_OBJECT_0)
			{
				THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_TIMEOUT), GetTickCount64() > deadline);
				pumpPrimer();
			}
			OwnedHelper probe{false};
			auto stopOwnedProbe = wil::scope_exit([&] {
				if (probe.alive)
					LOG_IF_WIN32_BOOL_FALSE(TerminateProcess(probe.process.get(), ERROR_PROCESS_ABORTED));
			});
			THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_TIMEOUT),
			    WaitForSingleObject(probe.started.get(), 10000) != WAIT_OBJECT_0);
			ThreadSuspension held;
			held.HoldProcess(probe.id);
			THROW_LAST_ERROR_IF(!DebugSetProcessKillOnExit(FALSE));
			THROW_LAST_ERROR_IF(!DebugActiveProcess(probe.id));
			AttachBreakpoint result;
			bool observed = false;
			const auto probeDeadline = GetTickCount64() + 10000;
			while (probe.alive)
			{
				DEBUG_EVENT event{};
				if (!WaitForDebugEvent(&event, 100))
				{
					THROW_WIN32_IF(GetLastError(), GetLastError() != ERROR_SEM_TIMEOUT);
					THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_TIMEOUT), GetTickCount64() > probeDeadline);
					continue;
				}
				DWORD disposition = DBG_CONTINUE;
				if (event.dwProcessId == primer.id)
					disposition = primer.Dispatch(event);
				else
				{
					THROW_HR_IF(E_UNEXPECTED, event.dwProcessId != probe.id);
					if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && !observed)
					{
						THROW_HR_IF_MSG(E_NOTIMPL, held.Contains(event.dwThreadId),
						    "Owned attach probe did not use an isolated bootstrap thread");
						result.ObserveOwned(probe.process.get(), event.u.Exception);
						observed = true;
						held.Resume();
						probe.writer.reset();
					}
					disposition = probe.Dispatch(event);
				}
				THROW_LAST_ERROR_IF(!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition));
			}
			THROW_HR_IF(E_UNEXPECTED, !observed);
			LOG_INFO << "Owned attach bootstrap probe qualified";
			return result;
		}

		struct Connection
		{
			ExistingProcess candidate;
			ThreadSuspension held;
			bool attached = false;
			bool initialized = false;
			bool verified = false;
			bool ready = false;
			bool restored = false;
			bool detached = false;
			bool exited = false;
			bool settled = false;
			DWORD bootstrapThread = 0;
			uint64_t bootstrapAddress = 0;
		};
	}

	boost::optional<int> Debugger::RunOwnedHelper(int argc, const char* const* argv)
	{
		if (argc != 4 || std::strcmp(argv[1], "--internal-debug-owner") != 0)
			return boost::none;
		wil::unique_handle reader{
		    reinterpret_cast<HANDLE>(static_cast<uintptr_t>(std::stoull(argv[2])))};
		THROW_HR_IF(E_INVALIDARG, GetFileType(reader.get()) != FILE_TYPE_PIPE);
		wil::unique_handle started{
		    reinterpret_cast<HANDLE>(static_cast<uintptr_t>(std::stoull(argv[3])))};
		THROW_LAST_ERROR_IF(!SetEvent(started.get()));
		char value = 0;
		DWORD read = 0;
		if (!ReadFile(reader.get(), &value, 1, &read, nullptr))
			THROW_WIN32_IF(GetLastError(), GetLastError() != ERROR_BROKEN_PIPE);
		return 0;
	}

	DWORD Debugger::AttachExceptionDisposition(const EXCEPTION_DEBUG_INFO& exception,
	    DWORD thread, bool heldOriginalThread, DWORD bootstrapThread, ULONG_PTR bootstrapAddress)
	{
		const auto code = exception.ExceptionRecord.ExceptionCode;
		if ((code != EXCEPTION_BREAKPOINT && code != 0x4000001f) || heldOriginalThread)
			return DBG_EXCEPTION_NOT_HANDLED;
		THROW_HR_IF_MSG(E_PENDING, !exception.dwFirstChance ||
		    thread != bootstrapThread || !bootstrapAddress ||
		    reinterpret_cast<ULONG_PTR>(exception.ExceptionRecord.ExceptionAddress) != bootstrapAddress ||
		    (exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT &&
		     exception.ExceptionRecord.ExceptionCode != 0x4000001f),
		    "Cannot attribute attach bootstrap; retaining ownership: tid=%lu expected_tid=%lu pc=%llx expected_pc=%llx code=%lx",
		    thread, bootstrapThread,
		    static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(
		        exception.ExceptionRecord.ExceptionAddress)),
		    static_cast<unsigned long long>(bootstrapAddress), exception.ExceptionRecord.ExceptionCode);
		return DBG_CONTINUE;
	}

	int Debugger::AttachExisting(
	    const Patterns& patterns, unsigned durationSeconds, IDebugEventsHandler& handler,
	    bool watchProcesses)
	{
		THROW_HR_IF(E_INVALIDARG, !durationSeconds || !processHandles_.empty());
		external_ = true;
		std::unique_ptr<ProcessWatcher> watcher;
		if (watchProcesses)
		{
			watcher = std::make_unique<ProcessWatcher>();
			watcher->Start();
		}
		OwnedHelper helper;
		const auto control = CalibrateBootstrap(helper);
		stopRequested.store(false);
		THROW_LAST_ERROR_IF(!SetConsoleCtrlHandler(&StopCollection, TRUE));
		auto removeHandler = wil::scope_exit([&] { SetConsoleCtrlHandler(&StopCollection, FALSE); });
		std::map<DWORD, std::unique_ptr<Connection>> connections;
		std::unordered_set<DWORD> reportedFailures;
		auto snapshot = SnapshotExistingProcesses(patterns, helper.id, {}, &reportedFailures);
		LOG_INFO << "External capture observes execution only after attachment; earlier execution is not collected";
		size_t nextCandidate = 0;
		int result = snapshot.failedAdmissions ? 1 : 0;
		bool stopping = false;
		bool quiesced = false;
		bool deadlineStarted = watchProcesses;
		auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{durationSeconds};
		if (watchProcesses)
			LOG_INFO << "Process watch started; initial_candidates=" << snapshot.processes.size()
			         << " duration=" << durationSeconds;
		std::deque<ProcessWatcher::Event> notices;
		auto nextSnapshot = std::chrono::steady_clock::now() + std::chrono::seconds{2};
		auto nextReconciliation = std::chrono::steady_clock::now();
		auto nextDiscovery = std::chrono::steady_clock::now();
		bool reconcile = false;
		bool discoveryStopped = false;
		DEBUG_EVENT event{};
		bool pending = false;
		bool dispatched = false;
		bool exceptionRepair = false;
		bool repairableException = false;
		DWORD disposition = DBG_CONTINUE;
		auto lastRecoveryLog = std::chrono::steady_clock::now() - std::chrono::seconds{10};

		auto reportRecovery = [&](const std::exception& error) {
			result = 1;
			stopping = true;
			stopRequested.store(true);
			const auto now = std::chrono::steady_clock::now();
			if (now - lastRecoveryLog >= std::chrono::seconds{1})
			{
				LOG_ERROR << "External cleanup retains debugger ownership and retries: " << error.what();
				lastRecoveryLog = now;
			}
		};

		auto outstanding = [&] {
			for (const auto& pair : connections)
				if (!pair.second->settled)
					return true;
			return false;
		};
		auto discover = [&] {
			if (!watcher || stopping || std::chrono::steady_clock::now() < nextDiscovery)
				return;
			nextDiscovery = std::chrono::steady_clock::now() + std::chrono::milliseconds{20};
			watcher->CheckHealth();
			reconcile |= watcher->TakeReconcileRequest();
			if (nextCandidate == snapshot.processes.size())
			{
				snapshot.processes.clear();
				nextCandidate = 0;
			}
			std::unordered_set<DWORD> skip;
			for (const auto& pair : connections)
				skip.insert(pair.first);
			for (size_t index = nextCandidate; index < snapshot.processes.size(); ++index)
				skip.insert(snapshot.processes[index].id);
			if (notices.empty())
				for (auto& notice : watcher->Drain())
					notices.push_back(std::move(notice));
			for (size_t count = 0; count < 8 && !notices.empty() &&
			    snapshot.processes.size() - nextCandidate < 64; ++count)
			{
				auto notice = std::move(notices.front());
				notices.pop_front();
				if (!notice.started)
				{
					reportedFailures.erase(notice.id);
					continue;
				}
				if (skip.count(notice.id))
					continue;
				if (notice.image.empty())
				{
					reconcile = true;
					continue;
				}
				try
				{
					auto candidate = InspectExistingProcess(
					    patterns, notice.id, notice.image, helper.id, notice.created);
					if (candidate)
					{
						LOG_DEBUG << "ETW process launch discovered pid=" << candidate->id
						          << " main_image=" << candidate->path;
						skip.insert(candidate->id);
						snapshot.processes.push_back(std::move(*candidate));
					}
				}
				catch (const std::exception& error)
				{
					result = 1;
					if (reportedFailures.insert(notice.id).second)
						LOG_ERROR << "Process admission failed pid=" << notice.id
						          << " main_image=" << notice.image << ": " << ProcessAdmissionDiagnostic(error);
				}
			}
			const auto now = std::chrono::steady_clock::now();
			if ((now >= nextSnapshot || (reconcile && now >= nextReconciliation)) &&
			    snapshot.processes.size() - nextCandidate < 64)
			{
				if (reconcile)
					LOG_WARNING << "Reconciling process watch after lost or incomplete ETW notifications";
				auto fresh = SnapshotExistingProcesses(patterns, helper.id, skip, &reportedFailures);
				if (fresh.failedAdmissions)
					result = 1;
				for (auto& candidate : fresh.processes)
					snapshot.processes.push_back(std::move(candidate));
				nextSnapshot = std::chrono::steady_clock::now() + std::chrono::seconds{2};
				nextReconciliation = std::chrono::steady_clock::now() + std::chrono::milliseconds{500};
				reconcile = false;
			}
		};
		auto admitNext = [&] {
			auto candidate = std::move(snapshot.processes[nextCandidate++]);
			const auto id = candidate.id;
			auto connection = std::make_unique<Connection>();
			connection->candidate = std::move(candidate);
			auto& current = *connection;
			THROW_HR_IF(E_UNEXPECTED, !connections.emplace(id, std::move(connection)).second);
			try
			{
				current.candidate.Validate();
				current.held.HoldProcess(id);
				current.candidate.Validate();
				THROW_LAST_ERROR_IF(!DebugSetProcessKillOnExit(FALSE));
				THROW_LAST_ERROR_IF(!DebugActiveProcess(id));
				current.attached = true;
				LOG_INFO << "Attaching existing process pid=" << id
				         << " main_image=" << current.candidate.path;
			}
			catch (const std::exception& error)
			{
				if (current.attached)
					throw;
				if (watchProcesses && Exited(current.candidate.handle.get()))
				{
					LOG_WARNING << "Selected process exited before attachment pid=" << id;
					current.held.Resume();
					connections.erase(id);
					return;
				}
				result = 1;
				if (reportedFailures.insert(id).second)
					LOG_ERROR << "Process attach failed pid=" << id << " main_image="
					          << current.candidate.path << ": " << ProcessAdmissionDiagnostic(error);
				current.held.Resume();
				connections.erase(id);
			}
		};
		while (helper.alive || outstanding())
		{
			try
			{
				if (pending && event.dwProcessId != helper.id &&
				    event.dwDebugEventCode != EXIT_PROCESS_DEBUG_EVENT)
				{
					auto& connection = *connections.at(event.dwProcessId);
					if (connection.verified &&
					    Exited(connection.candidate.handle.get()))
					{
						if (!dispatched && event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT)
						{
							wil::unique_handle file{event.u.LoadDll.hFile};
						}
						THROW_LAST_ERROR_IF(!ContinueDebugEvent(event.dwProcessId,
						    event.dwThreadId, event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
						        ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE));
						pending = false;
						continue;
					}
				}
				if (stopRequested.load() || (!helper.alive) ||
				    (deadlineStarted && std::chrono::steady_clock::now() >= deadline))
					stopping = true;
				if (stopping && watcher && !discoveryStopped)
				{
					watcher->Stop();
					discoveryStopped = true;
					watcher->CheckHealth();
				}
				if (stopping && nextCandidate < snapshot.processes.size())
				{
					LOG_ERROR << "Collection stopped before admitting all selected existing processes";
					nextCandidate = snapshot.processes.size();
					result = 1;
				}
				if (!stopping && !deadlineStarted && nextCandidate == snapshot.processes.size())
				{
					bool ready = true;
					for (const auto& pair : connections)
						ready &= pair.second->ready || pair.second->exited;
					if (ready)
					{
						deadline = std::chrono::steady_clock::now() +
						    std::chrono::seconds{durationSeconds};
						deadlineStarted = true;
						LOG_INFO << "Existing-process cohort collection started; count=" << connections.size();
						if (connections.empty())
						{
							LOG_ERROR << "No eligible existing process was attached";
							result = 1;
							stopping = true;
						}
					}
				}

				if (stopping && !quiesced)
				{
					for (auto& pair : connections)
					{
						auto& connection = *pair.second;
						if (connection.exited || connection.detached)
							continue;
						if (connection.attached && !connection.ready)
						{
							connection.held.Fence();
							if (connection.initialized)
								handler.OnPrepareDetach(GetProcessHandle(pair.first));
							connection.restored = true;
							continue;
						}
						connection.held.HoldProcess(pair.first);
						if (Exited(connection.candidate.handle.get()))
							continue;
						if (connection.initialized)
							handler.OnPrepareDetach(GetProcessHandle(pair.first));
						connection.restored = true;
					}
					quiesced = true;
				}

				if (!pending)
				{
					if (WaitForDebugEvent(&event, stopping ? 0 : 20))
					{
						pending = true;
						dispatched = false;
						exceptionRepair = false;
						repairableException = false;
						disposition = event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
						    ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
					}
					else
					{
						THROW_WIN32_IF(GetLastError(), GetLastError() != ERROR_SEM_TIMEOUT);
						if (stopping)
						{
							for (auto& pair : connections)
								if (!pair.second->settled)
									pair.second->held.Fence();
							if (WaitForDebugEvent(&event, 0))
							{
								pending = true;
								dispatched = false;
								exceptionRepair = false;
								repairableException = false;
								disposition = event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT
								    ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE;
								continue;
							}
							THROW_WIN32_IF(GetLastError(), GetLastError() != ERROR_SEM_TIMEOUT);
							for (auto& pair : connections)
							{
								auto& connection = *pair.second;
								if (connection.settled)
									continue;
								if (connection.attached &&
								    Exited(connection.candidate.handle.get()))
									continue;
								if (connection.attached && !connection.ready)
									continue;
								connection.held.Fence();
								if (connection.attached && !connection.detached)
								{
									THROW_HR_IF_MSG(E_PENDING, !connection.ready,
									    "Attach bootstrap is not yet attributed; retaining the connection");
									THROW_LAST_ERROR_IF(!DebugActiveProcessStop(pair.first));
									connection.detached = true;
									handler.OnDetachedProcess(GetProcessHandle(pair.first));
									RemoveProcessThreads(pair.first);
									processHandles_.erase(pair.first);
									LOG_INFO << "Detached existing process pid=" << pair.first;
								}
								connection.held.Resume();
								connection.settled = true;
							}
							if (!outstanding())
								helper.writer.reset();
						}
						else
						{
							discover();
							if (helper.ready && nextCandidate < snapshot.processes.size())
								admitNext();
						}
						continue;
					}
				}

				if (!dispatched)
				{
					if (event.dwProcessId == helper.id)
					{
						disposition = helper.Dispatch(event);
						if (!helper.alive && (outstanding() || (watchProcesses && !stopping)))
						{
							stopping = true;
							result = 1;
							LOG_ERROR << "Owned debugger helper exited; safely stopping external collection";
						}
					}
					else
					{
						auto& connection = *connections.at(event.dwProcessId);
						HANDLE process = processHandles_.count(event.dwProcessId)
						    ? GetProcessHandle(event.dwProcessId) : connection.candidate.handle.get();
						if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
						{
							THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
							    !connection.candidate.SameInstance(event.u.CreateProcessInfo.hProcess),
							    "CREATE_PROCESS identity differs from the admitted process instance");
							connection.verified = true;
							if (!connection.held.Contains(event.dwThreadId))
								connection.bootstrapThread = event.dwThreadId;
							connection.initialized = true;
						}
						if (event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT && !connection.ready &&
						    !connection.held.Contains(event.dwThreadId))
						{
							THROW_HR_IF_MSG(E_PENDING,
							    connection.bootstrapThread && connection.bootstrapThread != event.dwThreadId,
							    "Concurrent new threads make attach bootstrap ownership ambiguous");
							connection.bootstrapThread = event.dwThreadId;
						}
						if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && !connection.ready)
						{
							const auto address = control.Match(process,
							    event.u.LoadDll.hFile, event.u.LoadDll.lpBaseOfDll);
							if (address)
								connection.bootstrapAddress = address;
						}
						if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && !connection.ready)
						{
							const auto& exception = event.u.Exception;
							disposition = AttachExceptionDisposition(exception, event.dwThreadId,
							    connection.held.Contains(event.dwThreadId), connection.bootstrapThread,
							    static_cast<ULONG_PTR>(connection.bootstrapAddress));
							if (disposition == DBG_CONTINUE)
							{
								handler.OnAttachedProcessReady(GetProcessHandle(event.dwProcessId));
								connection.ready = true;
								if (stopping)
									quiesced = false;
								if (!stopping)
									connection.held.Resume();
								LOG_INFO << "Attached existing process pid=" << event.dwProcessId;
							}
						}
						else
						{
							// Callback failures retain the pending event; only exception repair is replayed.
							repairableException = connection.ready &&
							    event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
							    event.u.Exception.dwFirstChance &&
							    (event.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT ||
							     event.u.Exception.ExceptionRecord.ExceptionCode == 0x4000001f);
							dispatched = true;
							disposition = DispatchExternalEvent(event, handler);
						}
						if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
						{
							connection.exited = true;
							connection.settled = true;
						}
						if (stopping && connection.ready &&
						    event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT)
							connection.held.Hold(GetThreadHandle(event.dwThreadId));
						if (stopping && connection.ready &&
						    event.dwDebugEventCode != EXIT_PROCESS_DEBUG_EVENT &&
						    event.dwDebugEventCode != EXIT_THREAD_DEBUG_EVENT)
							connection.held.Hold(GetThreadHandle(event.dwThreadId));
						if (!stopping && connection.ready && processHandles_.count(event.dwProcessId))
							handler.OnBeforeContinue(GetProcessHandle(event.dwProcessId));
					}
					dispatched = true;
				}
				if (exceptionRepair)
				{
					auto& connection = *connections.at(event.dwProcessId);
					THROW_HR_IF(E_PENDING, !connection.ready || !connection.restored);
					disposition = DispatchExternalEvent(event, handler);
					exceptionRepair = false;
				}
				THROW_LAST_ERROR_IF(!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition));
				pending = false;
				if (watchProcesses && event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT &&
				    event.dwProcessId != helper.id)
				{
					const auto connection = connections.find(event.dwProcessId);
					if (connection != connections.end() &&
					    connection->second->exited && connection->second->settled)
					{
						completedProcessIds_.erase(connection->first);
						connections.erase(connection);
					}
				}
				discover();
				if (!stopping && helper.ready && nextCandidate < snapshot.processes.size())
					admitNext();
			}
			catch (const std::exception& error)
			{
				reportRecovery(error);
				quiesced = false;
				if (pending && dispatched && repairableException)
					exceptionRepair = true;
				Sleep(20);
			}
		}
		THROW_HR_IF_MSG(E_UNEXPECTED, !connections.empty() && !stopping,
		    "The owned debugger helper exited before external cleanup");
		return result;
	}
}
