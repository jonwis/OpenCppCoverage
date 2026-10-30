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

#include "stdafx.h"
#include "CppCoverage/ProcessWatcher.hpp"
#include <wil/resource.h>
#include <array>
#include <atomic>
#include <cstring>
#include <exception>
#include <stdexcept>

namespace CppCoverageTest
{
	namespace
	{
		using Watcher = CppCoverage::ProcessWatcher;
		const GUID Provider{
		    0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};

		struct TraceApi;
		TraceApi* active = nullptr;

		struct TraceApi
		{
			ULONG startError = ERROR_SUCCESS;
			ULONG enableError = ERROR_SUCCESS;
			ULONG openError = ERROR_SUCCESS;
			ULONG processError = ERROR_SUCCESS;
			ULONG metadataError = ERROR_SUCCESS;
			bool throwMetadata = false;
			ULONG eventsLost = 0;
			ULONG buffersLost = 0;
			int starts = 0;
			int closes = 0;
			int stops = 0;
			std::wstring name;
			EVENT_TRACE_LOGFILEW logfile{};
			HANDLE finish = CreateEventW(nullptr, TRUE, FALSE, nullptr);
			std::atomic<bool> entered{false};

			TraceApi()
			{
				active = this;
				if (!finish)
					throw std::runtime_error{"Cannot create fake trace completion event"};
			}
			~TraceApi()
			{
				CloseHandle(finish);
				active = nullptr;
			}
			TraceApi(const TraceApi&) = delete;
			TraceApi& operator=(const TraceApi&) = delete;

			Watcher::Api Functions()
			{
				Watcher::Api api;
				api.start = &Start;
				api.enable = &Enable;
				api.open = &Open;
				api.process = &Process;
				api.close = &Close;
				api.control = &Control;
				api.information = &Information;
				return api;
			}

			static ULONG WINAPI Start(PTRACEHANDLE handle, LPCWSTR name, PEVENT_TRACE_PROPERTIES properties)
			{
				++active->starts;
				active->name = name;
				EXPECT_EQ(static_cast<ULONG>(EVENT_TRACE_REAL_TIME_MODE), properties->LogFileMode);
				EXPECT_EQ(0u, properties->LogFileNameOffset);
				if (active->startError)
					return active->startError;
				*handle = 1234;
				return ERROR_SUCCESS;
			}
			static ULONG WINAPI Enable(TRACEHANDLE handle, LPCGUID provider, ULONG control,
			    UCHAR level, ULONGLONG any, ULONGLONG all, ULONG, PENABLE_TRACE_PARAMETERS)
			{
				EXPECT_EQ(1234u, handle);
				EXPECT_TRUE(IsEqualGUID(Provider, *provider));
				EXPECT_EQ(static_cast<ULONG>(EVENT_CONTROL_CODE_ENABLE_PROVIDER), control);
				EXPECT_EQ(TRACE_LEVEL_INFORMATION, level);
				EXPECT_EQ(0x10u, any);
				EXPECT_EQ(0u, all);
				return active->enableError;
			}
			static TRACEHANDLE WINAPI Open(PEVENT_TRACE_LOGFILEW logfile)
			{
				active->logfile = *logfile;
				if (active->openError)
				{
					SetLastError(active->openError);
					return INVALID_PROCESSTRACE_HANDLE;
				}
				return 5678;
			}
			static ULONG WINAPI Process(PTRACEHANDLE handle, ULONG count, LPFILETIME, LPFILETIME)
			{
				if (*handle != 5678 || count != 1)
					return ERROR_INVALID_HANDLE;
				active->entered.store(true);
				WaitForSingleObject(active->finish, INFINITE);
				return active->processError;
			}
			static ULONG WINAPI Close(TRACEHANDLE handle)
			{
				EXPECT_EQ(5678u, handle);
				++active->closes;
				SetEvent(active->finish);
				return ERROR_CTX_CLOSE_PENDING;
			}
			static ULONG WINAPI Control(TRACEHANDLE handle, LPCWSTR name,
			    PEVENT_TRACE_PROPERTIES properties, ULONG control)
			{
				EXPECT_EQ(1234u, handle);
				EXPECT_EQ(nullptr, name);
				if (control == EVENT_TRACE_CONTROL_STOP)
					++active->stops;
				else if (control == EVENT_TRACE_CONTROL_QUERY)
				{
					properties->EventsLost = active->eventsLost;
					properties->RealTimeBuffersLost = active->buffersLost;
				}
				else
					ADD_FAILURE() << "Unexpected trace control operation";
				return ERROR_SUCCESS;
			}
			static ULONG WINAPI Information(PEVENT_RECORD record, ULONG count, PTDH_CONTEXT context,
			    PTRACE_EVENT_INFO information, PULONG size)
			{
				if (active->throwMetadata)
					throw std::runtime_error{"injected metadata failure"};
				if (active->metadataError)
					return active->metadataError;
				return TdhGetEventInformation(record, count, context, information, size);
			}

			void Emit(std::vector<BYTE>& payload, USHORT id = 1, UCHAR version = 0,
			    USHORT flags = EVENT_HEADER_FLAG_64_BIT_HEADER)
			{
				EVENT_RECORD record{};
				record.EventHeader.Size = sizeof(EVENT_HEADER);
				record.EventHeader.ProviderId = Provider;
				record.EventHeader.ProcessId = 9999;
				record.EventHeader.ThreadId = 8888;
				record.EventHeader.EventDescriptor.Id = id;
				record.EventHeader.EventDescriptor.Version = version;
				record.EventHeader.EventDescriptor.Opcode = id == 1 ? 1 : 2;
				record.EventHeader.Flags = flags;
				record.UserContext = logfile.Context;
				record.UserData = payload.data();
				record.UserDataLength = static_cast<USHORT>(payload.size());
				logfile.EventRecordCallback(&record);
			}
		};

		template<typename T>
		void Append(std::vector<BYTE>& payload, const T& value)
		{
			const auto bytes = reinterpret_cast<const BYTE*>(&value);
			payload.insert(payload.end(), bytes, bytes + sizeof(value));
		}

		void Unicode(std::vector<BYTE>& payload, const std::wstring& value)
		{
			const auto bytes = reinterpret_cast<const BYTE*>(value.c_str());
			payload.insert(payload.end(), bytes, bytes + (value.size() + 1) * sizeof(wchar_t));
		}

		std::vector<BYTE> StartPayload(DWORD pid, const std::wstring& image = L"watched.exe",
		    UCHAR version = 0)
		{
			std::vector<BYTE> payload;
			Append(payload, pid);
			if (version >= 3)
				Append(payload, ULONGLONG{54321});
			Append(payload, FILETIME{123, 456});
			Append(payload, DWORD{4321});
			if (version >= 3)
				Append(payload, ULONGLONG{9876});
			Append(payload, DWORD{1});
			if (version >= 1)
				Append(payload, DWORD{0});
			if (version >= 3)
			{
				Append(payload, DWORD{1});
				Append(payload, DWORD{0});
				const BYTE sid[] = {1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
				payload.insert(payload.end(), std::begin(sid), std::end(sid));
			}
			Unicode(payload, image);
			if (version >= 2)
			{
				Append(payload, DWORD{0});
				Append(payload, DWORD{0});
				Unicode(payload, L"");
				Unicode(payload, L"");
			}
			return payload;
		}

		std::vector<BYTE> StopPayload(DWORD pid)
		{
			std::vector<BYTE> payload;
			Append(payload, pid);
			Append(payload, FILETIME{123, 456});
			Append(payload, FILETIME{321, 654});
			Append(payload, DWORD{0});
			Append(payload, DWORD{1});
			Append(payload, DWORD{0});
			Append(payload, ULONGLONG{0});
			Append(payload, ULONGLONG{0});
			const char image[] = "watched.exe";
			payload.insert(payload.end(), std::begin(image), std::end(image));
			return payload;
		}

		void ExpectFailure(Watcher& watcher, const char* api, const char* error)
		{
			try
			{
				watcher.Start();
				FAIL() << "Expected an ETW startup failure";
			}
			catch (const std::runtime_error& failure)
			{
				const std::string message{failure.what()};
				EXPECT_NE(std::string::npos, message.find(api));
				EXPECT_NE(std::string::npos, message.find(error));
				EXPECT_NE(std::string::npos, message.find("needs elevation"));
			}
		}
	}

	TEST(ProcessWatcher, InactiveWatcherMakesNoEtwCalls)
	{
		TraceApi api;
		{
			Watcher watcher{api.Functions()};
			EXPECT_TRUE(watcher.Drain().empty());
			EXPECT_FALSE(watcher.TakeReconcileRequest());
			EXPECT_NO_THROW(watcher.CheckHealth());
			watcher.Stop();
		}
		EXPECT_EQ(0, api.starts);
		EXPECT_EQ(0, api.stops);
		EXPECT_EQ(0, api.closes);
	}

	TEST(ProcessWatcher, StartDenialNeverStopsAnUnownedSession)
	{
		TraceApi api;
		api.startError = ERROR_ACCESS_DENIED;
		Watcher watcher{api.Functions()};
		ExpectFailure(watcher, "StartTraceW", "5");
		watcher.Stop();
		EXPECT_EQ(0, api.stops);
		EXPECT_EQ(0, api.closes);
		api.startError = ERROR_ALREADY_EXISTS;
		EXPECT_THROW(watcher.Start(), std::runtime_error);
		EXPECT_EQ(0, api.stops);
	}

	TEST(ProcessWatcher, RealEtwRejectsAnImpersonatedTokenWithoutTracingGroupsOrPrivileges)
	{
		wil::unique_handle source;
		ASSERT_TRUE(OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY,
		    source.put())) << GetLastError();
		const WELL_KNOWN_SID_TYPE groups[] = {
		    WinBuiltinAdministratorsSid, WinBuiltinPerfLoggingUsersSid, WinBuiltinPerfMonitoringUsersSid};
		std::array<std::array<DWORD, SECURITY_MAX_SID_SIZE / sizeof(DWORD)>, 3> sidStorage{};
		SID_AND_ATTRIBUTES disabled[3]{};
		for (size_t i = 0; i < sidStorage.size(); ++i)
		{
			DWORD size = sizeof(sidStorage[i]);
			disabled[i].Sid = sidStorage[i].data();
			ASSERT_TRUE(CreateWellKnownSid(groups[i], nullptr, disabled[i].Sid, &size))
			    << GetLastError();
		}
		DWORD bytes = 0;
		ASSERT_FALSE(GetTokenInformation(source.get(), TokenPrivileges, nullptr, 0, &bytes));
		ASSERT_EQ(static_cast<DWORD>(ERROR_INSUFFICIENT_BUFFER), GetLastError());
		std::vector<DWORD> privilegeStorage((bytes + sizeof(DWORD) - 1) / sizeof(DWORD));
		auto privileges = reinterpret_cast<TOKEN_PRIVILEGES*>(privilegeStorage.data());
		ASSERT_TRUE(GetTokenInformation(source.get(), TokenPrivileges, privileges, bytes, &bytes))
		    << GetLastError();
		wil::unique_handle restricted;
		ASSERT_TRUE(CreateRestrictedToken(source.get(), 0, 3, disabled,
		    privileges->PrivilegeCount, privileges->Privileges, 0, nullptr, restricted.put()))
		    << GetLastError();
		Watcher watcher;
		std::string rejection;
		{
			ASSERT_TRUE(ImpersonateLoggedOnUser(restricted.get())) << GetLastError();
			const auto revert = wil::scope_exit([]() noexcept
			{
				if (!RevertToSelf())
					std::terminate();
			});
			try { watcher.Start(); }
			catch (const std::runtime_error& error) { rejection = error.what(); }
		}
		watcher.Stop();
		ASSERT_FALSE(rejection.empty()) << "ETW accepted the restricted impersonation token";
		EXPECT_NE(std::string::npos, rejection.find("needs elevation"));
		EXPECT_TRUE(rejection.find("StartTraceW") != std::string::npos ||
		    rejection.find("OpenTraceW") != std::string::npos ||
		    rejection.find("EnableTraceEx2") != std::string::npos) << rejection;
		EXPECT_TRUE(rejection.find("Windows error 5") != std::string::npos ||
		    rejection.find("Windows error 1314") != std::string::npos) << rejection;
	}

	TEST(ProcessWatcher, RealLifecycleCreationTimeMatchesTheOwnedProcess)
	{
		Watcher watcher;
		try
		{
			watcher.Start();
		}
		catch (const std::runtime_error& error)
		{
			if (std::string{error.what()}.find("needs elevation") != std::string::npos)
				GTEST_SKIP() << error.what();
			throw;
		}
		std::array<wchar_t, 32768> directory{};
		const auto length = GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
		ASSERT_GT(length, 0u) << GetLastError();
		ASSERT_LT(length, directory.size());
		const std::wstring executable = std::wstring{directory.data(), length} + L"\\cmd.exe";
		std::wstring command = L"\"" + executable + L"\" /d /c exit 0";
		STARTUPINFOW startup{};
		startup.cb = sizeof(startup);
		PROCESS_INFORMATION information{};
		ASSERT_TRUE(CreateProcessW(executable.c_str(), &command[0], nullptr, nullptr, FALSE,
		    CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &startup, &information))
		    << GetLastError();
		wil::unique_handle process{information.hProcess};
		wil::unique_handle thread{information.hThread};
		const auto cleanup = wil::scope_exit([&]() noexcept
		{
			if (WaitForSingleObject(process.get(), 0) == WAIT_TIMEOUT)
			{
				TerminateProcess(process.get(), ERROR_CANCELLED);
				WaitForSingleObject(process.get(), 5000);
			}
		});
		FILETIME created{}, exited{}, kernel{}, user{};
		ASSERT_TRUE(GetProcessTimes(process.get(), &created, &exited, &kernel, &user)) << GetLastError();
		const auto awaitNotice = [&](bool started, Watcher::Event& result)
		{
			const auto deadline = GetTickCount64() + 10000;
			while (GetTickCount64() < deadline)
			{
				watcher.CheckHealth();
				for (const auto& event : watcher.Drain())
				{
					if (event.id == information.dwProcessId && event.started == started)
					{
						result = event;
						return true;
					}
				}
				Sleep(20);
			}
			return false;
		};
		Watcher::Event start;
		ASSERT_TRUE(awaitNotice(true, start)) << "No ETW start for the owned suspended cmd.exe";
		EXPECT_TRUE(start.started);
		EXPECT_EQ(information.dwProcessId, start.id);
		EXPECT_EQ(created.dwLowDateTime, start.created.dwLowDateTime);
		EXPECT_EQ(created.dwHighDateTime, start.created.dwHighDateTime);
		const auto separator = start.image.find_last_of(L"\\/");
		const auto basename = start.image.substr(separator == std::wstring::npos ? 0 : separator + 1);
		EXPECT_EQ(CSTR_EQUAL, CompareStringOrdinal(basename.c_str(), -1, L"cmd.exe", -1, TRUE))
		    << testing::PrintToString(start.image);
		ASSERT_NE(static_cast<DWORD>(-1), ResumeThread(thread.get())) << GetLastError();
		ASSERT_EQ(static_cast<DWORD>(WAIT_OBJECT_0), WaitForSingleObject(process.get(), 10000));
		DWORD exitCode = 0;
		ASSERT_TRUE(GetExitCodeProcess(process.get(), &exitCode)) << GetLastError();
		EXPECT_EQ(0u, exitCode);
		Watcher::Event stop;
		ASSERT_TRUE(awaitNotice(false, stop)) << "No ETW stop for the owned cmd.exe";
		EXPECT_EQ(created.dwLowDateTime, stop.created.dwLowDateTime);
		EXPECT_EQ(created.dwHighDateTime, stop.created.dwHighDateTime);
		watcher.Stop();
		EXPECT_NO_THROW(watcher.CheckHealth());
	}

	TEST(ProcessWatcher, ProviderDenialClosesConsumerAndOwnedSession)
	{
		TraceApi api;
		api.enableError = ERROR_PRIVILEGE_NOT_HELD;
		Watcher watcher{api.Functions()};
		ExpectFailure(watcher, "EnableTraceEx2", "1314");
		watcher.Stop();
		EXPECT_EQ(1, api.stops);
		EXPECT_EQ(1, api.closes);
	}

	TEST(ProcessWatcher, ConsumerOpenDenialStopsOwnedSession)
	{
		TraceApi api;
		api.openError = ERROR_ACCESS_DENIED;
		Watcher watcher{api.Functions()};
		ExpectFailure(watcher, "OpenTraceW", "5");
		EXPECT_EQ(1, api.stops);
		EXPECT_EQ(0, api.closes);
	}

	TEST(ProcessWatcher, StopJoinsBlockedConsumerAndSessionNamesAreUnique)
	{
		TraceApi api;
		std::wstring firstName;
		{
			Watcher watcher{api.Functions()};
			watcher.Start();
			firstName = api.name;
			const auto deadline = GetTickCount64() + 5000;
			while (!api.entered.load() && GetTickCount64() < deadline)
				Sleep(1);
			EXPECT_TRUE(api.entered.load());
		}
		EXPECT_EQ(1, api.stops);
		EXPECT_EQ(1, api.closes);
		ResetEvent(api.finish);
		Watcher next{api.Functions()};
		next.Start();
		EXPECT_NE(firstName, api.name);
		EXPECT_THROW(next.Start(), std::logic_error);
		next.Stop();
		next.Stop();
		EXPECT_NO_THROW(next.CheckHealth());
		EXPECT_EQ(2, api.stops);
		EXPECT_EQ(2, api.closes);
	}

	TEST(ProcessWatcher, DeliberateStopAllowsConsumerCancellation)
	{
		TraceApi api;
		api.processError = ERROR_CANCELLED;
		Watcher watcher{api.Functions()};
		watcher.Start();
		watcher.Stop();
		EXPECT_NO_THROW(watcher.CheckHealth());
	}

	TEST(ProcessWatcher, ManifestDecodingPreservesTargetIdentityAcrossHeaderArchitectures)
	{
		TraceApi api;
		Watcher watcher{api.Functions()};
		watcher.Start();
		for (const auto flags : {EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_HEADER_FLAG_64_BIT_HEADER})
		{
			for (const UCHAR version : {UCHAR{0}, UCHAR{3}})
			{
				auto payload = StartPayload(2468, L"C:\\bin\\watched.exe", version);
				api.Emit(payload, 1, version, static_cast<USHORT>(flags));
				auto events = watcher.Drain();
				ASSERT_EQ(1u, events.size());
				EXPECT_EQ(2468u, events[0].id);
				EXPECT_TRUE(events[0].started);
				EXPECT_EQ(123u, events[0].created.dwLowDateTime);
				EXPECT_EQ(456u, events[0].created.dwHighDateTime);
				EXPECT_EQ(L"C:\\bin\\watched.exe", events[0].image);
				EXPECT_FALSE(watcher.TakeReconcileRequest());
			}
		}
		auto payload = StopPayload(2468);
		api.Emit(payload, 2);
		auto events = watcher.Drain();
		ASSERT_EQ(1u, events.size());
		EXPECT_EQ(2468u, events[0].id);
		EXPECT_FALSE(events[0].started);
		EXPECT_EQ(123u, events[0].created.dwLowDateTime);
		EXPECT_EQ(L"watched.exe", events[0].image);
	}

	TEST(ProcessWatcher, OverflowAndMalformedNoticesCoalesceReconciliation)
	{
		TraceApi api;
		Watcher watcher{api.Functions()};
		watcher.Start();
		auto payload = StartPayload(2468);
		for (unsigned i = 0; i < 1040; ++i)
			api.Emit(payload);
		EXPECT_EQ(1024u, watcher.Drain().size());
		EXPECT_TRUE(watcher.TakeReconcileRequest());
		EXPECT_FALSE(watcher.TakeReconcileRequest());
		payload.resize(2);
		api.Emit(payload);
		EXPECT_TRUE(watcher.Drain().empty());
		EXPECT_TRUE(watcher.TakeReconcileRequest());
		EXPECT_FALSE(watcher.TakeReconcileRequest());
	}

	TEST(ProcessWatcher, OversizedImageIsUnavailableAndRequestsReconciliation)
	{
		TraceApi api;
		Watcher watcher{api.Functions()};
		watcher.Start();
		auto payload = StartPayload(2468, std::wstring(5000, L'x'));
		api.Emit(payload);
		auto events = watcher.Drain();
		ASSERT_EQ(1u, events.size());
		EXPECT_EQ(2468u, events[0].id);
		EXPECT_TRUE(events[0].image.empty());
		EXPECT_TRUE(watcher.TakeReconcileRequest());
	}

	TEST(ProcessWatcher, SessionLossCountersRequestReconciliation)
	{
		TraceApi api;
		api.eventsLost = 3;
		api.buffersLost = 2;
		Watcher watcher{api.Functions()};
		watcher.Start();
		EXPECT_TRUE(watcher.TakeReconcileRequest());
		EXPECT_FALSE(watcher.TakeReconcileRequest());
	}

	TEST(ProcessWatcher, CallbackFailuresStayInsideTheCallbackAndAreReported)
	{
		TraceApi api;
		api.throwMetadata = true;
		Watcher watcher{api.Functions()};
		watcher.Start();
		auto payload = StartPayload(2468);
		EXPECT_NO_THROW(api.Emit(payload));
		EXPECT_THROW(watcher.CheckHealth(), std::runtime_error);
	}

	TEST(ProcessWatcher, MissingMetadataRequestsReconciliationAndDeniedMetadataNamesTheApi)
	{
		TraceApi api;
		Watcher watcher{api.Functions()};
		watcher.Start();
		auto payload = StartPayload(2468);
		api.metadataError = ERROR_NOT_FOUND;
		api.Emit(payload);
		EXPECT_TRUE(watcher.Drain().empty());
		EXPECT_TRUE(watcher.TakeReconcileRequest());
		EXPECT_NO_THROW(watcher.CheckHealth());
		api.metadataError = ERROR_ACCESS_DENIED;
		api.Emit(payload);
		try
		{
			watcher.CheckHealth();
			FAIL() << "Expected a denied TDH operation";
		}
		catch (const std::runtime_error& error)
		{
			const std::string message{error.what()};
			EXPECT_NE(std::string::npos, message.find("TdhGetEventInformation"));
			EXPECT_NE(std::string::npos, message.find("needs elevation"));
		}
	}

	TEST(ProcessWatcher, UnexpectedConsumerTerminationIsFatalAndNamesTheApi)
	{
		TraceApi api;
		api.processError = ERROR_ACCESS_DENIED;
		Watcher watcher{api.Functions()};
		watcher.Start();
		SetEvent(api.finish);
		std::string failure;
		const auto deadline = GetTickCount64() + 5000;
		while (GetTickCount64() < deadline && failure.empty())
		{
			try { watcher.CheckHealth(); }
			catch (const std::runtime_error& error) { failure = error.what(); }
			if (failure.empty())
				Sleep(1);
		}
		EXPECT_NE(std::string::npos, failure.find("ProcessTrace"));
		EXPECT_NE(std::string::npos, failure.find("needs elevation"));
		EXPECT_NE(std::string::npos, failure.find("Windows error 5"));
		watcher.Stop();
		EXPECT_THROW(watcher.CheckHealth(), std::runtime_error);
	}

	TEST(ProcessWatcher, DeliberateStopDoesNotHideAnUnexpectedConsumerError)
	{
		TraceApi api;
		api.processError = ERROR_ACCESS_DENIED;
		Watcher watcher{api.Functions()};
		watcher.Start();
		watcher.Stop();
		EXPECT_THROW(watcher.CheckHealth(), std::runtime_error);
	}
}
