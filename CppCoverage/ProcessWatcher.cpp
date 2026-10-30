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

#include "ProcessWatcher.hpp"
#include <rpc.h>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <stdexcept>
#include <thread>

namespace CppCoverage
{
	namespace
	{
		const GUID ProcessProvider{
		    0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};

		class Lock
		{
		public:
			explicit Lock(SRWLOCK& lock) noexcept : lock_(lock)
			{
				AcquireSRWLockExclusive(&lock_);
			}
			~Lock() noexcept { ReleaseSRWLockExclusive(&lock_); }
			Lock(const Lock&) = delete;
			Lock& operator=(const Lock&) = delete;
		private:
			SRWLOCK& lock_;
		};

		[[noreturn]] void Fail(const char* api, ULONG error)
		{
			std::string message = std::string{api} + " failed (Windows error " +
			    std::to_string(error) + "). ";
			if (error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD)
				message += "Process launch watching needs elevation. Run --watch_processes "
				    "from an elevated command prompt, or omit --watch_processes.";
			else
				message += "Cannot watch process launches. Check the ETW session/provider "
				    "configuration and available tracing resources, or omit --watch_processes.";
			throw std::runtime_error{message};
		}
	}

	struct ProcessWatcher::State
	{
		static constexpr size_t QueueCapacity = 1024;
		static constexpr size_t ImageCapacity = 4096;
		enum class Operation : ULONG
		{
			Process, Close, Control, Callback, Information, PropertySize, Property
		};
		struct Properties
		{
			EVENT_TRACE_PROPERTIES trace{};
			wchar_t name[128]{};
		};

		explicit State(const Api& functions) : api(functions) {}

		Api api;
		SRWLOCK lifecycleLock = SRWLOCK_INIT;
		SRWLOCK queueLock = SRWLOCK_INIT;
		Properties properties{};
		TRACEHANDLE session = 0;
		TRACEHANDLE consumer = INVALID_PROCESSTRACE_HANDLE;
		EVENT_TRACE_LOGFILEW logfile{};
		std::thread worker;
		std::atomic<bool> stopping{true};
		std::atomic<bool> reconcile{false};
		std::atomic<ULONGLONG> failure{0};
		std::array<Event, QueueCapacity> queue;
		size_t head = 0;
		size_t count = 0;
		ULONG lostEvents = 0;
		ULONG lostBuffers = 0;
		ULONGLONG lastLossQuery = 0;
		std::array<ULONGLONG, 8192> metadata{};
		std::array<wchar_t, ImageCapacity> imageBuffer{};

		void RecordFailure(Operation operation, ULONG error) noexcept
		{
			ULONGLONG expected = 0;
			failure.compare_exchange_strong(expected,
			    (static_cast<ULONGLONG>(operation) << 32) | error);
		}

		void CheckPermission(Operation operation, ULONG error) noexcept
		{
			if (error == ERROR_ACCESS_DENIED || error == ERROR_PRIVILEGE_NOT_HELD)
				RecordFailure(operation, error);
		}

		void QueryLoss()
		{
			Lock lock{lifecycleLock};
			if (!session || stopping.load())
				return;
			const auto now = GetTickCount64();
			if (lastLossQuery && now - lastLossQuery < 1000)
				return;
			Properties observed{};
			observed.trace.Wnode.BufferSize = sizeof(observed);
			observed.trace.LoggerNameOffset = offsetof(Properties, name);
			const auto error = api.control(session, nullptr, &observed.trace, EVENT_TRACE_CONTROL_QUERY);
			if (error != ERROR_SUCCESS)
				Fail("ControlTraceW(QUERY)", error);
			lastLossQuery = now;
			if (observed.trace.EventsLost != lostEvents ||
			    observed.trace.RealTimeBuffersLost != lostBuffers)
			{
				lostEvents = observed.trace.EventsLost;
				lostBuffers = observed.trace.RealTimeBuffersLost;
				reconcile.store(true);
			}
		}

		void StopLocked() noexcept
		{
			stopping.store(true);
			// CloseTrace cancels the real-time consumer even if stopping the session fails.
			if (consumer != INVALID_PROCESSTRACE_HANDLE)
			{
				const auto error = api.close(consumer);
				if (error != ERROR_SUCCESS && error != ERROR_CTX_CLOSE_PENDING)
					RecordFailure(Operation::Close, error);
				consumer = INVALID_PROCESSTRACE_HANDLE;
			}
			if (session)
			{
				const auto error = api.control(session, nullptr, &properties.trace,
				    EVENT_TRACE_CONTROL_STOP);
				if (error == ERROR_SUCCESS || error == ERROR_WMI_INSTANCE_NOT_FOUND)
					session = 0;
				else
					RecordFailure(Operation::Control, error);
			}
			if (worker.joinable())
				worker.join();
		}

		void StartLocked()
		{
			if (session || worker.joinable())
				throw std::logic_error{"Process launch watching is already started"};
			GUID id{};
			const auto uuidError = UuidCreate(&id);
			if (uuidError != RPC_S_OK && uuidError != RPC_S_UUID_LOCAL_ONLY)
				Fail("UuidCreate", uuidError);
			properties = {};
			swprintf_s(properties.name,
			    L"OpenCppCoverage-Process-%lu-%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
			    GetCurrentProcessId(), id.Data1, id.Data2, id.Data3,
			    id.Data4[0], id.Data4[1], id.Data4[2], id.Data4[3],
			    id.Data4[4], id.Data4[5], id.Data4[6], id.Data4[7]);
			properties.trace.Wnode.BufferSize = sizeof(properties);
			properties.trace.Wnode.Guid = id;
			properties.trace.Wnode.ClientContext = 1;
			properties.trace.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
			properties.trace.BufferSize = 64;
			properties.trace.MinimumBuffers = 4;
			properties.trace.MaximumBuffers = 64;
			properties.trace.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
			properties.trace.FlushTimer = 1;
			properties.trace.LoggerNameOffset = offsetof(Properties, name);
			failure.store(ERROR_SUCCESS);
			reconcile.store(false);
			lostEvents = 0;
			lostBuffers = 0;
			lastLossQuery = 0;
			{
				Lock lock{queueLock};
				for (auto& event : queue)
					event = {};
				head = count = 0;
			}
			TRACEHANDLE started = 0;
			const auto error = api.start(&started, properties.name, &properties.trace);
			if (error != ERROR_SUCCESS)
				Fail("StartTraceW", error);
			session = started;
			try
			{
				logfile = {};
				logfile.LoggerName = properties.name;
				logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
				logfile.Context = this;
				logfile.EventRecordCallback = &OnEvent;
				logfile.BufferCallback = &OnBuffer;
				consumer = api.open(&logfile);
				if (consumer == INVALID_PROCESSTRACE_HANDLE)
					Fail("OpenTraceW", GetLastError());
				const auto enableError = api.enable(session, &ProcessProvider,
				    EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, 0x10, 0, 0, nullptr);
				if (enableError != ERROR_SUCCESS)
					Fail("EnableTraceEx2", enableError);
				stopping.store(false);
				const auto trace = consumer;
				worker = std::thread{[this, trace]() noexcept
				{
					try
					{
						auto handle = trace;
						const auto result = api.process(&handle, 1, nullptr, nullptr);
						if (!stopping.load())
							RecordFailure(Operation::Process,
							    result == ERROR_SUCCESS ? ERROR_INVALID_STATE : result);
						else if (result != ERROR_SUCCESS && result != ERROR_CANCELLED &&
						    result != ERROR_INVALID_HANDLE && result != ERROR_WMI_INSTANCE_NOT_FOUND)
							RecordFailure(Operation::Process, result);
					}
					catch (...)
					{
						RecordFailure(Operation::Process, ERROR_UNHANDLED_EXCEPTION);
					}
				}};
			}
			catch (...)
			{
				StopLocked();
				throw;
			}
		}

		const EVENT_PROPERTY_INFO* FindProperty(
		    const TRACE_EVENT_INFO& info, ULONG bytes, const wchar_t* name) const noexcept
		{
			const auto base = reinterpret_cast<const BYTE*>(&info);
			for (ULONG i = 0; i < info.TopLevelPropertyCount; ++i)
			{
				const auto& property = info.EventPropertyInfoArray[i];
				const auto offset = property.NameOffset;
				if (offset >= bytes || offset % sizeof(wchar_t))
					continue;
				const auto text = reinterpret_cast<const wchar_t*>(base + offset);
				const auto length = (bytes - offset) / sizeof(wchar_t);
				const auto end = std::wmemchr(text, L'\0', length);
				if (end && static_cast<size_t>(end - text) == std::wcslen(name) &&
				    std::wmemcmp(text, name, static_cast<size_t>(end - text)) == 0)
					return &property;
			}
			return nullptr;
		}

		bool ReadProperty(EVENT_RECORD& record, const TRACE_EVENT_INFO& info,
		    const EVENT_PROPERTY_INFO& property, void* value, ULONG capacity,
		    ULONG& bytes)
		{
			PROPERTY_DATA_DESCRIPTOR descriptor{};
			descriptor.PropertyName = reinterpret_cast<ULONGLONG>(
			    reinterpret_cast<const BYTE*>(&info) + property.NameOffset);
			descriptor.ArrayIndex = ULONG_MAX;
			bytes = 0;
			auto error = api.propertySize(&record, 0, nullptr, 1, &descriptor, &bytes);
			CheckPermission(Operation::PropertySize, error);
			if (error != ERROR_SUCCESS || !bytes || bytes > capacity)
				return false;
			error = api.property(&record, 0, nullptr, 1, &descriptor, bytes, static_cast<PBYTE>(value));
			CheckPermission(Operation::Property, error);
			return error == ERROR_SUCCESS;
		}

		static bool Scalar(const EVENT_PROPERTY_INFO& property, USHORT type) noexcept
		{
			return !(property.Flags & (PropertyStruct | PropertyParamCount | PropertyParamLength)) &&
			    property.count == 1 && property.nonStructType.InType == type;
		}

		void Decode(EVENT_RECORD& record)
		{
			if (!IsEqualGUID(record.EventHeader.ProviderId, ProcessProvider))
				return;
			const auto eventId = record.EventHeader.EventDescriptor.Id;
			// Kernel-Process lifecycle events are ProcessStart=1 and ProcessStop=2.
			if (eventId != 1 && eventId != 2)
				return;
			ULONG bytes = static_cast<ULONG>(sizeof(metadata));
			auto info = reinterpret_cast<TRACE_EVENT_INFO*>(metadata.data());
			const auto infoError = api.information(&record, 0, nullptr, info, &bytes);
			CheckPermission(Operation::Information, infoError);
			if (infoError != ERROR_SUCCESS ||
			    bytes > sizeof(metadata) || bytes < offsetof(TRACE_EVENT_INFO, EventPropertyInfoArray) ||
			    info->PropertyCount >
			        (bytes - offsetof(TRACE_EVENT_INFO, EventPropertyInfoArray)) / sizeof(EVENT_PROPERTY_INFO) ||
			    info->TopLevelPropertyCount > info->PropertyCount)
			{
				reconcile.store(true);
				return;
			}
			Event event;
			event.started = eventId == 1;
			const auto pid = FindProperty(*info, bytes, L"ProcessID");
			ULONG size = 0;
			if (!pid || !Scalar(*pid, TDH_INTYPE_UINT32) ||
			    !ReadProperty(record, *info, *pid, &event.id, sizeof(event.id), size) ||
			    size != sizeof(event.id))
			{
				reconcile.store(true);
				return;
			}
			const auto created = FindProperty(*info, bytes, L"CreateTime");
			if (created && (!Scalar(*created, TDH_INTYPE_FILETIME) ||
			    !ReadProperty(record, *info, *created, &event.created, sizeof(event.created), size) ||
			    size != sizeof(event.created)))
			{
				event.created = {};
				reconcile.store(true);
			}
			const auto image = FindProperty(*info, bytes, L"ImageName");
			bool imageRead = false;
			if (image && Scalar(*image, TDH_INTYPE_UNICODESTRING) &&
			    ReadProperty(record, *info, *image, imageBuffer.data(), sizeof(imageBuffer), size) &&
			    size % sizeof(wchar_t) == 0)
			{
				const auto length = size / sizeof(wchar_t);
				const auto end = std::wmemchr(imageBuffer.data(), L'\0', length);
				if (end && end != imageBuffer.data())
				{
					event.image.assign(imageBuffer.data(), end);
					imageRead = true;
				}
			}
			else if (image && Scalar(*image, TDH_INTYPE_ANSISTRING) &&
			    ReadProperty(record, *info, *image, imageBuffer.data(), ImageCapacity, size))
			{
				const auto text = reinterpret_cast<const char*>(imageBuffer.data());
				const auto end = static_cast<const char*>(std::memchr(text, '\0', size));
				if (end && end != text)
				{
					const auto length = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, text,
					    static_cast<int>(end - text), nullptr, 0);
					if (length > 0 && length < static_cast<int>(ImageCapacity))
					{
						event.image.resize(length);
						imageRead = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, text,
						    static_cast<int>(end - text), &event.image[0], length) == length;
						if (!imageRead)
							event.image.clear();
					}
				}
			}
			if (!imageRead)
				reconcile.store(true);
			Lock lock{queueLock};
			if (count == QueueCapacity)
			{
				reconcile.store(true);
				return;
			}
			queue[(head + count) % QueueCapacity] = std::move(event);
			++count;
		}

		static void WINAPI OnEvent(EVENT_RECORD* record) noexcept
		{
			if (!record || !record->UserContext)
				return;
			auto& state = *static_cast<State*>(record->UserContext);
			if (state.stopping.load())
				return;
			try
			{
				state.Decode(*record);
			}
			catch (const std::bad_alloc&)
			{
				state.RecordFailure(Operation::Callback, ERROR_NOT_ENOUGH_MEMORY);
			}
			catch (...)
			{
				state.RecordFailure(Operation::Callback, ERROR_UNHANDLED_EXCEPTION);
			}
		}

		static ULONG WINAPI OnBuffer(EVENT_TRACE_LOGFILEW* logfile) noexcept
		{
			if (!logfile || !logfile->Context)
				return FALSE;
			auto& state = *static_cast<State*>(logfile->Context);
			return !state.stopping.load();
		}
	};

	ProcessWatcher::ProcessWatcher() : ProcessWatcher(Api{}) {}
	ProcessWatcher::ProcessWatcher(const Api& api) : state_(std::make_unique<State>(api)) {}
	ProcessWatcher::~ProcessWatcher() noexcept { Stop(); }

	void ProcessWatcher::Start()
	{
		Lock lock{state_->lifecycleLock};
		state_->StartLocked();
	}

	void ProcessWatcher::Stop() noexcept
	{
		Lock lock{state_->lifecycleLock};
		state_->StopLocked();
	}

	std::vector<ProcessWatcher::Event> ProcessWatcher::Drain()
	{
		std::vector<Event> events;
		events.reserve(State::QueueCapacity);
		Lock lock{state_->queueLock};
		while (state_->count)
		{
			events.push_back(std::move(state_->queue[state_->head]));
			state_->head = (state_->head + 1) % State::QueueCapacity;
			--state_->count;
		}
		return events;
	}

	bool ProcessWatcher::TakeReconcileRequest()
	{
		// EVENT_TRACE_LOGFILE::EventsLost is unused; session counters report real-time loss.
		state_->QueryLoss();
		return state_->reconcile.exchange(false);
	}

	void ProcessWatcher::CheckHealth() const
	{
		const auto failure = state_->failure.load();
		if (!failure)
			return;
		const char* api = "ETW event callback";
		switch (static_cast<State::Operation>(failure >> 32))
		{
		case State::Operation::Process: api = "ProcessTrace"; break;
		case State::Operation::Close: api = "CloseTrace"; break;
		case State::Operation::Control: api = "ControlTraceW(STOP)"; break;
		case State::Operation::Information: api = "TdhGetEventInformation"; break;
		case State::Operation::PropertySize: api = "TdhGetPropertySize"; break;
		case State::Operation::Property: api = "TdhGetProperty"; break;
		case State::Operation::Callback: break;
		}
		Fail(api, static_cast<ULONG>(failure));
	}
}
