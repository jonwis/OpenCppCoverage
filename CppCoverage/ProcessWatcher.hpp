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

#pragma once

#include <Windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <memory>
#include <string>
#include <vector>
#include "CppCoverageExport.hpp"

namespace CppCoverage
{
	class CPPCOVERAGE_DLL ProcessWatcher
	{
	public:
		struct Event
		{
			DWORD id = 0;
			bool started = false;
			FILETIME created{};
			std::wstring image;
		};

		struct Api
		{
			decltype(&StartTraceW) start = &StartTraceW;
			decltype(&EnableTraceEx2) enable = &EnableTraceEx2;
			decltype(&OpenTraceW) open = &OpenTraceW;
			decltype(&ProcessTrace) process = &ProcessTrace;
			decltype(&CloseTrace) close = &CloseTrace;
			decltype(&ControlTraceW) control = &ControlTraceW;
			decltype(&TdhGetEventInformation) information = &TdhGetEventInformation;
			decltype(&TdhGetPropertySize) propertySize = &TdhGetPropertySize;
			decltype(&TdhGetProperty) property = &TdhGetProperty;
		};

		ProcessWatcher();
		explicit ProcessWatcher(const Api&);
		~ProcessWatcher() noexcept;
		ProcessWatcher(const ProcessWatcher&) = delete;
		ProcessWatcher& operator=(const ProcessWatcher&) = delete;

		void Start();
		void Stop() noexcept;
		std::vector<Event> Drain();
		bool TakeReconcileRequest();
		void CheckHealth() const;

	private:
		struct State;
		std::unique_ptr<State> state_;
	};
}
