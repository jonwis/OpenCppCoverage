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
#include <wil/resource.h>
#include <string>
#include <vector>
#include "CppCoverageExport.hpp"

namespace CppCoverage
{
	class Patterns;
	struct CPPCOVERAGE_DLL ExistingProcess
	{
		struct AdmissionChecks
		{
			decltype(&IsProcessCritical) critical = &IsProcessCritical;
			decltype(&CheckRemoteDebuggerPresent) debugged = &CheckRemoteDebuggerPresent;
		};
		ExistingProcess() = default;
		ExistingProcess(ExistingProcess&&) = default;
		ExistingProcess& operator=(ExistingProcess&&) = default;
		ExistingProcess(const ExistingProcess&) = delete;
		ExistingProcess& operator=(const ExistingProcess&) = delete;
		DWORD id = 0;
		FILETIME created{};
		std::wstring path;
		wil::unique_handle handle;
		bool SameInstance(HANDLE) const;
		void Validate() const;
		void Validate(const AdmissionChecks&) const;
	};

	struct CPPCOVERAGE_DLL ExistingProcessSnapshot
	{
		ExistingProcessSnapshot() = default;
		ExistingProcessSnapshot(ExistingProcessSnapshot&&) = default;
		ExistingProcessSnapshot& operator=(ExistingProcessSnapshot&&) = default;
		ExistingProcessSnapshot(const ExistingProcessSnapshot&) = delete;
		ExistingProcessSnapshot& operator=(const ExistingProcessSnapshot&) = delete;
		std::vector<ExistingProcess> processes;
		size_t failedAdmissions = 0;
	};

	CPPCOVERAGE_DLL ExistingProcessSnapshot SnapshotExistingProcesses(
	    const Patterns&, DWORD ownedHelper);
}
