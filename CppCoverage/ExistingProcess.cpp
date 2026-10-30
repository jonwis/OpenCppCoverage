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

#include "ExistingProcess.hpp"
#include "ArchitectureBreakpoint.hpp"
#include "HandleInformation.hpp"
#include "PeImage.hpp"
#include "ProcessFilter.hpp"
#include "Tools/Log.hpp"
#include <TlHelp32.h>
#include <filesystem>
#include <wil/result.h>

namespace CppCoverage
{
	namespace
	{
		FILETIME CreationTime(HANDLE process)
		{
			FILETIME created{}, exited{}, kernel{}, user{};
			THROW_LAST_ERROR_IF(!GetProcessTimes(process, &created, &exited, &kernel, &user));
			return created;
		}

		Patterns BasenamePatterns(const Patterns& patterns)
		{
			Patterns basenames;
			for (const auto& pattern : patterns.GetSelectedPatterns())
				basenames.AddSelectedPatterns(std::filesystem::path{pattern}.filename().wstring());
			for (const auto& pattern : patterns.GetExcludedPatterns())
				if (pattern.find(L'\\') == std::wstring::npos)
					basenames.AddExcludedPatterns(pattern);
			return basenames;
		}
	}

	std::string ProcessAdmissionDiagnostic(const std::exception& error)
	{
		const auto* failure = dynamic_cast<const wil::ResultException*>(&error);
		if (failure && (failure->GetErrorCode() == E_ACCESSDENIED ||
		    failure->GetErrorCode() == HRESULT_FROM_WIN32(ERROR_PRIVILEGE_NOT_HELD)))
			return std::string{"Access denied. The process may be critical, protected, or owned by another user; "
			    "elevation does not permit debugging every protected process. "} + error.what();
		return error.what();
	}

	bool ExistingProcess::SameInstance(HANDLE process) const
	{
		const auto time = CreationTime(process);
		return GetProcessId(process) == id &&
		    time.dwLowDateTime == created.dwLowDateTime &&
		    time.dwHighDateTime == created.dwHighDateTime &&
		    CompareStringOrdinal(path.c_str(), -1,
		        HandleInformation{}.ComputeProcessFilename(process).c_str(), -1, TRUE) == CSTR_EQUAL;
	}

	void ExistingProcess::Validate() const
	{
		Validate(AdmissionChecks{});
	}

	void ExistingProcess::Validate(const AdmissionChecks& checks) const
	{
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER),
		    !SameInstance(handle.get()) || WaitForSingleObject(handle.get(), 0) != WAIT_TIMEOUT,
		    "The selected process instance exited or changed before admission");
		BOOL critical = TRUE;
		THROW_LAST_ERROR_IF_MSG(!checks.critical(handle.get(), &critical),
		    "Cannot determine whether the selected process is critical; refusing attachment");
		THROW_HR_IF_MSG(E_ACCESSDENIED, critical, "Refusing attachment to a critical process");
		BOOL debugged = TRUE;
		THROW_LAST_ERROR_IF(!checks.debugged(handle.get(), &debugged));
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BUSY), debugged,
		    "The selected process already has a debugger");
		const PeImage image{path};
		ArchitectureBreakpoint::ValidateTarget(handle.get(), image.Identity().machine);
	}

	boost::optional<ExistingProcess> InspectExistingProcess(
	    const Patterns& patterns, DWORD id, const std::wstring& image, DWORD helper,
	    const FILETIME& expectedCreation)
	{
		if (!id || id == GetCurrentProcessId() || id == helper ||
		    !ProcessFilter{BasenamePatterns(patterns)}.IsSelected(image))
			return boost::none;
		ExistingProcess candidate;
		candidate.id = id;
		candidate.handle.reset(OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, FALSE, id));
		if (!candidate.handle)
		{
			const auto error = GetLastError();
			if (error == ERROR_INVALID_PARAMETER)
				return boost::none;
			THROW_WIN32_MSG(error, "OpenProcess failed for a selected executable");
		}
		if (WaitForSingleObject(candidate.handle.get(), 0) == WAIT_OBJECT_0)
			return boost::none;
		try
		{
			candidate.path = HandleInformation{}.ComputeProcessFilename(candidate.handle.get());
			if (!ProcessFilter{patterns}.IsSelected(candidate.path))
				return boost::none;
			candidate.created = CreationTime(candidate.handle.get());
			if ((expectedCreation.dwLowDateTime || expectedCreation.dwHighDateTime) &&
			    CompareFileTime(&candidate.created, &expectedCreation) != 0)
				return boost::none;
			candidate.Validate();
		}
		catch (...)
		{
			if (WaitForSingleObject(candidate.handle.get(), 0) == WAIT_OBJECT_0)
				return boost::none;
			throw;
		}
		return std::move(candidate);
	}

	ExistingProcessSnapshot SnapshotExistingProcesses(const Patterns& patterns, DWORD helper,
	    const std::unordered_set<DWORD>& skip, std::unordered_set<DWORD>* reportedFailures)
	{
		const ProcessFilter possible{BasenamePatterns(patterns)};
		wil::unique_handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
		THROW_LAST_ERROR_IF(snapshot.get() == INVALID_HANDLE_VALUE);
		ExistingProcessSnapshot result;
		std::unordered_set<DWORD> observed;
		PROCESSENTRY32W entry{};
		entry.dwSize = sizeof(entry);
		THROW_LAST_ERROR_IF(!Process32FirstW(snapshot.get(), &entry));
		do
		{
			if (reportedFailures)
				observed.insert(entry.th32ProcessID);
			if (!entry.th32ProcessID || entry.th32ProcessID == GetCurrentProcessId() ||
			    entry.th32ProcessID == helper || skip.count(entry.th32ProcessID) ||
			    !possible.IsSelected(entry.szExeFile))
				continue;
			try
			{
				auto candidate = InspectExistingProcess(patterns, entry.th32ProcessID, entry.szExeFile, helper);
				if (candidate)
					result.processes.push_back(std::move(*candidate));
			}
			catch (const std::exception& error)
			{
				++result.failedAdmissions;
				if (!reportedFailures || reportedFailures->insert(entry.th32ProcessID).second)
					LOG_ERROR << "Process admission failed pid=" << entry.th32ProcessID
					          << " main_image=" << entry.szExeFile << ": " << ProcessAdmissionDiagnostic(error);
			}
		} while (Process32NextW(snapshot.get(), &entry));
		THROW_WIN32_IF(GetLastError(), GetLastError() != ERROR_NO_MORE_FILES);
		if (reportedFailures)
		{
			for (auto failure = reportedFailures->begin(); failure != reportedFailures->end();)
				if (!observed.count(*failure))
					failure = reportedFailures->erase(failure);
				else
					++failure;
		}
		return result;
	}
}
