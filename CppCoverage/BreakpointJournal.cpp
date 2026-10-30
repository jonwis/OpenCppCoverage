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

#include "BreakpointJournal.hpp"
#include <algorithm>
#include <wil/resource.h>
#include <wil/result.h>

namespace CppCoverage
{
	BreakpointJournal::BreakpointJournal(HANDLE process)
	    : BreakpointJournal(process, Operations{}) {}

	BreakpointJournal::BreakpointJournal(HANDLE process, Operations operations)
	    : process_{process}, operations_{operations} {}

	std::vector<uint8_t> BreakpointJournal::Read(uint64_t address, size_t size) const
	{
		std::vector<uint8_t> bytes(size);
		SIZE_T count = 0;
		THROW_LAST_ERROR_IF(!ReadProcessMemory(process_,
		    reinterpret_cast<void*>(address), bytes.data(), size, &count));
		THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_PARTIAL_COPY), count != size);
		return bytes;
	}

	void BreakpointJournal::Put(const Entry& entry, const std::vector<uint8_t>& bytes)
	{
		auto address = reinterpret_cast<void*>(entry.address);
		DWORD previous = 0;
		THROW_LAST_ERROR_IF(!operations_.protect(process_, address, bytes.size(),
		    PAGE_EXECUTE_READWRITE | PAGE_TARGETS_NO_UPDATE, &previous));
		const DWORD protection = entry.protection |
		    ((entry.protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
		      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) ? PAGE_TARGETS_NO_UPDATE : 0);
		auto restore = wil::scope_exit([&] {
			DWORD ignored = 0;
			LOG_IF_WIN32_BOOL_FALSE(operations_.protect(
			    process_, address, bytes.size(), protection, &ignored));
		});
		SIZE_T count = 0;
		const BOOL written = operations_.write(
		    process_, address, bytes.data(), bytes.size(), &count);
		const DWORD error = GetLastError();
		DWORD ignored = 0;
		THROW_LAST_ERROR_IF(!operations_.protect(
		    process_, address, bytes.size(), protection, &ignored));
		restore.release();
		THROW_WIN32_IF(error, !written);
		THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_PARTIAL_COPY), count != bytes.size());
		THROW_LAST_ERROR_IF(!operations_.flush(process_, address, bytes.size()));
		THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
		    Read(entry.address, bytes.size()) != bytes);
		MEMORY_BASIC_INFORMATION memory{};
		THROW_LAST_ERROR_IF(!VirtualQueryEx(process_, address, &memory, sizeof(memory)));
		THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), memory.Protect != entry.protection);
	}

	void BreakpointJournal::Write(uint64_t address, const uint8_t* bytes, size_t size)
	{
		THROW_HR_IF(E_INVALIDARG, !bytes || !size);
		MEMORY_BASIC_INFORMATION memory{};
		THROW_LAST_ERROR_IF(!VirtualQueryEx(
		    process_, reinterpret_cast<void*>(address), &memory, sizeof(memory)));
		const auto base = reinterpret_cast<uint64_t>(memory.BaseAddress);
		THROW_HR_IF(HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
		    memory.State != MEM_COMMIT || address < base ||
		    address - base >= memory.RegionSize || size > memory.RegionSize - (address - base));
		Entry entry{address, memory.Protect, Read(address, size), {bytes, bytes + size}};
		// Record intent before the first protection or byte mutation.
		entries_.push_back(std::move(entry));
		Put(entries_.back(), entries_.back().after);
	}

	void BreakpointJournal::Rollback()
	{
		while (!entries_.empty())
		{
			const auto& entry = entries_.back();
			const auto current = Read(entry.address, entry.before.size());
			for (size_t i = 0; i < current.size(); ++i)
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
				    current[i] != entry.before[i] && current[i] != entry.after[i],
				    "External code changed outside the breakpoint journal; retaining debugger ownership");
			Put(entry, entry.before);
			entries_.pop_back();
		}
	}

	void BreakpointJournal::ForgetUnloadedRange(uint64_t base, uint64_t size)
	{
		entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
		    [&](const Entry& entry) {
			    return entry.address >= base && entry.address - base < size;
		    }), entries_.end());
	}
}
