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
#include <cstdint>
#include <vector>
#include "CppCoverageExport.hpp"

namespace CppCoverage
{
	class CPPCOVERAGE_DLL BreakpointJournal
	{
	public:
		struct Operations
		{
			decltype(&WriteProcessMemory) write = &WriteProcessMemory;
			decltype(&VirtualProtectEx) protect = &VirtualProtectEx;
			decltype(&FlushInstructionCache) flush = &FlushInstructionCache;
		};

		explicit BreakpointJournal(HANDLE);
		BreakpointJournal(HANDLE, Operations);
		BreakpointJournal(const BreakpointJournal&) = delete;
		BreakpointJournal& operator=(const BreakpointJournal&) = delete;
		void Write(uint64_t, const uint8_t*, size_t);
		void Rollback();
		void ForgetUnloadedRange(uint64_t, uint64_t);
		bool Empty() const noexcept { return entries_.empty(); }

	private:
		struct Entry
		{
			uint64_t address;
			DWORD protection;
			std::vector<uint8_t> before;
			std::vector<uint8_t> after;
		};
		std::vector<uint8_t> Read(uint64_t, size_t) const;
		void Put(const Entry&, const std::vector<uint8_t>&);
		HANDLE process_;
		Operations operations_;
		std::vector<Entry> entries_;
	};
}
