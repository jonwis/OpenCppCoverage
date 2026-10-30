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
#include <map>
#include "CppCoverageExport.hpp"

namespace CppCoverage
{
	class CPPCOVERAGE_DLL ThreadSuspension
	{
	public:
		ThreadSuspension() = default;
		ThreadSuspension(const ThreadSuspension&) = delete;
		ThreadSuspension& operator=(const ThreadSuspension&) = delete;
		void Hold(HANDLE);
		void HoldProcess(DWORD);
		void Fence();
		void Resume();
		bool Contains(DWORD) const;

	private:
		struct Thread
		{
			wil::unique_handle handle;
			FILETIME created{};
			bool ownedIncrement = false;
		};
		void Fence(Thread&);
		std::map<DWORD, Thread> threads_;
	};
}
