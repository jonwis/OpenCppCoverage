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

#include "ProcessFilter.hpp"

#include <Windows.h>
#include <algorithm>
#include <string_view>
#include <wil/result.h>

namespace CppCoverage
{
	namespace
	{
		bool Equal(std::wstring_view left, std::wstring_view right)
		{
			if (left.size() != right.size())
				return false;
			if (left.empty())
				return true;
			const auto result = CompareStringOrdinal(
			    left.data(), static_cast<int>(left.size()),
			    right.data(), static_cast<int>(right.size()), TRUE);
			THROW_LAST_ERROR_IF(!result);
			return result == CSTR_EQUAL;
		}

		std::wstring Normalize(std::wstring_view path)
		{
			if (path.size() >= 8 && Equal(path.substr(0, 8), L"\\\\?\\UNC\\"))
				return L"\\\\" + std::wstring{path.substr(8)};
			if (path.size() >= 4 && Equal(path.substr(0, 4), L"\\\\?\\"))
				path.remove_prefix(4);
			return std::wstring{path};
		}

		bool Match(std::wstring_view pattern, std::wstring_view value)
		{
			size_t p = 0, v = 0, retry = 0;
			size_t star = std::wstring_view::npos;
			while (v < value.size())
			{
				if (p < pattern.size() && pattern[p] == L'*')
				{
					star = p++;
					retry = v;
					continue;
				}
				const auto end = pattern.find(L'*', p);
				const auto length = (end == std::wstring_view::npos ? pattern.size() : end) - p;
				if (length && length <= value.size() - v &&
				    Equal(pattern.substr(p, length), value.substr(v, length)))
				{
					p += length;
					v += length;
				}
				else if (star != std::wstring_view::npos)
				{
					p = star + 1;
					v = ++retry;
				}
				else
					return false;
			}
			while (p < pattern.size() && pattern[p] == L'*')
				++p;
			return p == pattern.size();
		}

		bool AnyMatch(const Patterns::T_Patterns& patterns, const std::wstring& path)
		{
			const auto separator = path.find_last_of(L'\\');
			const std::wstring_view basename{path.data() +
			    (separator == std::wstring::npos ? 0 : separator + 1),
			    path.size() - (separator == std::wstring::npos ? 0 : separator + 1)};
			return std::any_of(patterns.begin(), patterns.end(), [&](const auto& pattern)
			{
				const auto normalized = Normalize(pattern);
				return Match(normalized, normalized.find(L'\\') == std::wstring::npos
				    ? basename : std::wstring_view{path});
			});
		}
	}

	ProcessFilter::ProcessFilter(const Patterns& patterns) : patterns_(patterns) {}

	bool ProcessFilter::IsSelected(const std::wstring& mainImagePath) const
	{
		const auto path = Normalize(mainImagePath);
		return (patterns_.GetSelectedPatterns().empty() ||
		        AnyMatch(patterns_.GetSelectedPatterns(), path)) &&
		       !AnyMatch(patterns_.GetExcludedPatterns(), path);
	}
}
