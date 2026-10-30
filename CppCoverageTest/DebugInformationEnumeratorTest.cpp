// OpenCppCoverage is an open source code coverage for C++.
// Copyright (C) 2017 OpenCppCoverage
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

#include <fstream>

#include "CppCoverage/DebugInformationEnumerator.hpp"
#include "TestCoverageConsole/TestDebugInformationEnumerator.hpp"
#include "TestCoverageConsole/TestCoverageConsole.hpp"

namespace CppCoverageTest
{
	namespace
	{
		struct DebugInformationHandlerMock
		    : CppCoverage::IDebugInformationHandler
		{
			//--------------------------------------------------------------------------
			explicit DebugInformationHandlerMock(
			    const std::filesystem::path& selectedFilename)
			    : selectedFilename_{selectedFilename}
			{
			}

			//--------------------------------------------------------------------------
			bool IsSourceFileSelected(
			    const std::filesystem::path& sourceFile) override
			{
				return selectedFilename_ == sourceFile.filename();
			}

			//--------------------------------------------------------------------------
			void OnSourceFile(const std::filesystem::path& path,
			                  const std::vector<Line>& lines) override
			{
				selectedFullPath_ = path;
				for (const auto& line : lines)
					lines_.push_back(line.lineNumber_);
			}

			const std::filesystem::path selectedFilename_;
			std::filesystem::path selectedFullPath_;
			std::vector<int> lines_;
		};

		//---------------------------------------------------------------------------
		std::vector<int>
		GetLineNumbersWithTag(const std::filesystem::path& path,
		                      const std::wstring& tag)
		{
			std::vector<int> lines;
			std::wifstream ifs(path.wstring());
			std::wstring line;

			for (int lineNumber = 1; std::getline(ifs, line); ++lineNumber)
			{
				if (line.find(tag) != std::wstring::npos)
					lines.push_back(lineNumber);
			}

			return lines;
		}
	}

	//-------------------------------------------------------------------------
	TEST(DebugInformationEnumeratorTest, Enumerate)
	{
		auto selectedPath =
		    TestCoverageConsole::GetDebugInformationEnumeratorTestPath();
		DebugInformationHandlerMock debugInformationHandler{
		    selectedPath.filename()};

		CppCoverage::DebugInformationEnumerator debugInformationEnumerator{ {} };

		auto binary = TestCoverageConsole::GetOutputBinaryPath();
		ASSERT_TRUE(debugInformationEnumerator.Enumerate(
		    binary, debugInformationHandler));

		auto lineWithDebugInfo = GetLineNumbersWithTag(
		    debugInformationHandler.selectedFullPath_, L"@DebugInfoExpected");

		ASSERT_EQ(debugInformationHandler.lines_, lineWithDebugInfo);
	}

	//-------------------------------------------------------------------------
	TEST(DebugInformationEnumeratorTest, SubstituteSourceDirectory)
	{
		DebugInformationHandlerMock original{
		    TestCoverageConsole::GetDebugInformationEnumeratorTestPath()};
		CppCoverage::DebugInformationEnumerator unmodified{{}};
		ASSERT_TRUE(unmodified.Enumerate(
		    TestCoverageConsole::GetOutputBinaryPath(), original));
		const auto selectedPath = original.selectedFullPath_;
		ASSERT_FALSE(selectedPath.empty());
		const auto directory = selectedPath.parent_path().wstring();
		const std::filesystem::path localRoot{L"C:\\mapped-sources"};
		for (const auto& prefix : {directory, directory + L"\\"})
		{
			SCOPED_TRACE(prefix);
			std::vector<CppCoverage::SubstitutePdbSourcePath> substitutions;
			substitutions.emplace_back(
			    std::filesystem::path{prefix}, std::filesystem::path{localRoot});
			CppCoverage::DebugInformationEnumerator enumerator{substitutions};
			DebugInformationHandlerMock handler{selectedPath.filename()};
			ASSERT_TRUE(enumerator.Enumerate(
			    TestCoverageConsole::GetOutputBinaryPath(), handler));
			ASSERT_EQ(localRoot / selectedPath.filename(), handler.selectedFullPath_);
		}
	}

	//-------------------------------------------------------------------------
	TEST(DebugInformationEnumeratorTest, DoNotSubstitutePartialSourceDirectory)
	{
		DebugInformationHandlerMock original{
		    TestCoverageConsole::GetDebugInformationEnumeratorTestPath()};
		CppCoverage::DebugInformationEnumerator unmodified{{}};
		ASSERT_TRUE(unmodified.Enumerate(
		    TestCoverageConsole::GetOutputBinaryPath(), original));
		const auto selectedPath = original.selectedFullPath_;
		auto directoryPrefix = selectedPath.parent_path().wstring();
		ASSERT_FALSE(directoryPrefix.empty());
		directoryPrefix.pop_back();
		std::vector<CppCoverage::SubstitutePdbSourcePath> substitutions;
		substitutions.emplace_back(
		    std::filesystem::path{directoryPrefix},
		    std::filesystem::path{L"C:\\mapped-sources"});
		CppCoverage::DebugInformationEnumerator enumerator{substitutions};
		DebugInformationHandlerMock handler{selectedPath.filename()};
		ASSERT_TRUE(enumerator.Enumerate(
		    TestCoverageConsole::GetOutputBinaryPath(), handler));
		ASSERT_EQ(selectedPath, handler.selectedFullPath_);
	}
}