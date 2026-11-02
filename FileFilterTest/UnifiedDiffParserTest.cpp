// OpenCppCoverage is an open source code coverage for C++.
// Copyright (C) 2016 OpenCppCoverage
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

#include "FileFilter/UnifiedDiffParser.hpp"
#include "FileFilter/File.hpp"
#include "FileFilter/UnifiedDiffParserException.hpp"

#include <fstream>
#include <filesystem>

#include "Tools/Tool.hpp"

using namespace FileFilter;
namespace fs = std::filesystem;

namespace FileFilterTest
{
	namespace
	{
		//-------------------------------------------------------------------------
		const File& GetFile(
			const std::vector<File>& files,
			const fs::path& path)
		{
			auto it = std::find_if(files.begin(), files.end(),
				[&](const File& file) { return file.GetPath() == path; });
			if (it == files.end())
				throw std::runtime_error("Cannot find: " + path.string());

			return *it;
		}

		//-------------------------------------------------------------------------
		int GetSelectedLinesCount(
			const std::vector<File>& files, 
			const fs::path& path)
		{
			const auto& file = GetFile(files, path);
			return static_cast<int>(file.GetSelectedLines().size());
		}		

		//---------------------------------------------------------------------------
		void CheckEqual(const std::vector<File>& files1, const std::vector<File>& files2)
		{
			ASSERT_EQ(files1.size(), files2.size());
			for (size_t i = 0; i < files1.size(); ++i)
				ASSERT_EQ(files1[i], files2[i]);
		}

		//-------------------------------------------------------------------------
		void AssertSingleFile(
			const std::vector<File>& files,
			const std::wstring& filename,
			const std::set<int>& expectedLines)
		{
			ASSERT_EQ(1, files.size());
			const auto& file = files.at(0);
			ASSERT_EQ(filename, file.GetPath().wstring());
			EXPECT_THAT(expectedLines, testing::ContainerEq(file.GetSelectedLines()));
		}

		//---------------------------------------------------------------------
		struct UnifiedDiffParserTest : public testing::Test
		{
			//-------------------------------------------------------------------------
			std::wstring GetError(const std::wstring& diffContent) const
			{
				std::wistringstream istr{ diffContent };
				try
				{
					unifiedDiffParser_.Parse(istr);
				}
				catch (UnifiedDiffParserException& e)
				{
					auto fullMessage = Tools::LocalToWString(e.what());
					auto index = fullMessage.find('\n');

					if (index != std::string::npos)
						return fullMessage.substr(index + 1);
				}
				return L"";
			}

			//--------------------------------------------------------------------------
			static fs::path GetFullPath(const std::wstring& filename)
			{
				return fs::path(PROJECT_DIR) / L"Data" / filename;
			}

			UnifiedDiffParser unifiedDiffParser_;
			const fs::path diffPath_{ GetFullPath(L"test.diff") };
		};
	}
		
	//-------------------------------------------------------------------------
	TEST_F(UnifiedDiffParserTest, ExpectedFiles)
	{
		std::wifstream diffFile{ diffPath_.string() };
		auto files = unifiedDiffParser_.Parse(diffFile);
		
		ASSERT_EQ(1, GetSelectedLinesCount(files, "CppCoverage/CodeCoverageRunner.cpp"));
		ASSERT_EQ(3, GetSelectedLinesCount(files, "CppCoverage/CoverageData.cpp"));
		ASSERT_EQ(2, GetSelectedLinesCount(files, "CppCoverage/CoverageData.hpp"));
		ASSERT_EQ(14, GetSelectedLinesCount(files, "CppCoverage/ExecutedAddressManager.cpp"));
		ASSERT_EQ(6, GetSelectedLinesCount(files, "CppCoverage/ExecutedAddressManager.hpp"));
		ASSERT_EQ(4, GetSelectedLinesCount(files, "CppCoverageTest/CodeCoverageRunnerTest.cpp"));
		ASSERT_EQ(4, GetSelectedLinesCount(files, "CppCoverageTest/ExecutedAddressManagerTest.cpp"));
		ASSERT_EQ(0, GetSelectedLinesCount(files, "TestHelper/Container.hpp"));
		ASSERT_EQ(0, GetSelectedLinesCount(files, "TestHelper/Container.inl"));
		ASSERT_EQ(0, GetSelectedLinesCount(files, "TestHelper/CoverageDataComparer.cpp"));
		ASSERT_EQ(0, GetSelectedLinesCount(files, "TestHelper/CoverageDataComparer.hpp"));
	}

	//-------------------------------------------------------------------------
	TEST_F(UnifiedDiffParserTest, ExpectedUpdatedLines)
	{
		std::wifstream diffFile{ diffPath_.string() };
		auto files = unifiedDiffParser_.Parse(diffFile);

		const auto& file = GetFile(files, "CppCoverage/ExecutedAddressManager.cpp");
		const auto& lines = file.GetSelectedLines();
		const std::set<int> expectedLines =
				{93, 95, 105, 130, 132, 133, 134, 154, 155, 156, 158, 159, 160, 162};

		ASSERT_EQ(expectedLines, lines);
	}
	
	//-------------------------------------------------------------------------
	TEST_F(UnifiedDiffParserTest, ErrorNoFilenameBeforeHunks)
	{
		ASSERT_EQ(UnifiedDiffParserException::ErrorNoFilenameBeforeHunks,
			GetError(L"@@"));
	}
	
	//-------------------------------------------------------------------------
	TEST_F(UnifiedDiffParserTest, ErrorCannotReadLine)
	{
		ASSERT_EQ(UnifiedDiffParserException::ErrorCannotReadLine,
			GetError(UnifiedDiffParser::FromFilePrefix));
	}
	
	//-------------------------------------------------------------------------
	TEST_F(UnifiedDiffParserTest, ErrorExpectFromFilePrefix)
	{
		ASSERT_EQ(UnifiedDiffParserException::ErrorExpectFromFilePrefix,
			GetError(UnifiedDiffParser::FromFilePrefix + L"\nXXX"));
	}
	
	//-------------------------------------------------------------------------
	TEST_F(UnifiedDiffParserTest, ErrorInvalidHunks)
	{
		ASSERT_EQ(UnifiedDiffParserException::ErrorInvalidHunks,
			GetError(UnifiedDiffParser::FromFilePrefix + L"\n+++ \n@@ -1,2 +3,X"));
	}

	//-------------------------------------------------------------------------
	TEST_F(UnifiedDiffParserTest, ErrorContextHunks)
	{
		ASSERT_EQ(UnifiedDiffParserException::ErrorContextHunks,
			GetError(UnifiedDiffParser::FromFilePrefix + L"\n+++ \n@@ -1,2 +3,4 @@\n"));
	}

	//-------------------------------------------------------------------------
	TEST_F(UnifiedDiffParserTest, FromFileModificationTime)
	{
		std::wistringstream istr{ L"--- foo\t2002-02-21 23:30:39.942229878 -0800\n"
								  L"+++ bar\t2002-02 - 21 23:30 : 50.442260588 - 0800\n"
								  L"@@ -1,0 +1,0 @@" };
		auto files = unifiedDiffParser_.Parse(istr);

		ASSERT_EQ(1, files.size());
		ASSERT_EQ(L"bar", files.at(0).GetPath().wstring());
	}

	//-------------------------------------------------------------------------
	TEST_F(UnifiedDiffParserTest, GitDiff)
	{
		std::wifstream diffFile{ diffPath_.wstring() };
		auto files = unifiedDiffParser_.Parse(diffFile);

		std::wifstream gitDiffFile{ GetFullPath(L"test_git.diff").wstring() };
		auto gitFiles = unifiedDiffParser_.Parse(gitDiffFile);

		CheckEqual(files, gitFiles);
	}

	//-------------------------------------------------------------------------
	TEST_F(UnifiedDiffParserTest, FileRemoved)
	{
		std::wifstream diffFile{ GetFullPath(L"test_remove.diff").wstring() };
		auto files = unifiedDiffParser_.Parse(diffFile);

		ASSERT_TRUE(files.empty());
	}

	//-------------------------------------------------------------------------
	TEST_F(UnifiedDiffParserTest, FileAdded)
	{
		std::wifstream diffFile{ GetFullPath(L"test_add.diff").wstring() };
		auto files = unifiedDiffParser_.Parse(diffFile);

		GetFile(files, "FileFilter/stdafx.h");		
	}

	//-------------------------------------------------------------------------
	TEST_F(UnifiedDiffParserTest, NoRange)
	{		
		std::wistringstream istr{	L"--- a/test\n"
									L"+++ b/test\n"
									L"@@ -1 +1 @@ Something\n"
									L"- something\n"
									L"\\ No newline at end of file\n"
									L"+ something\n"
									L"\\ No newline at end of file\n"};
		auto files = unifiedDiffParser_.Parse(istr);
		AssertSingleFile(files, L"b/test", { 1 });
	}
	
	//-------------------------------------------------------------------------
	TEST_F(UnifiedDiffParserTest, FromRangeZero)
	{
		std::wistringstream istr{	
			L"--- test1.txt\n"
			L"+++ test2.txt\n"
			L"@@ -0,0 +1 @@\n"
			L"+ test\n"
			L"\\ No newline at end of file\n" };
		auto files = unifiedDiffParser_.Parse(istr);
		AssertSingleFile(files, L"test2.txt", { 1 });
	}

	//-------------------------------------------------------------------------
	TEST_F(UnifiedDiffParserTest, ToRangeZero)
	{
		std::wistringstream istr{ 
			L"--- test2.txt\n"
			L"+++ test1.txt\n"
			L"@@ -1 +0,0 @@\n"
			L"- test\n"
			L"\\ No newline at end of file\n" };
		auto files = unifiedDiffParser_.Parse(istr);
		AssertSingleFile(files, L"test1.txt", {});
	}

	TEST_F(UnifiedDiffParserTest, NewSideDeletionAnchorsWithoutChangingDefault)
	{
		const std::wstring diff = L"--- old.cpp\n+++ new.cpp\n"
			L"@@ -3,2 +2,0 @@\n-deleted\n-deleted\n";
		std::wistringstream added(diff), changed(diff);
		AssertSingleFile(unifiedDiffParser_.Parse(added), L"new.cpp", {});
		AssertSingleFile(unifiedDiffParser_.Parse(changed,
			UnifiedDiffParser::Mode::NewSideChanges), L"new.cpp", {2, 3});
	}

	TEST_F(UnifiedDiffParserTest, ReplacementsUseAddedLinesAndNotContextOrDeletionAnchors)
	{
		std::wistringstream diff(L"--- old.cpp\n+++ new.cpp\n"
			L"@@ -32,5 +32,5 @@\n context\n-old\n-old\n-old\n"
			L"+new\n+new\n+new\n context\n");
		AssertSingleFile(unifiedDiffParser_.Parse(diff, UnifiedDiffParser::Mode::NewSideChanges),
			L"new.cpp", {33, 34, 35});
	}

	TEST_F(UnifiedDiffParserTest, QuotedGitUtf8AndRenamedNewPath)
	{
		std::wistringstream diff(L"\ufeffdiff --git \"a/old name.cpp\" \"b/new \\316\\273.cpp\"\r\n"
			L"--- \"a/old name.cpp\"\r\n+++ \"b/new \\316\\273.cpp\"\r\n"
			L"@@ -1 +1 @@\r\n-old\r\n+new\r\n");
		AssertSingleFile(unifiedDiffParser_.Parse(diff, UnifiedDiffParser::Mode::NewSideChanges),
			L"new \u03bb.cpp", {1});
	}

	TEST_F(UnifiedDiffParserTest, WindowsPathWithSpaces)
	{
		std::wistringstream diff(L"--- C:\\old source\\old.cpp\n"
			L"+++ C:\\new source\\new.cpp\n@@ -1 +1 @@\n-old\n+new\n");
		AssertSingleFile(unifiedDiffParser_.Parse(diff, UnifiedDiffParser::Mode::NewSideChanges),
			L"C:\\new source\\new.cpp", {1});
	}

	TEST_F(UnifiedDiffParserTest, RemovedFileHasNoNewSideSelection)
	{
		std::wistringstream diff(L"diff --git a/old.cpp b/old.cpp\n"
			L"--- a/old.cpp\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-one\n-two\n");
		EXPECT_TRUE(unifiedDiffParser_.Parse(diff, UnifiedDiffParser::Mode::NewSideChanges).empty());
	}

	TEST_F(UnifiedDiffParserTest, RejectsOverflowAndTruncatedOldSide)
	{
		std::wistringstream overflow(L"--- old\n+++ new\n@@ -1 +2147483647,2 @@\n+a\n+b\n");
		EXPECT_THROW(unifiedDiffParser_.Parse(overflow, UnifiedDiffParser::Mode::NewSideChanges), std::exception);
		std::wistringstream truncated(L"--- old\n+++ new\n@@ -1,2 +0,0 @@\n-one\n");
		EXPECT_THROW(unifiedDiffParser_.Parse(truncated, UnifiedDiffParser::Mode::NewSideChanges), std::exception);
	}
}