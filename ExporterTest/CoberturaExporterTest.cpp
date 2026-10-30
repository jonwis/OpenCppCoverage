// OpenCppCoverage is an open source code coverage for C++.
// Copyright (C) 2014 OpenCppCoverage
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

#include <filesystem>
#include <fstream>
#include <regex>

#include <boost/algorithm/string.hpp>
#include <boost/property_tree/xml_parser.hpp>

#include "Plugin/Exporter/CoverageData.hpp"
#include "Plugin/Exporter/ModuleCoverage.hpp"
#include "Plugin/Exporter/FileCoverage.hpp"

#include "Exporter/InvalidOutputFileException.hpp"
#include "Exporter/CoberturaExporter.hpp"
#include "tools/Tool.hpp"

#include "TestHelper/TemporaryPath.hpp"

namespace fs = std::filesystem;

namespace ExporterTest
{
	namespace
	{
		//-------------------------------------------------------------------------
		std::wstring GetExpectedResult()
		{
			fs::path expectedResult = fs::path(PROJECT_DIR) / "Data" / "CoberturaExporterExpectedResult.xml";
			std::wifstream ifs{ expectedResult.wstring().c_str() };
			std::wostringstream ostr;

			ostr << ifs.rdbuf();

			return ostr.str();
		}
	}
	
	//-------------------------------------------------------------------------
	TEST(CoberturaExporterTest, Export)
	{
		Plugin::CoverageData coverageData{L"", 0};

		coverageData.AddModule(L"EmptyModule");
		auto& module = coverageData.AddModule(L"Module");

		module.AddFile("EmptyFile");
		auto& file = module.AddFile("File");

		file.AddLine(0, true);
		file.AddLine(1, false);

		module.AddFile("File2").AddLine(0, true);

		std::wostringstream ostr;
		Exporter::CoberturaExporter().Export(coverageData, ostr);
		auto result = ostr.str();
		std::wregex regex(LR"(timestamp="\d*")");
		result = std::regex_replace(result, regex, L"timestamp=\"TIMESTAMP\"");

		auto expectedResult = GetExpectedResult();				
		
		ASSERT_EQ(result, expectedResult);
	}	

	//-------------------------------------------------------------------------
	TEST(CoberturaExporterTest, SubFolderDoesNotExist)
	{
		Plugin::CoverageData coverageData{ L"", 0 };
		TestHelper::TemporaryPath output;
		auto outputPath = output.GetPath() / "SubFolder" / "output.xml";

		ASSERT_FALSE(Tools::FileExists(outputPath));
		Exporter::CoberturaExporter().Export(coverageData, outputPath);
		ASSERT_TRUE(Tools::FileExists(outputPath));
	}

	TEST(CoberturaExporterTest, VisualStudioPreservesSourcePathsAndFileLines)
	{
		Plugin::CoverageData coverageData{L"", 0};
		auto& module = coverageData.AddModule(L"C:\\bin\\sample.dll");
		module.AddFile(L"C:\\source\\same.cpp").AddLine(10, true);
		module.AddFile(L"D:\\source\\same.cpp").AddLine(20, false);
		module.AddFile(L"\\\\server\\share\\source.cpp").AddLine(30, true);

		std::wstringstream stream;
		Exporter::CoberturaExporter(true).Export(coverageData, stream);
		boost::property_tree::wptree tree;
		boost::property_tree::read_xml(stream, tree);
		const auto& package = tree.get_child(L"coverage.packages.package");
		EXPECT_EQ(package.get<std::wstring>(L"<xmlattr>.name"),
			L"sample.dll [module 1].coverage-module");
		EXPECT_EQ(tree.get<std::wstring>(L"coverage.sources.source"), L"");
		size_t index = 0;
		const std::wstring paths[] = {L"C:\\source\\same.cpp",
			L"D:\\source\\same.cpp", L"\\\\server\\share\\source.cpp"};
		for (const auto& entry : package.get_child(L"classes"))
		{
			const auto& file = entry.second;
			EXPECT_EQ(file.get<std::wstring>(L"<xmlattr>.filename"), paths[index]);
			EXPECT_EQ(file.get<std::wstring>(L"methods.method.<xmlattr>.name"),
				L"[file-level coverage]");
			const auto& line = file.get_child(L"lines.line");
			const auto& methodLine = file.get_child(L"methods.method.lines.line");
			EXPECT_EQ(line.get<unsigned>(L"<xmlattr>.number"), (index + 1) * 10);
			EXPECT_EQ(methodLine.get<unsigned>(L"<xmlattr>.number"),
				line.get<unsigned>(L"<xmlattr>.number"));
			EXPECT_EQ(methodLine.get<unsigned>(L"<xmlattr>.hits"), index == 1 ? 0u : 1u);
			++index;
		}
		EXPECT_EQ(index, 3u);
	}

	TEST(CoberturaExporterTest, VisualStudioDistinguishesSameModuleBasename)
	{
		Plugin::CoverageData coverageData{L"", 0};
		coverageData.AddModule(L"C:\\one\\sample.dll").AddFile(L"same.cpp").AddLine(1, true);
		coverageData.AddModule(L"D:\\two\\sample.dll").AddFile(L"same.cpp").AddLine(1, false);
		std::wostringstream stream;
		Exporter::CoberturaExporter(true).Export(coverageData, stream);
		EXPECT_NE(stream.str().find(L"sample.dll [module 1].coverage-module"), std::wstring::npos);
		EXPECT_NE(stream.str().find(L"sample.dll [module 2].coverage-module"), std::wstring::npos);
	}

	//-------------------------------------------------------------------------
	TEST(CoberturaExporterTest, SpecialChars)
	{
		Plugin::CoverageData coverageData{ L"", 0 };
		coverageData.AddModule(L"יא").AddFile(L"יא").AddLine(0, true);
		
		std::wostringstream ostr;
		Exporter::CoberturaExporter().Export(coverageData, ostr);
		auto result = ostr.str();

		auto packageName = Tools::LocalToWString(u8"package name=\"יא\"");
		auto name = Tools::LocalToWString(u8"class name=\"יא\"");
		auto filename = Tools::LocalToWString(u8"filename=\"יא\"");

		ASSERT_TRUE(boost::algorithm::contains(result, packageName));
		ASSERT_TRUE(boost::algorithm::contains(result, name));
		ASSERT_TRUE(boost::algorithm::contains(result, filename));
	}

	//-------------------------------------------------------------------------
	TEST(CoberturaExporterTest, OutputExists)
	{
		Plugin::CoverageData coverageData{ L"", 0 };
		TestHelper::TemporaryPath outputPath{ TestHelper::TemporaryPathOption::CreateAsFile };
		
		ASSERT_NO_THROW(Exporter::CoberturaExporter().Export(coverageData, outputPath));
	}

	//-------------------------------------------------------------------------
	TEST(CoberturaExporterTest, InvalidFile)
	{
		Plugin::CoverageData coverageData{L"", 0};
		TestHelper::TemporaryPath outputPath{
		    TestHelper::TemporaryPathOption::CreateAsFolder};

		ASSERT_THROW(Exporter::CoberturaExporter().Export(
		                 coverageData, outputPath.GetPath() / "InvalidFile/"),
		             Exporter::InvalidOutputFileException);
	}
}