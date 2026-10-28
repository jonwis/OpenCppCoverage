#include "stdafx.h"

#include <optional>
#include <sstream>

#include "CppCoverage/Options.hpp"
#include "CppCoverage/OptionsParser.hpp"
#include "CppCoverage/ExportOptionParser.hpp"
#include "CppCoverage/IOptionParser.hpp"

namespace
{
	boost::optional<CppCoverage::Options> ParseRvaOptions(
		std::initializer_list<const char*> arguments)
	{
		std::vector<std::unique_ptr<CppCoverage::IOptionParser>> parsers;
		parsers.push_back(std::make_unique<CppCoverage::ExportOptionParser>(
			std::vector<CppCoverage::ExportPluginDescription>{}));
		CppCoverage::OptionsParser parser{nullptr, std::move(parsers)};
		std::vector<const char*> argv{"OpenCppCoverage"};
		argv.insert(argv.end(), arguments.begin(), arguments.end());
		std::wostringstream explanation;
		return parser.Parse(static_cast<int>(argv.size()), argv.data(), &explanation);
	}
}

TEST(RvaOptionsTest, SymbolFreeDefaultsToRawBinary)
{
	auto options = ParseRvaOptions({"--symbol-free", "--", "test.exe"});
	ASSERT_TRUE(options);
	ASSERT_TRUE(options->IsSymbolFreeModeEnabled());
	ASSERT_EQ(1u, options->GetExports().size());
	EXPECT_EQ(CppCoverage::OptionsExportType::Binary, options->GetExports()[0].GetType());
}

TEST(RvaOptionsTest, SymbolBasedCollectionRetainsHtmlDefault)
{
	auto options = ParseRvaOptions({"--", "test.exe"});
	ASSERT_TRUE(options);
	EXPECT_FALSE(options->IsSymbolFreeModeEnabled());
	EXPECT_FALSE(options->GetResolvePath());
	ASSERT_EQ(1u, options->GetExports().size());
	EXPECT_EQ(CppCoverage::OptionsExportType::Html, options->GetExports()[0].GetType());
}

TEST(RvaOptionsTest, CollectionRejectsReportsAndSourceFilters)
{
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--export_type", "html", "--", "test.exe"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--sources", "src", "--", "test.exe"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--unified_diff", "missing.diff", "--", "test.exe"}));
}

TEST(RvaOptionsTest, CollectionRequiresProgram)
{
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--resolve", __FILE__, "--", "test.exe"}));
}

TEST(RvaOptionsTest, ResolutionAcceptsSourceFiltersAndModuleDirectories)
{
	auto options = ParseRvaOptions({
		"--resolve", __FILE__, "--module_dir", ".", "--sources", "src",
		"--export_type", "cobertura:coverage.xml"});
	ASSERT_TRUE(options);
	EXPECT_TRUE(options->GetResolvePath());
	ASSERT_EQ(1u, options->GetModuleDirectories().size());
	EXPECT_EQ(CppCoverage::OptionsExportType::Cobertura, options->GetExports()[0].GetType());
}

TEST(RvaOptionsTest, ResolutionRejectsMissingInputAndProgram)
{
	EXPECT_FALSE(ParseRvaOptions({"--resolve", "missing-rva-input.cov"}));
	EXPECT_FALSE(ParseRvaOptions({"--resolve", __FILE__, "--", "test.exe"}));
	EXPECT_FALSE(ParseRvaOptions({"--module_dir", ".", "--", "test.exe"}));
}
