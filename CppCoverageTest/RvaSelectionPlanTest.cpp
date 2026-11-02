#include "stdafx.h"
#include "CppCoverage/RvaSelectionPlan.hpp"
#include "CppCoverage/DebugInformationEnumerator.hpp"
#include "CppCoverage/Patterns.hpp"
#include "TestCoverageConsole/TestCoverageConsole.hpp"

#include <Windows.h>
#include <algorithm>
#include <atomic>
#include <fstream>
#include <iterator>
#include <process.h>
#include <stdexcept>
#include <set>
#include <tuple>

namespace CppCoverageTest
{
	namespace
	{
		namespace cov = CppCoverage;
		namespace fs = std::filesystem;

		std::string Read(const fs::path& path)
		{
			std::ifstream input(path, std::ios::binary);
			if (!input)
				throw std::runtime_error("Cannot read test file");
			return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
		}

		void Save(const fs::path& path, const std::string& bytes)
		{
			std::ofstream out(path, std::ios::binary | std::ios::trunc);
			out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
			if (!out)
				throw std::runtime_error("Cannot write test file");
		}

		std::string Replace(std::string text, const std::string& before, const std::string& after)
		{
			const auto found = text.find(before);
			if (found == std::string::npos)
				throw std::runtime_error("Test replacement not found");
			text.replace(found, before.size(), after);
			return text;
		}

		class RvaSelectionPlanTest : public testing::Test
		{
		protected:
			void SetUp() override
			{
				static std::atomic<unsigned> next{0};
				directory_ = fs::current_path() /
					("RvaSelectionPlanTest-" + std::to_string(_getpid()) + "-" + std::to_string(next++));
				ASSERT_TRUE(fs::create_directory(directory_));
				path_ = directory_ / L"selection.json";
			}
			void TearDown() override
			{
				std::error_code error;
				fs::remove_all(directory_, error);
			}
			cov::RvaSelectionPlan Sample()
			{
				cov::RvaSelectionModule module;
				module.name = L"module-\u03bb-\U0001f600.dll";
				module.identity.machine = 0xa641;
				module.identity.timeDateStamp = 0x12345678;
				module.identity.sizeOfImage = 0x4000;
				module.identity.checksum = 0x1234;
				module.identity.pdbGuid[1] = 0xab;
				module.identity.pdbAge = 2;
				module.identity.imageHash[5] = 0xef;
				module.blocks = {{0x1000, 7, cov::InstructionSet::Amd64},
					{0x2000, 8, cov::InstructionSet::Arm64}};
				module.catalogSha256 = cov::RvaCatalogSha256(module.blocks);
				return {{module}};
			}
			void Make(const fs::path& diff, unsigned expansion = 10)
			{
				cov::MakeRvaSelectionPlan(diff, directory_, {}, cov::Patterns(), {}, expansion, path_);
			}
			std::string Explanation()
			{
				auto report = path_;
				report += L".explain.json";
				return Read(report);
			}
			fs::path directory_;
			fs::path path_;
		};

		void ExpectRegions(const std::vector<uint32_t>& lines, unsigned expansion, uint32_t count,
			const std::vector<cov::RvaSourceRegion>& expected)
		{
			const auto actual = cov::ExpandRvaSourceLines(lines, expansion, count);
			ASSERT_EQ(expected.size(), actual.size());
			for (size_t i = 0; i < expected.size(); ++i)
			{
				EXPECT_EQ(expected[i].first, actual[i].first);
				EXPECT_EQ(expected[i].last, actual[i].last);
			}
		}
	}

	TEST(RvaSourceRegions, ExpandsBeforeMerging)
	{
		ExpectRegions({33, 34, 35, 38}, 10, 100, {{23, 48}});
		ExpectRegions({33, 34, 35, 38}, 5, 100, {{28, 43}});
		ExpectRegions({38, 35, 33, 34, 33}, 0, 100, {{33, 35}, {38, 38}});
		ExpectRegions({3, 90}, 5, 100, {{1, 8}, {85, 95}});
		ExpectRegions({33, 34, 35, 38}, 10, 40, {{23, 40}});
		ExpectRegions({1, 20}, 10, 20, {{1, 20}});
	}

	TEST(RvaSourceRegions, ClampsEmptyDeletionAndOverflow)
	{
		ExpectRegions({}, 10, 100, {});
		ExpectRegions({1}, 10, 0, {});
		ExpectRegions({101}, 0, 100, {{100, 100}});
		ExpectRegions({101}, 1, 100, {{100, 100}});
		ExpectRegions({UINT32_MAX}, UINT32_MAX, UINT32_MAX, {{1, UINT32_MAX}});
		ExpectRegions({UINT32_MAX - 1}, 10, UINT32_MAX, {{UINT32_MAX - 11, UINT32_MAX}});
		EXPECT_THROW(cov::ExpandRvaSourceLines({0}, 1, 10), std::exception);
	}

	TEST(RvaSelectionBlocks, IntersectsAllCatalogBlocksAndHeaderInstances)
	{
		const std::vector<cov::BasicBlock> catalog{
			{100, 10, cov::InstructionSet::Amd64}, {110, 20, cov::InstructionSet::Amd64},
			{200, 8, cov::InstructionSet::Arm64}, {300, 8, cov::InstructionSet::Arm64}};
		const auto selected = cov::SelectRvaBlocks(catalog, {{105, 10}, {202, 2}, {302, 2}, {105, 1}});
		ASSERT_EQ(4, selected.size());
		for (size_t i = 0; i < catalog.size(); ++i)
		{
			EXPECT_EQ(catalog[i].rva, selected[i].rva);
			EXPECT_EQ(catalog[i].size, selected[i].size);
			EXPECT_EQ(catalog[i].instructionSet, selected[i].instructionSet);
		}
		EXPECT_TRUE(cov::SelectRvaBlocks(catalog, {{130, 10}, {100, 0}}).empty());
		EXPECT_THROW(cov::SelectRvaBlocks(catalog, {{UINT32_MAX, 2}}), std::exception);
	}

	TEST(RvaSelectionDigest, CanonicalBinaryTuples)
	{
		const std::vector<cov::BasicBlock> catalog{{0x1000, 7, cov::InstructionSet::Amd64},
			{0x2000, 8, cov::InstructionSet::Arm64}};
		EXPECT_EQ("4487f4171398378c3b7d0cad7248cd1fd1f90f6efc345f4ec1d817e954cd5a86",
			cov::RvaCatalogSha256(catalog));
		EXPECT_EQ(cov::RvaCatalogSha256(catalog),
			cov::RvaCatalogSha256({catalog[1], catalog[0], catalog[1]}));
		EXPECT_NE(cov::RvaCatalogSha256(catalog),
			cov::RvaCatalogSha256({{0x1000, 8, cov::InstructionSet::Amd64}, catalog[1]}));
		EXPECT_EQ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			cov::RvaCatalogSha256({}));
	}

	TEST_F(RvaSelectionPlanTest, RoundTripFullIdentityAndEmptyPlan)
	{
		const auto sample = Sample();
		cov::WriteRvaSelectionPlan(sample, path_);
		const auto loaded = cov::ReadRvaSelectionPlan(path_);
		ASSERT_EQ(1, loaded.modules.size());
		const auto* module = cov::FindRvaSelection(loaded, sample.modules[0].identity);
		ASSERT_NE(nullptr, module);
		EXPECT_EQ(sample.modules[0].name, module->name);
		EXPECT_EQ(sample.modules[0].catalogSha256, module->catalogSha256);
		ASSERT_EQ(2, module->blocks.size());
		EXPECT_EQ(0x2000, module->blocks[1].rva);
		auto different = sample.modules[0].identity;
		different.imageHash[0] ^= 1;
		EXPECT_EQ(nullptr, cov::FindRvaSelection(loaded, different));
		different = sample.modules[0].identity;
		different.pdbAge++;
		EXPECT_EQ(nullptr, cov::FindRvaSelection(loaded, different));
		different = sample.modules[0].identity;
		different.checksum++;
		EXPECT_EQ(nullptr, cov::FindRvaSelection(loaded, different));
		cov::WriteRvaSelectionPlan({}, path_);
		EXPECT_TRUE(cov::ReadRvaSelectionPlan(path_).modules.empty());
		EXPECT_EQ(nullptr, cov::FindRvaSelection({}, sample.modules[0].identity));
	}

	TEST_F(RvaSelectionPlanTest, RejectsMalformedSchemaTypesAndJson)
	{
		cov::WriteRvaSelectionPlan(Sample(), path_);
		const auto valid = Read(path_);
		const std::vector<std::string> malformed{
			Replace(valid, "\"schema\":1", "\"schema\":2"),
			Replace(valid, "\"schema\":1", "\"schema\":\"1\""),
			Replace(valid, "\"schema\":1", "\"schema\":true"),
			Replace(valid, "\"schema\":1", "\"schema\":1.0"),
			Replace(valid, "\"schema\":1", "\"schema\":01"),
			Replace(valid, "\"schema\":1", "\"schema\":-1"),
			Replace(valid, "\"schema\":1", "\"schema\":1,\"schema\":1"),
			Replace(valid, "\"schema\":1", "\"extra\":0,\"schema\":1"),
			Replace(valid, "\"size\":7", "\"size\":\"7\""),
			Replace(valid, "\"size\":7", "\"size\":false"),
			Replace(valid, "\"size\":7", "\"size\":4294967296"),
			Replace(valid, "\"size\":7", "\"size\":7,\"executed\":1"),
			Replace(valid, "\"blocks\":[", "\"blocks\":{"),
			Replace(valid, "\"name\":", "\"name\":null,\"unused\":"),
			valid + "junk", valid.substr(0, valid.size() / 2),
			"{\"schema\":1,\"modules\":[{\"name\":\"\\ud800\"}]}",
			"{\"schema\":1,\"modules\":{},\"modules\":[]}",
			"{\"schema\":1,\"modules\":[[[[[[[[[[]]]]]]]]]]}"};
		for (const auto& text : malformed)
		{
			SCOPED_TRACE(text.substr(0, 140));
			Save(path_, text);
			EXPECT_THROW(cov::ReadRvaSelectionPlan(path_), std::exception);
		}
		Save(path_, "\xef\xbb\xbf" + valid);
		EXPECT_NO_THROW(cov::ReadRvaSelectionPlan(path_));
	}

	TEST_F(RvaSelectionPlanTest, RejectsInvalidBlocksIdentityAndDigest)
	{
		const auto sample = Sample();
		cov::WriteRvaSelectionPlan(sample, path_);
		const auto valid = Read(path_);
		const std::vector<std::string> malformed{
			Replace(valid, "\"rva\":4096", "\"rva\":16384"),
			Replace(valid, "\"size\":7", "\"size\":0"),
			Replace(valid, "\"rva\":8192", "\"rva\":4096"),
			Replace(valid, "\"rva\":8192", "\"rva\":4092"),
			Replace(valid, "\"rva\":8192", "\"rva\":8193"),
			Replace(valid, "\"size\":8", "\"size\":7"),
			Replace(valid, "\"isa\":34404", "\"isa\":1"),
			Replace(valid, "\"isa\":34404", "\"isa\":65536"),
			Replace(valid, "\"machine\":42561", "\"machine\":34404"),
			Replace(valid, "\"machine\":42561", "\"machine\":65536"),
			Replace(valid, "\"sizeOfImage\":16384", "\"sizeOfImage\":0"),
			Replace(valid, sample.modules[0].catalogSha256, "not-a-digest"),
			Replace(valid, "\"pdbGuid\":\"", "\"pdbGuid\":\"g"),
			Replace(valid, "\"imageHash\":\"", "\"imageHash\":\"f")};
		for (const auto& text : malformed)
		{
			SCOPED_TRACE(text.substr(0, 140));
			Save(path_, text);
			EXPECT_THROW(cov::ReadRvaSelectionPlan(path_), std::exception);
		}
		auto duplicate = sample;
		duplicate.modules.push_back(sample.modules[0]);
		EXPECT_THROW(cov::WriteRvaSelectionPlan(duplicate, path_), std::exception);
		EXPECT_THROW(cov::FindRvaSelection(duplicate, sample.modules[0].identity), std::exception);
		auto unordered = sample;
		std::reverse(unordered.modules[0].blocks.begin(), unordered.modules[0].blocks.end());
		EXPECT_THROW(cov::WriteRvaSelectionPlan(unordered, path_), std::exception);
		auto repeatedBlock = sample;
		repeatedBlock.modules[0].blocks.insert(repeatedBlock.modules[0].blocks.begin(),
			repeatedBlock.modules[0].blocks.front());
		EXPECT_THROW(cov::WriteRvaSelectionPlan(repeatedBlock, path_), std::exception);
		auto emptyHash = sample;
		emptyHash.modules[0].identity.imageHash.fill(0);
		EXPECT_THROW(cov::WriteRvaSelectionPlan(emptyHash, path_), std::exception);
		const auto start = valid.find("\"modules\":[") + std::string("\"modules\":[").size();
		const auto moduleText = valid.substr(start, valid.rfind("]}") - start);
		Save(path_, "{\"schema\":1,\"modules\":[" + moduleText + "," + moduleText + "]}");
		EXPECT_THROW(cov::ReadRvaSelectionPlan(path_), std::exception);
	}

	TEST_F(RvaSelectionPlanTest, EnforcesInputAndCollectionBounds)
	{
		std::string modules = "{\"schema\":1,\"modules\":[";
		for (unsigned i = 0; i < 4097; ++i)
			modules += i == 0 ? "{}" : ",{}";
		Save(path_, modules + "]}");
		EXPECT_THROW(cov::ReadRvaSelectionPlan(path_), std::exception);
		cov::WriteRvaSelectionPlan(Sample(), path_);
		auto text = Read(path_);
		const auto blocksStart = text.find("\"blocks\":[") + std::string("\"blocks\":[").size();
		const auto blocksEnd = text.find(']', blocksStart);
		std::string blocks;
		blocks.reserve(750003);
		for (unsigned i = 0; i < 250001; ++i)
			blocks += i == 0 ? "{}" : ",{}";
		text.replace(blocksStart, blocksEnd - blocksStart, blocks);
		Save(path_, text);
		EXPECT_THROW(cov::ReadRvaSelectionPlan(path_), std::exception);
		{
			std::ofstream out(path_, std::ios::binary | std::ios::trunc);
			out.seekp(64 * 1024 * 1024);
			out.put('x');
		}
		EXPECT_THROW(cov::ReadRvaSelectionPlan(path_), std::exception);
	}

	TEST_F(RvaSelectionPlanTest, ReportsUnmappedSourcesAndUsesNewSideWithoutContextExpansion)
	{
		const auto source = directory_ / L"new source.hpp";
		Save(source, std::string(100, '\n'));
		const auto diff = directory_ / L"changes.diff";
		Save(diff, "\xef\xbb\xbf"
			"diff --git a/old.hpp b/new source.hpp\r\n"
			"--- a/old.hpp\r\n+++ b/new source.hpp\r\n"
			"@@ -32,5 +32,5 @@\r\n context\r\n-old\r\n+new\r\n"
			"-old\r\n+new\r\n-old\r\n+new\r\n context\r\n"
			"@@ -38 +38 @@\r\n-old\r\n+new\r\n");
		Make(diff);
		EXPECT_TRUE(cov::ReadRvaSelectionPlan(path_).modules.empty());
		const auto report = Explanation();
		EXPECT_NE(std::string::npos, report.find("\"changed\":[33,34,35,38]"));
		EXPECT_NE(std::string::npos, report.find("\"expanded\":[{\"first\":23,\"last\":48}]"));
		EXPECT_NE(std::string::npos, report.find("unmapped-source-path"));
		EXPECT_NE(std::string::npos, report.find("no-executable-lines"));
		EXPECT_NE(std::string::npos, report.find("\"completeness\":\"partial\""));
		Make(diff, 5);
		EXPECT_NE(std::string::npos, Explanation().find("\"expanded\":[{\"first\":28,\"last\":43}]"));
	}

	TEST_F(RvaSelectionPlanTest, DeletionAnchorsSurvivingNeighborsAndClampsEof)
	{
		Save(directory_ / L"new.cpp", "one\ntwo\nthree\nfour\n");
		const auto diff = directory_ / L"changes.diff";
		Save(diff, "diff --git a/old.cpp b/new.cpp\n--- a/old.cpp\n+++ b/new.cpp\n"
			"@@ -3,2 +2,0 @@\n-deleted\n-deleted\n");
		Make(diff, 0);
		EXPECT_NE(std::string::npos, Explanation().find("\"changed\":[2,3]"));
		EXPECT_NE(std::string::npos, Explanation().find("\"expanded\":[{\"first\":2,\"last\":3}]"));
		Save(diff, "diff --git a/new.cpp b/new.cpp\n--- a/new.cpp\n+++ b/new.cpp\n"
			"@@ -5 +4,0 @@\n-deleted\n");
		Make(diff, 0);
		EXPECT_NE(std::string::npos, Explanation().find("\"expanded\":[{\"first\":4,\"last\":4}]"));
	}

	TEST_F(RvaSelectionPlanTest, RejectsUnsafeMappingAndInputOverwriteWithoutArtifacts)
	{
		const auto diff = directory_ / L"changes.diff";
		Save(diff, "--- old\n+++ ..\\outside.cpp\n@@ -1 +1 @@\n-old\n+new\n");
		EXPECT_THROW(Make(diff), std::exception);
		EXPECT_FALSE(fs::exists(path_));
		Save(directory_ / L"source.cpp", "source\n");
		Save(diff, "--- source.cpp\n+++ source.cpp\n@@ -1 +1 @@\n-old\n+new\n");
		EXPECT_THROW(cov::MakeRvaSelectionPlan(diff, directory_, {}, cov::Patterns(), {}, 0, diff), std::exception);
		EXPECT_THROW(cov::MakeRvaSelectionPlan(diff, directory_, {}, cov::Patterns(), {}, 0,
			directory_ / L"source.cpp"), std::exception);
		Save(path_, "unrelated existing file");
		EXPECT_THROW(Make(diff), std::exception);
		EXPECT_EQ("unrelated existing file", Read(path_));
		EXPECT_EQ("source\n", Read(directory_ / L"source.cpp"));
		for (const auto& entry : fs::directory_iterator(directory_))
			EXPECT_EQ(std::wstring::npos, entry.path().filename().wstring().find(L".stage-"));
	}

	TEST_F(RvaSelectionPlanTest, EmptyDiffCapturesNothing)
	{
		const auto diff = directory_ / L"empty.diff";
		Save(diff, "");
		Make(diff);
		EXPECT_TRUE(cov::ReadRvaSelectionPlan(path_).modules.empty());
		EXPECT_NE(std::string::npos, Explanation().find("\"sources\":[]"));
	}

	TEST_F(RvaSelectionPlanTest, MapsQuotedUtf8DiffNamesToUnicodeCheckoutPaths)
	{
		Save(directory_ / L"new \u03bb.hpp", "\xef\xbb\xbfsource\n");
		const auto diff = directory_ / L"changes.diff";
		Save(diff, "diff --git a/old.hpp \"b/new \\316\\273.hpp\"\n"
			"--- a/old.hpp\n+++ \"b/new \\316\\273.hpp\"\n@@ -1 +1 @@\n-old\n+new\n");
		Make(diff, 0);
		EXPECT_NE(std::string::npos, Explanation().find("new \xce\xbb.hpp"));
		EXPECT_NE(std::string::npos, Explanation().find("\"expanded\":[{\"first\":1,\"last\":1}]"));
	}

	TEST_F(RvaSelectionPlanTest, RejectsInvalidSelectedImagesAndStalePdbIdentity)
	{
		const auto bin = directory_ / L"bin";
		ASSERT_TRUE(fs::create_directory(bin));
		const auto image = bin / L"orphan.exe";
		const auto diff = directory_ / L"empty.diff";
		Save(diff, "");
		Save(image, "invalid image");
		cov::Patterns patterns;
		patterns.AddSelectedPatterns(L"*orphan.exe");
		EXPECT_THROW(cov::MakeRvaSelectionPlan(diff, directory_, {bin}, patterns, {}, 0, path_), std::exception);
		EXPECT_FALSE(fs::exists(path_));
		auto bytes = Read(TestCoverageConsole::GetOutputBinaryPath());
		const auto rsds = bytes.find("RSDS");
		ASSERT_NE(std::string::npos, rsds);
		ASSERT_LT(rsds + 20, bytes.size());
		bytes[rsds + 4] ^= 0x7f;
		Save(image, bytes);
		EXPECT_THROW(cov::MakeRvaSelectionPlan(diff, directory_, {bin}, patterns, {}, 0, path_), std::exception);
		EXPECT_FALSE(fs::exists(path_));
	}

	TEST_F(RvaSelectionPlanTest, RestoresExplanationWhenPlanPublicationFails)
	{
		const auto diff = directory_ / L"changes.diff";
		Save(directory_ / L"source.cpp", "one\ntwo\n");
		Save(diff, "--- source.cpp\n+++ source.cpp\n@@ -1 +1 @@\n-old\n+new\n");
		Make(diff, 0);
		const auto previousPlan = Read(path_);
		const auto previousReport = Explanation();
		ASSERT_NE(FALSE, SetFileAttributesW(path_.c_str(), FILE_ATTRIBUTE_READONLY));
		EXPECT_THROW(Make(diff, 10), std::exception);
		EXPECT_NE(FALSE, SetFileAttributesW(path_.c_str(), FILE_ATTRIBUTE_NORMAL));
		EXPECT_EQ(previousPlan, Read(path_));
		EXPECT_EQ(previousReport, Explanation());
		for (const auto& entry : fs::directory_iterator(directory_))
			EXPECT_EQ(std::wstring::npos, entry.path().filename().wstring().find(L".stage-"));
	}

	namespace
	{
		struct FixtureSource : cov::IDebugInformationHandler
		{
			bool WantsSourceProvenance() const override { return true; }
			bool IsSourceFileSelected(const fs::path& path) override
			{
				return path.filename() == L"TestDebugInformationEnumerator.cpp";
			}
			void OnSourceFile(const fs::path& path, const std::vector<Line>&) override { source = path; }
			void OnSourceChecksum(const fs::path&, uint32_t type, const std::vector<uint8_t>& bytes) override
			{
				checksumType = type;
				checksumSize = bytes.size();
				hasChecksum = (type == 1 || type == 2 || type == 3) && !bytes.empty();
			}
			fs::path source;
			bool hasChecksum = false;
			uint32_t checksumType = 0;
			size_t checksumSize = 0;
		};
	}

	TEST_F(RvaSelectionPlanTest, ValidatesFixtureChecksumWithoutCollectingCoverage)
	{
		const auto image = TestCoverageConsole::GetOutputBinaryPath();
		FixtureSource fixture;
		cov::DebugInformationEnumerator enumerator({});
		ASSERT_TRUE(enumerator.Enumerate(image, fixture));
		ASSERT_TRUE(fixture.hasChecksum) << "Compiland source checksum unavailable: type=" <<
			fixture.checksumType << ", bytes=" << fixture.checksumSize;
		if (fixture.source.empty() || !fs::exists(fixture.source))
			GTEST_SKIP() << "Native fixture provenance unavailable: checksum type=" << fixture.checksumType <<
				", bytes=" << fixture.checksumSize << ", source=" << fixture.source.string();
		const auto local = directory_ / fixture.source.filename();
		const auto original = Read(fixture.source);
		Save(local, original);
		const auto diff = directory_ / L"changes.diff";
		Save(diff, "--- TestDebugInformationEnumerator.cpp\n+++ TestDebugInformationEnumerator.cpp\n"
			"@@ -1 +1 @@\n-old\n+new\n");
		cov::Patterns patterns;
		patterns.AddSelectedPatterns(L"*TestCoverageConsole.exe");
		std::vector<cov::SubstitutePdbSourcePath> substitutions;
		substitutions.emplace_back(fixture.source.parent_path(), fs::path(directory_));
		cov::MakeRvaSelectionPlan(diff, directory_, {image.parent_path()}, patterns, substitutions, UINT32_MAX, path_);
		const auto selected = cov::ReadRvaSelectionPlan(path_);
		ASSERT_EQ(1, selected.modules.size());
		EXPECT_FALSE(selected.modules[0].blocks.empty());
		cov::MakeRvaSelectionPlan(diff, directory_, {image.parent_path()}, patterns, substitutions, 0, path_);
		EXPECT_TRUE(cov::ReadRvaSelectionPlan(path_).modules[0].blocks.empty());
		EXPECT_NE(std::string::npos, Explanation().find("no-executable-lines-in-expanded-regions"));
		EXPECT_NE(std::string::npos, Explanation().find("verified-in-encountered-pdbs"));
		const auto previous = Read(path_);
		Save(local, original + "\r\n// stale source\r\n");
		try
		{
			cov::MakeRvaSelectionPlan(diff, directory_, {image.parent_path()}, patterns,
				substitutions, UINT32_MAX, path_);
			FAIL() << "Changed source checksum was accepted";
		}
		catch (const std::exception& error)
		{
			EXPECT_NE(std::string::npos, std::string(error.what()).find("Stale source checksum"));
		}
		EXPECT_EQ(previous, Read(path_));
	}

	TEST_F(RvaSelectionPlanTest, IncludesRealInlineHeaderLinesAfterPathSubstitution)
	{
		struct HeaderLines : cov::IDebugInformationHandler
		{
			explicit HeaderLines(bool provenance, fs::path selected = {})
				: provenance(provenance), selected(std::move(selected)) {}
			bool WantsSourceProvenance() const override { return provenance; }
			bool IsSourceFileSelected(const fs::path& path) override
			{
				return selected.empty() ? path.filename() == L"filesystem" :
					fs::weakly_canonical(path) == fs::weakly_canonical(selected);
			}
			void OnSourceFile(const fs::path& path, const std::vector<Line>& lines) override
			{
				source = path;
				for (const auto& line : lines)
					if (line.length_ != 0)
						mappings.emplace(line.lineNumber_, line.virtualAddress_, line.length_);
			}
			bool provenance;
			fs::path selected;
			fs::path source;
			std::set<std::tuple<unsigned long, int64_t, unsigned long>> mappings;
		};
		const auto image = TestCoverageConsole::GetOutputBinaryPath().parent_path() /
			L"TestCoverageOptimizedBuild.dll";
		HeaderLines ordinary(false);
		cov::DebugInformationEnumerator original({});
		ASSERT_TRUE(original.Enumerate(image, ordinary));
		ASSERT_FALSE(ordinary.source.empty());
		const auto relocatedDirectory = directory_ / L"relocated SDK";
		ASSERT_TRUE(fs::create_directory(relocatedDirectory));
		const auto relocatedSource = relocatedDirectory / ordinary.source.filename();
		std::vector<cov::SubstitutePdbSourcePath> substitutions;
		substitutions.emplace_back(ordinary.source.parent_path(), fs::path(relocatedDirectory));
		HeaderLines withInline(true, relocatedSource);
		cov::DebugInformationEnumerator relocated(substitutions);
		ASSERT_TRUE(relocated.Enumerate(image, withInline));
		EXPECT_EQ(fs::weakly_canonical(relocatedSource), fs::weakly_canonical(withInline.source));
		EXPECT_TRUE(std::includes(withInline.mappings.begin(), withInline.mappings.end(),
			ordinary.mappings.begin(), ordinary.mappings.end()));
		EXPECT_GT(withInline.mappings.size(), ordinary.mappings.size()) <<
			"Optimized fixture inline header mappings were dropped";
	}
}
