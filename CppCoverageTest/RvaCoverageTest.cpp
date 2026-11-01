#include "stdafx.h"

#include <wil/result.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <map>
#include <process.h>
#include <stdexcept>
#include <Windows.h>

#include "CppCoverage/RvaCoverage.hpp"
#include "CppCoverage/RvaCoverageResolver.hpp"
#include "CppCoverage/RvaCoverageRunner.hpp"
#include "CppCoverage/DebugInformationEnumerator.hpp"
#include "CppCoverage/CfgReport.hpp"
#include <boost/property_tree/json_parser.hpp>
#include <set>
#include <tuple>
#include "Plugin/Exporter/FileCoverage.hpp"
#include "Plugin/Exporter/ModuleCoverage.hpp"
#include "Tools/Tool.hpp"

namespace CppCoverageTest
{
	namespace
	{
		namespace cov = CppCoverage;
		namespace fs = std::filesystem;

		fs::path CurrentExecutable()
		{
			std::wstring path(32768, L'\0');
			const auto size = GetModuleFileNameW(
			    nullptr, &path[0], static_cast<DWORD>(path.size()));
			if (size == 0 || size == path.size())
				throw std::runtime_error("Cannot locate test executable");
			path.resize(size);
			return path;
		}

		class RvaCoverageTest : public testing::Test
		{
		  protected:
			void SetUp() override
			{
				static std::atomic<unsigned int> next{0};
				directory_ = fs::current_path() /
				    ("RvaCoverageTest-" + std::to_string(_getpid()) + "-" +
				     std::to_string(next++));
				ASSERT_TRUE(fs::create_directory(directory_));
				path_ = directory_ / L"raw.cov";
			}

			void TearDown() override
			{
				std::error_code error;
				fs::remove_all(directory_, error);
			}

			cov::RvaCoverage Sample()
			{
				cov::RvaCoverage coverage;
				coverage.name = L"capture \u03bb \U0001f600";
				coverage.exitCode = -42;
				cov::RvaModule module;
				module.path = L"C:\\binaries\\\u03bb.dll";
				module.identity.machine = 0x8664;
				module.identity.timeDateStamp = 0x12345678;
				module.identity.sizeOfImage = 0x4000;
				module.identity.checksum = 0xabcdef01;
				module.identity.pdbGuid[0] = 0x23;
				module.identity.pdbGuid[15] = 0x45;
				module.identity.pdbAge = 7;
				module.identity.imageHash[0] = 0x67;
				module.identity.imageHash[31] = 0x89;
				module.blocks.push_back(
				    {{0x1000, 7, cov::InstructionSet::Amd64}, true});
				module.blocks.push_back(
				    {{0x2000, 8, cov::InstructionSet::Arm64}, false});
				coverage.modules.push_back(std::move(module));
				return coverage;
			}

			std::vector<uint8_t> Bytes()
			{
				std::ifstream stream(path_, std::ios::binary);
				return {std::istreambuf_iterator<char>(stream),
				        std::istreambuf_iterator<char>()};
			}

			void Save(const std::vector<uint8_t>& bytes)
			{
				std::ofstream stream(path_, std::ios::binary | std::ios::trunc);
				stream.write(reinterpret_cast<const char*>(bytes.data()),
				             static_cast<std::streamsize>(bytes.size()));
			}

			fs::path directory_;
			fs::path path_;
		};

		struct LineCollector : cov::IDebugInformationHandler
		{
			bool IsSourceFileSelected(const fs::path& path) override
			{
				return path.filename() == fs::path(__FILE__).filename();
			}

			void OnSourceFile(const fs::path&,
			                  const std::vector<Line>& lines) override
			{
				lines_.insert(lines_.end(), lines.begin(), lines.end());
			}

			std::vector<Line> lines_;
		};
	}

	TEST_F(RvaCoverageTest, RoundTripPreservesIdentityBlocksAndExecution)
	{
		const auto original = Sample();
		cov::WriteRvaCoverage(original, path_);
		const auto bytes = Bytes();
		ASSERT_GE(bytes.size(), 12u);
		EXPECT_EQ(std::vector<uint8_t>({'O', 'C', 'C', 'R', 'V', 'A', 'C', 0}),
		          std::vector<uint8_t>(bytes.begin(), bytes.begin() + 8));
		EXPECT_EQ(1, bytes[8]);
		EXPECT_EQ(0, bytes[9]);
		EXPECT_EQ(0, bytes[10]);
		EXPECT_EQ(0, bytes[11]);
		const auto result = cov::ReadRvaCoverage(path_);
		EXPECT_EQ(original.name, result.name);
		EXPECT_EQ(original.exitCode, result.exitCode);
		ASSERT_EQ(1u, result.modules.size());
		const auto& expected = original.modules[0];
		const auto& actual = result.modules[0];
		EXPECT_EQ(expected.path, actual.path);
		EXPECT_EQ(expected.identity.machine, actual.identity.machine);
		EXPECT_EQ(expected.identity.timeDateStamp, actual.identity.timeDateStamp);
		EXPECT_EQ(expected.identity.sizeOfImage, actual.identity.sizeOfImage);
		EXPECT_EQ(expected.identity.checksum, actual.identity.checksum);
		EXPECT_EQ(expected.identity.pdbGuid, actual.identity.pdbGuid);
		EXPECT_EQ(expected.identity.pdbAge, actual.identity.pdbAge);
		EXPECT_EQ(expected.identity.imageHash, actual.identity.imageHash);
		ASSERT_EQ(2u, actual.blocks.size());
		for (size_t i = 0; i < actual.blocks.size(); ++i)
		{
			EXPECT_EQ(expected.blocks[i].block.rva, actual.blocks[i].block.rva);
			EXPECT_EQ(expected.blocks[i].block.size, actual.blocks[i].block.size);
			EXPECT_EQ(expected.blocks[i].block.instructionSet,
			          actual.blocks[i].block.instructionSet);
			EXPECT_EQ(expected.blocks[i].executed, actual.blocks[i].executed);
			EXPECT_TRUE(actual.blocks[i].selected);
			EXPECT_TRUE(actual.blocks[i].observed);
		}
	}

	TEST_F(RvaCoverageTest, SampledRoundTripPreservesCatalogAndObservationStates)
	{
		auto sample = Sample();
		sample.modules[0].blocks[1].selected = false;
		sample.modules[0].blocks[1].observed = false;
		sample.modules[0].blocks.push_back(
		    {{0x3000, 4, cov::InstructionSet::Arm64}, false, true, false});
		cov::WriteRvaCoverage(sample, path_);
		const auto bytes = Bytes();
		EXPECT_EQ(2, bytes[8]);
		ASSERT_GE(bytes.size(), 33u);
		EXPECT_EQ(7, bytes[bytes.size() - 23]);
		EXPECT_EQ(0, bytes[bytes.size() - 12]);
		EXPECT_EQ(1, bytes.back());
		const auto result = cov::ReadRvaCoverage(path_);
		ASSERT_EQ(1u, result.modules.size());
		ASSERT_EQ(3u, result.modules[0].blocks.size());
		for (size_t i = 0; i < 3; ++i)
		{
			const auto& expected = sample.modules[0].blocks[i];
			const auto& actual = result.modules[0].blocks[i];
			EXPECT_EQ(expected.block.rva, actual.block.rva);
			EXPECT_EQ(expected.block.size, actual.block.size);
			EXPECT_EQ(expected.block.instructionSet, actual.block.instructionSet);
			EXPECT_EQ(expected.executed, actual.executed);
			EXPECT_EQ(expected.selected, actual.selected);
			EXPECT_EQ(expected.observed, actual.observed);
		}
	}

	TEST_F(RvaCoverageTest, VersionTwoRejectsReservedBitsAndInvalidObservationStates)
	{
		auto sample = Sample();
		sample.modules[0].blocks[1].observed = false;
		cov::WriteRvaCoverage(sample, path_);
		const auto bytes = Bytes();
		ASSERT_EQ(2, bytes[8]);
		for (const uint8_t state : {uint8_t{2}, uint8_t{4}, uint8_t{5},
		    uint8_t{6}, uint8_t{8}, uint8_t{0xff}})
		{
			SCOPED_TRACE(static_cast<unsigned>(state));
			auto invalid = bytes;
			invalid.back() = state;
			Save(invalid);
			EXPECT_THROW(cov::ReadRvaCoverage(path_), wil::ResultException);
		}
		for (const uint8_t state : {uint8_t{0}, uint8_t{1}, uint8_t{3}, uint8_t{7}})
		{
			auto valid = bytes;
			valid.back() = state;
			Save(valid);
			const auto result = cov::ReadRvaCoverage(path_);
			const auto& block = result.modules[0].blocks[1];
			EXPECT_EQ((state & 1) != 0, block.selected);
			EXPECT_EQ((state & 2) != 0, block.observed);
			EXPECT_EQ((state & 4) != 0, block.executed);
		}
	}

	TEST_F(RvaCoverageTest, WriterAndResolverRejectInvalidObservationImplications)
	{
		for (const auto& state : std::vector<cov::RvaBlock>{
		    {{0x1000, 4, cov::InstructionSet::Arm64}, true, true, false},
		    {{0x1000, 4, cov::InstructionSet::Arm64}, false, false, true}})
		{
			auto sample = Sample();
			sample.modules[0].blocks[0] = state;
			EXPECT_THROW(cov::WriteRvaCoverage(sample, path_), wil::ResultException);
			EXPECT_THROW(cov::RvaCoverageResolver{}.Resolve(sample, {}, {}),
			    wil::ResultException);
		}
	}

	TEST(RvaCoverageSamplingTest, SelectionRoundsUpWithoutChangingCatalog)
	{
		cov::RvaCoverageSampling sampling;
		for (const size_t size : {size_t{0}, size_t{1}, size_t{2}, size_t{3}, size_t{101}})
			for (const unsigned percent : {1u, 33u, 50u, 75u, 100u})
			{
				SCOPED_TRACE(size);
				SCOPED_TRACE(percent);
				std::vector<cov::RvaBlock> blocks;
				for (size_t i = 0; i < size; ++i)
					blocks.push_back({{static_cast<uint32_t>(i * 4), 4,
					    cov::InstructionSet::Arm64}, true});
				sampling.Select(blocks, percent);
				const auto selected = std::count_if(blocks.begin(), blocks.end(),
				    [](const cov::RvaBlock& block) { return block.selected; });
				EXPECT_EQ((uint64_t{size} * percent + 99) / 100,
				    static_cast<uint64_t>(selected));
				ASSERT_EQ(size, blocks.size());
				for (size_t i = 0; i < size; ++i)
				{
					EXPECT_EQ(i * 4, blocks[i].block.rva);
					EXPECT_EQ(4u, blocks[i].block.size);
					EXPECT_EQ(cov::InstructionSet::Arm64, blocks[i].block.instructionSet);
					EXPECT_FALSE(blocks[i].executed);
					EXPECT_FALSE(blocks[i].observed);
				}
			}
	}

	TEST(RvaCoverageSamplingTest, InvalidPercentageDoesNotChangeCatalog)
	{
		cov::RvaCoverageSampling sampling;
		std::vector<cov::RvaBlock> blocks{
		    {{0x1000, 4, cov::InstructionSet::Arm64}, true}};
		for (const unsigned percent : {0u, 101u})
		{
			EXPECT_THROW(sampling.Select(blocks, percent), wil::ResultException);
			EXPECT_TRUE(blocks[0].executed);
			EXPECT_TRUE(blocks[0].selected);
			EXPECT_TRUE(blocks[0].observed);
		}
	}

	TEST_F(RvaCoverageTest, EmptyCoverageRoundTrip)
	{
		cov::WriteRvaCoverage({}, path_);
		const auto result = cov::ReadRvaCoverage(path_);
		EXPECT_TRUE(result.name.empty());
		EXPECT_TRUE(result.modules.empty());
		EXPECT_EQ(0, result.exitCode);
	}

	TEST_F(RvaCoverageTest, Arm64HybridHeadersPreserveMixedInstructionSets)
	{
		for (const uint16_t machine : {uint16_t{0xaa64}, uint16_t{0xa641}})
		{
			auto sample = Sample();
			sample.modules[0].identity.machine = machine;
			cov::WriteRvaCoverage(sample, path_);
			const auto result = cov::ReadRvaCoverage(path_);
			ASSERT_EQ(1u, result.modules.size());
			EXPECT_EQ(machine, result.modules[0].identity.machine);
			ASSERT_EQ(2u, result.modules[0].blocks.size());
			for (size_t i = 0; i < 2; ++i)
			{
				const auto& expected = sample.modules[0].blocks[i];
				const auto& actual = result.modules[0].blocks[i];
				EXPECT_EQ(expected.block.instructionSet, actual.block.instructionSet);
				EXPECT_EQ(expected.block.rva, actual.block.rva);
				EXPECT_EQ(expected.block.size, actual.block.size);
				EXPECT_EQ(expected.executed, actual.executed);
			}
		}
	}

	TEST_F(RvaCoverageTest, ExtendedWindowsModulePathRoundTrip)
	{
		auto sample = Sample();
		for (const auto* path : {L"\\\\?\\C:\\binaries\\module.dll",
		                         L"\\\\?\\UNC\\server\\share\\module.dll"})
		{
			sample.modules[0].path = path;
			cov::WriteRvaCoverage(sample, path_);
			EXPECT_EQ(sample.modules[0].path, cov::ReadRvaCoverage(path_).modules[0].path);
		}
	}

	TEST_F(RvaCoverageTest, IdentifiesRawSignatureIndependentlyOfVersion)
	{
		cov::WriteRvaCoverage(Sample(), path_);
		EXPECT_TRUE(cov::IsRvaCoverage(path_));
		auto bytes = Bytes();
		bytes[8] = 0xff;
		Save(bytes);
		EXPECT_TRUE(cov::IsRvaCoverage(path_));
		EXPECT_THROW(cov::ReadRvaCoverage(path_), wil::ResultException);
		Save({'2', '2', ' ', 's', 'e', 'r', 'i', 'a', 'l', 'i', 'z', 'a', 't', 'i', 'o', 'n'});
		EXPECT_FALSE(cov::IsRvaCoverage(path_));
		Save({});
		EXPECT_FALSE(cov::IsRvaCoverage(path_));
	}

	TEST_F(RvaCoverageTest, RejectsEveryTruncatedPrefixAndTrailingBytes)
	{
		cov::WriteRvaCoverage(Sample(), path_);
		const auto bytes = Bytes();
		for (size_t size = 0; size < bytes.size(); ++size)
		{
			SCOPED_TRACE(size);
			Save({bytes.begin(), bytes.begin() + size});
			EXPECT_THROW(cov::ReadRvaCoverage(path_), wil::ResultException);
		}
		auto trailing = bytes;
		trailing.push_back(0);
		Save(trailing);
		EXPECT_THROW(cov::ReadRvaCoverage(path_), wil::ResultException);
	}

	TEST_F(RvaCoverageTest, RejectsBadSignatureVersionCountsPathsAndBlocks)
	{
		const auto sample = Sample();
		cov::WriteRvaCoverage(sample, path_);
		const auto bytes = Bytes();
		const size_t nameEnd = 16 + sample.name.size() * 2;
		const size_t moduleCount = nameEnd + 4;
		const size_t modulePath = moduleCount + 4;
		const size_t identity = modulePath + 4 +
		    sample.modules[0].path.wstring().size() * 2;
		const size_t blockCount = identity + 66;
		const size_t firstBlock = blockCount + 4;
		const std::vector<std::pair<size_t, uint8_t>> mutations{
		    {0, 0}, {8, 3}, {12, 0xff}, {moduleCount + 3, 0xff},
		    {modulePath + 4, 0}, {modulePath + 5, 0xd8},
		    {identity, 0}, {blockCount + 3, 0xff},
		    {firstBlock + 4, 0}, {firstBlock + 8, 0},
		    {firstBlock + 10, 2}, {firstBlock + 11 + 1, 0x10}};
		for (const auto& mutation : mutations)
		{
			SCOPED_TRACE(mutation.first);
			auto invalid = bytes;
			invalid[mutation.first] = mutation.second;
			Save(invalid);
			EXPECT_THROW(cov::ReadRvaCoverage(path_), wil::ResultException);
		}
	}

	TEST_F(RvaCoverageTest, RejectsInvalidInMemoryRangesAndStrings)
	{
		auto sample = Sample();
		sample.modules[0].blocks[0].block.size = 0;
		EXPECT_THROW(cov::WriteRvaCoverage(sample, path_), wil::ResultException);
		sample = Sample();
		sample.modules[0].blocks[0].block.size = 0x4000;
		EXPECT_THROW(cov::WriteRvaCoverage(sample, path_), wil::ResultException);
		sample = Sample();
		sample.modules[0].blocks[1].block.rva = 0x1000;
		EXPECT_THROW(cov::WriteRvaCoverage(sample, path_), wil::ResultException);
		sample = Sample();
		sample.modules[0].blocks[1].block.size = 3;
		EXPECT_THROW(cov::WriteRvaCoverage(sample, path_), wil::ResultException);
		sample = Sample();
		sample.modules[0].identity.machine = 0x14c;
		EXPECT_THROW(cov::WriteRvaCoverage(sample, path_), wil::ResultException);
		sample = Sample();
		sample.modules[0].path = L"bad?.dll";
		EXPECT_THROW(cov::WriteRvaCoverage(sample, path_), wil::ResultException);
		sample = Sample();
		sample.name = std::wstring(1, static_cast<wchar_t>(0xd800));
		EXPECT_THROW(cov::WriteRvaCoverage(sample, path_), wil::ResultException);
		sample.name = std::wstring(32768, L'x');
		EXPECT_THROW(cov::WriteRvaCoverage(sample, path_), wil::ResultException);
	}

	TEST_F(RvaCoverageTest, ResolverRejectsMismatchedImageBeforeLoadingSymbols)
	{
		auto sample = Sample();
		sample.modules[0].path = CurrentExecutable();
		const auto identity = cov::PeImage(sample.modules[0].path).Identity();
		std::vector<cov::PeIdentity> mismatches(7, identity);
		mismatches[0].machine ^= 1;
		mismatches[1].timeDateStamp ^= 1;
		mismatches[2].sizeOfImage ^= 1;
		mismatches[3].checksum ^= 1;
		mismatches[4].pdbGuid[0] ^= 1;
		mismatches[5].pdbAge ^= 1;
		mismatches[6].imageHash[0] ^= 1;
		for (const auto& mismatch : mismatches)
		{
			sample.modules[0].identity = mismatch;
			try
			{
				cov::RvaCoverageResolver().Resolve(sample, {}, {});
				FAIL() << "Mismatched image was accepted";
			}
			catch (const std::exception& error)
			{
				EXPECT_NE(std::string::npos,
				          std::string(error.what()).find("No matching image found"));
			}
		}
	}

	TEST_F(RvaCoverageTest, ResolverRejectsMismatchedPdbForMatchingImage)
	{
		const auto binary = CurrentExecutable();
		const auto identity = cov::PeImage(binary).Identity();
		std::ifstream stream(binary, std::ios::binary);
		std::vector<uint8_t> bytes{
		    std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>()};
		std::vector<uint8_t> signature{'R', 'S', 'D', 'S'};
		signature.insert(signature.end(), identity.pdbGuid.begin(), identity.pdbGuid.end());
		const auto codeView =
		    std::search(bytes.begin(), bytes.end(), signature.begin(), signature.end());
		ASSERT_NE(bytes.end(), codeView);
		codeView[4] ^= 1;
		path_ = directory_ / L"mismatched-pdb.exe";
		Save(bytes);
		cov::RvaCoverage raw;
		cov::RvaModule module;
		module.path = path_;
		module.identity = cov::PeImage(path_).Identity();
		raw.modules.push_back(module);
		try
		{
			cov::RvaCoverageResolver().Resolve(raw, {}, {});
			FAIL() << "Mismatched PDB was accepted";
		}
		catch (const std::exception& error)
		{
			EXPECT_NE(std::string::npos,
			          std::string(error.what()).find("Cannot load matching PDB"));
		}
	}

	TEST_F(RvaCoverageTest, ResolveCliSkipsUnavailableExcludedModules)
	{
		auto raw = Sample();
		const auto binary = CurrentExecutable();
		cov::RvaModule selected;
		selected.path = binary;
		selected.identity = cov::PeImage(binary).Identity();
		raw.modules.push_back(selected);
		cov::WriteRvaCoverage(raw, path_);
		const auto resolved = directory_ / L"resolved.cov";
		std::string output;
		const auto result = Tools::RunProcess(
			Tools::GetExecutableFolder() / L"OpenCppCoverage.exe",
			{L"--resolve", path_.wstring(), L"--modules", binary.filename().wstring(),
			 L"--export_type", L"binary:" + resolved.wstring()}, &output, true);
		EXPECT_EQ(0, result) << output;
		EXPECT_TRUE(fs::exists(resolved));
	}

	TEST_F(RvaCoverageTest, ResolvesRelocatedImageAndLinesInsideBlockOnly)
	{
		const auto binary = CurrentExecutable();
		LineCollector collector;
		ASSERT_TRUE(cov::DebugInformationEnumerator({}).Enumerate(binary, collector));
		auto& lines = collector.lines_;
		std::sort(lines.begin(), lines.end(),
		          [](const LineCollector::Line& a, const LineCollector::Line& b) {
			          return a.virtualAddress_ < b.virtualAddress_;
		          });
		ASSERT_GE(lines.size(), 3u);
		const auto first = lines.front();
		auto interior = std::find_if(
		    lines.begin(), lines.end(), [&](const LineCollector::Line& line) {
			    return line.virtualAddress_ > first.virtualAddress_ &&
			           line.lineNumber_ != first.lineNumber_;
		    });
		ASSERT_NE(lines.end(), interior);
		const auto end = interior->virtualAddress_ +
		    (std::max)(1ul, interior->length_);
		ASSERT_LT(end, lines.back().virtualAddress_);

		cov::RvaCoverage raw;
		raw.name = L"offline";
		raw.exitCode = 9;
		cov::RvaModule module;
		module.path = directory_ / L"missing" / binary.filename();
		module.identity = cov::PeImage(binary).Identity();
		const auto isa = module.identity.machine == 0xaa64
		    ? cov::InstructionSet::Arm64 : cov::InstructionSet::Amd64;
		module.blocks.push_back(
		    {{static_cast<uint32_t>(first.virtualAddress_),
		      static_cast<uint32_t>(end - first.virtualAddress_), isa}, true});
		raw.modules.push_back(module);
		fs::copy_file(binary, directory_ / binary.filename());

		for (const bool executed : {false, true})
		{
			raw.modules[0].blocks[0].executed = executed;
			auto output = cov::RvaCoverageResolver().Resolve(raw, {directory_}, {});
			EXPECT_EQ(raw.name, output.GetName());
			EXPECT_EQ(raw.exitCode, output.GetExitCode());
			ASSERT_EQ(1u, output.GetModules().size());
			EXPECT_EQ(directory_ / binary.filename(), output.GetModules()[0]->GetPath());
			bool found = false;
			for (const auto& file : output.GetModules()[0]->GetFiles())
			{
				if (file->GetPath().filename() != fs::path(__FILE__).filename())
					continue;
				found = true;
				std::map<unsigned long, bool> expected;
				for (const auto& line : lines)
					if (line.virtualAddress_ < end &&
					    line.virtualAddress_ + (std::max)(1ul, line.length_) >
					        first.virtualAddress_)
						expected[line.lineNumber_] = executed;
				EXPECT_EQ(expected.size(), file->GetLines().size());
				for (const auto& line : expected)
				{
					ASSERT_NE(nullptr, (*file)[line.first]);
					EXPECT_EQ(line.second, (*file)[line.first]->HasBeenExecuted());
				}
				ASSERT_NE(nullptr, (*file)[interior->lineNumber_]);
			}
			EXPECT_TRUE(found);
		}
		const unsigned long split = isa == cov::InstructionSet::Arm64 ? 4 : 1;
		const auto spanning = std::find_if(
		    lines.begin(), lines.end(), [&](const LineCollector::Line& line) {
			    return line.length_ > split;
		    });
		ASSERT_NE(lines.end(), spanning);
		const auto start = static_cast<uint32_t>(spanning->virtualAddress_);
		for (const bool firstExecuted : {false, true})
		{
			raw.modules[0].blocks = {
			    {{start, split, isa}, firstExecuted},
			    {{start + split, spanning->length_ - split, isa}, !firstExecuted}};
			const auto output = cov::RvaCoverageResolver().Resolve(raw, {directory_}, {});
			bool found = false;
			for (const auto& file : output.GetModules()[0]->GetFiles())
			{
				if (file->GetPath().filename() != fs::path(__FILE__).filename())
					continue;
				found = true;
				ASSERT_NE(nullptr, (*file)[spanning->lineNumber_]);
				EXPECT_TRUE((*file)[spanning->lineNumber_]->HasBeenExecuted());
			}
			EXPECT_TRUE(found);
		}
	}

	TEST_F(RvaCoverageTest, CfgReportLeavesRawEvidenceAndMeasuredSourceExportsUnchanged)
	{
		const auto binary = CurrentExecutable();
		LineCollector collector;
		ASSERT_TRUE(cov::DebugInformationEnumerator({}).Enumerate(binary, collector));
		ASSERT_FALSE(collector.lines_.empty());
		const auto& line = collector.lines_.front();
		cov::RvaCoverage raw;
		cov::RvaModule module;
		module.path = binary;
		module.identity = cov::PeImage(binary).Identity();
		const auto isa = module.identity.machine == 0xaa64 ? cov::InstructionSet::Arm64 : cov::InstructionSet::Amd64;
		module.blocks.push_back({{static_cast<uint32_t>(line.virtualAddress_),
			(std::max)(1ul, line.length_), isa}, true});
		raw.modules.push_back(module);
		cov::WriteRvaCoverage(raw, path_);
		const auto original = Bytes();
		const auto baseline = cov::RvaCoverageResolver{}.Resolve(raw, {}, {});
		const auto reportPath = directory_ / L"cfg.json";
		const auto withReport = cov::RvaCoverageResolver{}.Resolve(raw, {}, {}, reportPath);
		ASSERT_TRUE(fs::is_regular_file(reportPath));
		std::ifstream reportFile(reportPath);
		boost::property_tree::ptree report;
		boost::property_tree::read_json(reportFile, report);
		EXPECT_FALSE(report.get<bool>("withinWindowExecutionClaim"));
		EXPECT_EQ("unknown", report.get<std::string>("temporalProvenance"));
		ASSERT_EQ(baseline.GetModules().size(), withReport.GetModules().size());
		for (size_t i = 0; i < baseline.GetModules().size(); ++i)
		{
			const auto& expected = baseline.GetModules()[i]->GetFiles();
			const auto& actual = withReport.GetModules()[i]->GetFiles();
			ASSERT_EQ(expected.size(), actual.size());
			for (size_t j = 0; j < expected.size(); ++j)
			{
				EXPECT_EQ(expected[j]->GetPath(), actual[j]->GetPath());
				const auto expectedLines = expected[j]->GetLines();
				const auto actualLines = actual[j]->GetLines();
				ASSERT_EQ(expectedLines.size(), actualLines.size());
				for (size_t k = 0; k < expectedLines.size(); ++k)
				{
					EXPECT_EQ(expectedLines[k].GetLineNumber(), actualLines[k].GetLineNumber());
					EXPECT_EQ(expectedLines[k].HasBeenExecuted(), actualLines[k].HasBeenExecuted());
				}
			}
		}
		cov::WriteRvaCoverage(raw, path_);
		EXPECT_EQ(original, Bytes());
		const auto baselinePath = directory_ / L"baseline.cov";
		const auto reportedPath = directory_ / L"reported.cov";
		const auto cliReport = directory_ / L"cli-cfg.json";
		std::string diagnostic;
		const auto cli = Tools::GetExecutableFolder() / L"OpenCppCoverage.exe";
		ASSERT_EQ(0, Tools::RunProcess(cli,
			{L"--resolve", path_.wstring(), L"--export_type", L"binary:" + baselinePath.wstring()},
			&diagnostic, true)) << diagnostic;
		ASSERT_EQ(0, Tools::RunProcess(cli,
			{L"--resolve", path_.wstring(), L"--cfg-report", cliReport.wstring(),
				L"--export_type", L"binary:" + reportedPath.wstring()},
			&diagnostic, true)) << diagnostic;
		std::ifstream expectedFile(baselinePath, std::ios::binary);
		std::ifstream actualFile(reportedPath, std::ios::binary);
		EXPECT_EQ((std::vector<uint8_t>{std::istreambuf_iterator<char>(expectedFile), {}}),
			(std::vector<uint8_t>{std::istreambuf_iterator<char>(actualFile), {}}));
		std::ifstream cliReportFile(cliReport);
		boost::property_tree::ptree cliJson;
		boost::property_tree::read_json(cliReportFile, cliJson);
		EXPECT_FALSE(cliJson.get<bool>("withinWindowExecutionClaim"));
		EXPECT_THROW(cov::RvaCoverageResolver{}.Resolve(raw, {}, {}, binary), std::runtime_error);
	}

	TEST_F(RvaCoverageTest, NativeMatchingPdbProducesConditionalChainWithoutChangingMeasuredExports)
	{
		const auto binary = Tools::GetExecutableFolder() / L"TestCoverageOptimizedBuild.dll";
		struct FunctionCollector : LineCollector
		{
			std::vector<Function> functions;
			void OnFunction(const Function& function) override { functions.push_back(function); }
		} collector;
		ASSERT_TRUE(cov::DebugInformationEnumerator({}).Enumerate(binary, collector, true));
		const auto chain = std::find_if(collector.functions.begin(), collector.functions.end(), [](const auto& function) {
			return function.name.find(L"CfgReportChain") != std::wstring::npos;
		});
		ASSERT_NE(collector.functions.end(), chain);
		cov::PeImage image(binary);
		cov::RvaCoverage raw;
		cov::RvaModule module;
		module.path = binary;
		module.identity = image.Identity();
		for (const auto& block : cov::BasicBlockDiscovery{}.Discover(image))
			module.blocks.push_back({block, false});
		auto anchor = module.blocks.end();
		for (auto site = module.blocks.begin(); site != module.blocks.end(); ++site)
			if (site->block.rva > chain->rva &&
				uint64_t{site->block.rva} + site->block.size <= uint64_t{chain->rva} + chain->size)
				anchor = site;
		ASSERT_NE(module.blocks.end(), anchor);
		anchor->executed = true;
		const auto measuredRva = anchor->block.rva;
		raw.modules.push_back(module);
		cov::WriteRvaCoverage(raw, path_);
		const auto original = Bytes();
		const auto withoutReport = cov::RvaCoverageResolver{}.Resolve(raw, {}, {});
		const auto reportPath = directory_ / L"native-cfg.json";
		const auto withReport = cov::RvaCoverageResolver{}.Resolve(raw, {}, {}, reportPath);
		const auto measuredLines = [](const Plugin::CoverageData& coverage) {
			std::map<std::tuple<fs::path, fs::path, unsigned>, bool> lines;
			for (const auto& currentModule : coverage.GetModules())
				for (const auto& source : currentModule->GetFiles())
					for (const auto& line : source->GetLines())
						lines.emplace(std::make_tuple(currentModule->GetPath(), source->GetPath(), line.GetLineNumber()),
							line.HasBeenExecuted());
			return lines;
		};
		EXPECT_EQ(measuredLines(withoutReport), measuredLines(withReport));
		cov::WriteRvaCoverage(raw, path_);
		EXPECT_EQ(original, Bytes());
		const auto baselinePath = directory_ / L"native-baseline.cov";
		const auto reportedPath = directory_ / L"native-reported.cov";
		std::string diagnostic;
		const auto cli = Tools::GetExecutableFolder() / L"OpenCppCoverage.exe";
		ASSERT_EQ(0, Tools::RunProcess(cli,
			{L"--resolve", path_.wstring(), L"--export_type", L"binary:" + baselinePath.wstring()},
			&diagnostic, true)) << diagnostic;
		ASSERT_EQ(0, Tools::RunProcess(cli,
			{L"--resolve", path_.wstring(), L"--cfg-report", reportPath.wstring(),
				L"--export_type", L"binary:" + reportedPath.wstring()},
			&diagnostic, true)) << diagnostic;
		std::ifstream baselineFile(baselinePath, std::ios::binary);
		std::ifstream reportedFile(reportedPath, std::ios::binary);
		EXPECT_EQ((std::vector<uint8_t>{std::istreambuf_iterator<char>(baselineFile), {}}),
			(std::vector<uint8_t>{std::istreambuf_iterator<char>(reportedFile), {}}));
		std::ifstream file(reportPath);
		boost::property_tree::ptree report;
		boost::property_tree::read_json(file, report);
		const auto& reported = report.get_child("modules").front().second;
		ASSERT_EQ("null", reported.get<std::string>("exclusion"));
		size_t implications = 0;
		bool entryRequired = false;
		std::ostringstream evidence;
		for (const auto& function : reported.get_child("functions"))
		{
			if (function.second.get<std::string>("name").find("CfgReportChain") == std::string::npos)
				continue;
			ASSERT_EQ("null", function.second.get<std::string>("exclusion"));
			EXPECT_EQ(chain->uncertainties.size(), function.second.get_child("uncertainties").size());
			for (const auto& implication : function.second.get_child("implications"))
			{
				EXPECT_EQ(measuredRva, implication.second.get<uint32_t>("measuredRva"));
				const auto required = implication.second.get<uint32_t>("requiredRva");
				entryRequired = entryRequired || required == chain->rva;
				evidence << measuredRva << "->" << required << ';';
				++implications;
			}
		}
		EXPECT_GT(implications, 0u);
		EXPECT_TRUE(entryRequired);
		EXPECT_FALSE(report.get<bool>("withinWindowExecutionClaim"));
		EXPECT_EQ("unknown", report.get<std::string>("temporalProvenance"));
		RecordProperty("cfgNativeChainImplications", evidence.str());
		RecordProperty("cfgNativeImageHash", reported.get<std::string>("identity.imageHash"));
	}

	TEST_F(RvaCoverageTest, CfgReportRejectsChangedIdentity)
	{
		const auto binary = CurrentExecutable();
		cov::CfgModuleInput input;
		input.image = binary;
		input.evidence.identity = cov::PeImage(binary).Identity();
		input.functions.push_back({0x1000, 4, L"synthetic", {}});
		input.evidence.identity.imageHash[0] ^= 1;
		std::ostringstream output;
		EXPECT_THROW(cov::WriteCfgReport(output, {input}), std::runtime_error);
	}

	TEST_F(RvaCoverageTest, UnknownContributorsSuppressNegativesAcrossRepeatedLineRecords)
	{
		const auto binary = CurrentExecutable();
		LineCollector collector;
		ASSERT_TRUE(cov::DebugInformationEnumerator({}).Enumerate(binary, collector));
		std::map<unsigned long, std::vector<uint32_t>> records;
		for (const auto& line : collector.lines_)
			if (line.virtualAddress_ >= 0 && line.lineNumber_ != 0)
				records[line.lineNumber_].push_back(static_cast<uint32_t>(line.virtualAddress_));
		auto repeated = records.end();
		for (auto record = records.begin(); record != records.end(); ++record)
		{
			auto& addresses = record->second;
			std::sort(addresses.begin(), addresses.end());
			addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());
			if (addresses.size() >= 2)
			{
				repeated = record;
				break;
			}
		}
		ASSERT_NE(records.end(), repeated);
		cov::RvaCoverage raw;
		cov::RvaModule module;
		module.path = binary;
		module.identity = cov::PeImage(binary).Identity();
		const auto isa = module.identity.machine == 0xaa64
		    ? cov::InstructionSet::Arm64 : cov::InstructionSet::Amd64;
		const uint32_t size = isa == cov::InstructionSet::Arm64 ? 4 : 1;
		ASSERT_GE(repeated->second.back() - repeated->second.front(), size);
		module.blocks = {
		    {{repeated->second.front(), size, isa}, false},
		    {{repeated->second.back(), size, isa}, false, false, false}};
		raw.modules.push_back(module);
		for (const bool selected : {false, true})
			for (const bool observed : {false, true})
				for (const bool executed : {false, true})
				{
					SCOPED_TRACE(selected);
					SCOPED_TRACE(observed);
					SCOPED_TRACE(executed);
					raw.modules[0].blocks[0].executed = executed;
					raw.modules[0].blocks[1].selected = selected || observed;
					raw.modules[0].blocks[1].observed = observed;
					const auto output = cov::RvaCoverageResolver{}.Resolve(raw, {}, {});
					ASSERT_EQ(1u, output.GetModules().size());
					const Plugin::LineCoverage* resolved = nullptr;
					for (const auto& file : output.GetModules()[0]->GetFiles())
						if (file->GetPath().filename() == fs::path(__FILE__).filename())
							resolved = (*file)[repeated->first];
					if (executed || observed)
					{
						ASSERT_NE(nullptr, resolved);
						EXPECT_EQ(executed, resolved->HasBeenExecuted());
					}
					else
						EXPECT_EQ(nullptr, resolved);
				}
	}
}
