#include <gtest/gtest.h>

#include <wil/result.h>

#include "CppCoverage/BasicBlockDiscovery.hpp"
#include "CppCoverage/CfgReport.hpp"
#include <boost/property_tree/json_parser.hpp>
#include <atomic>
#include <fstream>
#include <process.h>
#include <sstream>
#include <set>
#include <map>

#include <algorithm>
#include <array>
#include <cstdint>
#include <initializer_list>
#include <stdexcept>
#include <utility>
#include <vector>

namespace CppCoverageTest
{
	namespace
	{
		using namespace CppCoverage;

		class PeFixture
		{
		public:
			explicit PeFixture(uint16_t machine = 0x8664) : bytes(0x1600, 0)
			{
				Put(0, 0x5a4d, 2);
				Put(0x3c, 0x80);
				Put(0x80, 0x4550);
				Put(0x84, machine, 2);
				Put(0x86, 2, 2);
				Put(0x88, 0x12345678);
				Put(0x94, 0xf0, 2);
				Put(0x98, 0x20b, 2);
				Put(0xa8, 0x1000);
				Put(0xb0, Base, 8);
				Put(0xb8, 0x1000);
				Put(0xbc, 0x200);
				Put(0xd0, 0x3000);
				Put(0xd4, 0x200);
				Put(0xd8, 0xabcdef);
				Put(0x104, 16);
				Put(0x190, 0x400);
				Put(0x194, 0x1000);
				Put(0x198, 0x400);
				Put(0x19c, 0x200);
				Put(0x1ac, 0x60000020);
				Put(0x1b8, 0x1000);
				Put(0x1bc, 0x2000);
				Put(0x1c0, 0x1000);
				Put(0x1c4, 0x600);
				Put(0x1d4, 0x40000040);
				std::fill(bytes.begin() + 0x200, bytes.begin() + 0x600, uint8_t{0xcc});
			}

			void Put(size_t offset, uint64_t value, size_t width = 4)
			{
				for (size_t i = 0; i < width; ++i)
					bytes.at(offset + i) = static_cast<uint8_t>(value >> (i * 8));
			}

			void ResizeText(uint32_t size, uint32_t rva = 0x1000)
			{
				bytes.resize(0x200 + size);
				std::fill(bytes.begin() + 0x200, bytes.end(), uint8_t{0x90});
				Put(0x86, 1, 2);
				Put(0xa8, rva);
				Put(0xd0, (uint64_t{rva} + size + 0xfff) & ~uint64_t{0xfff});
				Put(0x190, size);
				Put(0x194, rva);
				Put(0x198, size);
			}

			size_t Offset(uint32_t rva) const
			{
				return rva < 0x2000 ? 0x200 + rva - 0x1000 : 0x600 + rva - 0x2000;
			}

			void Rva(uint32_t rva, uint64_t value, size_t width = 4)
			{
				Put(Offset(rva), value, width);
			}

			void Code(uint32_t rva, std::initializer_list<uint8_t> code)
			{
				std::copy(code.begin(), code.end(), bytes.begin() + Offset(rva));
			}

			void Directory(size_t index, uint32_t rva, uint32_t size)
			{
				Put(0x108 + index * 8, rva);
				Put(0x10c + index * 8, size);
			}

			void Exports(std::initializer_list<uint32_t> targets)
			{
				Directory(0, 0x2000, 0x100);
				Rva(0x2014, targets.size());
				Rva(0x201c, 0x2080);
				uint32_t entry = 0x2080;
				for (const auto target : targets)
				{
					Rva(entry, target);
					entry += 4;
				}
			}

			void Hybrid(uint16_t machine)
			{
				Put(0x84, machine, 2);
				Directory(10, 0x2100, 280);
				Rva(0x2100, 280);
				Rva(0x21c8, Base + 0x2300, 8);
				Rva(0x2300, 2);
				Rva(0x2304, 0x2380);
				Rva(0x2308, 4);
				Rva(0x2328, 0x1020);
				Rva(0x2380, 0x1000 | 2);
				Rva(0x2384, 0x20);
				Rva(0x2388, 0x1020 | 1);
				Rva(0x238c, 0x20);
				Rva(0x2390, 0x1040);
				Rva(0x2394, 0x20);
				Rva(0x2398, 0x1060 | 2);
				Rva(0x239c, 0x20);
				Code(0x1000, {0xe9, 0x1b, 0, 0, 0});
				Rva(0x1020, 0xd65f03c0);
				Rva(0x1040, 0xd65f03c0);
				Code(0x1060, {0xc3});
				Directory(3, 0x2500, 12);
				Rva(0x2500, 0x1060);
				Rva(0x2504, 0x1061);
				Rva(0x2508, 0x2580);
				Rva(0x2580, 1);
				Rva(0x2340, 0x2540);
				Rva(0x2344, 8);
				Rva(0x2540, 0x1040);
				Rva(0x2544, 5);
			}

			void FunctionOverride(uint16_t type = 2,
				bool sectionRelative = false, bool version2 = false)
			{
				Directory(10, 0x2100, 232);
				Rva(0x2100, 232);
				if (sectionRelative)
				{
					Rva(0x21e0, 0x300);
					Rva(0x21e4, 2, 2);
				}
				else
					Rva(0x21c0, Base + 0x2300, 8);
				const uint32_t headerSize = version2 ? 24 : 12;
				Rva(0x2300, version2 ? 2 : 1);
				Rva(0x2304, headerSize + 52);
				if (version2)
				{
					Rva(0x2308, headerSize);
					Rva(0x230c, 52);
					Rva(0x2310, 7, 8);
				}
				else
				{
					Rva(0x2308, 7, 8);
					Rva(0x2310, 52);
				}
				const auto payload = 0x2308 + headerSize;
				Rva(payload, 32);
				Rva(payload + 4, 0x1040);
				Rva(payload + 12, 4);
				Rva(payload + 16, 12);
				Rva(payload + 20, 0x1060);
				Rva(payload + 24, 0x1000);
				Rva(payload + 28, 12);
				Rva(payload + 32, (type << 12) | (type == 1 ? 1 : 0), 2);
				Rva(payload + 36, 1);
				Rva(payload + 40, 8);
			}

			std::vector<BasicBlock> Discover() const
			{
				return BasicBlockDiscovery().Discover(PeImage(bytes));
			}

			static constexpr uint64_t Base = 0x140000000;
			std::vector<uint8_t> bytes;
		};

		void ExpectBlocks(const std::vector<BasicBlock>& actual,
			std::initializer_list<std::pair<uint32_t, uint32_t>> expected,
			InstructionSet instructionSet = InstructionSet::Amd64)
		{
			ASSERT_EQ(expected.size(), actual.size());
			size_t i = 0;
			for (const auto& block : expected)
			{
				EXPECT_EQ(block.first, actual[i].rva);
				EXPECT_EQ(block.second, actual[i].size);
				EXPECT_EQ(instructionSet, actual[i].instructionSet);
				++i;
			}
		}

		boost::property_tree::ptree Report(const PeFixture& fixture,
			std::vector<IDebugInformationHandler::Function> functions,
			const std::vector<uint32_t>& hits,
			std::vector<CfgSourceLine> lines = {}, bool corruptCatalog = false,
			bool unobserveUnhit = false)
		{
			static std::atomic<unsigned> next{0};
			const auto path = std::filesystem::path(PROJECT_DIR) /
				("CfgFixture-" + std::to_string(_getpid()) + "-" + std::to_string(next++) + ".exe");
			struct Cleanup
			{
				std::filesystem::path path;
				~Cleanup() { std::error_code error; std::filesystem::remove(path, error); }
			} cleanup{path};
			{
				std::ofstream file(path, std::ios::binary);
				file.write(reinterpret_cast<const char*>(fixture.bytes.data()), fixture.bytes.size());
			}
			CfgModuleInput input;
			input.image = path;
			input.evidence.path = path;
			input.evidence.identity = PeImage(fixture.bytes).Identity();
			try
			{
				for (const auto& block : fixture.Discover())
					input.evidence.blocks.push_back({block,
						std::find(hits.begin(), hits.end(), block.rva) != hits.end()});
			}
			catch (const wil::ResultException&)
			{
				EXPECT_EQ(0u, hits.size());
			}
			if (corruptCatalog && !input.evidence.blocks.empty())
				++input.evidence.blocks.front().block.size;
			if (unobserveUnhit)
				for (auto& site : input.evidence.blocks)
					if (!site.executed)
					{
						site.selected = false;
						site.observed = false;
					}
			input.functions = std::move(functions);
			input.lines = std::move(lines);
			std::stringstream text;
			WriteCfgReport(text, {input});
			std::ostringstream repeated;
			repeated << std::hex << std::showbase << std::showpos;
			WriteCfgReport(repeated, {input});
			EXPECT_EQ(text.str(), repeated.str());
			boost::property_tree::ptree report;
			boost::property_tree::read_json(text, report);
			EXPECT_EQ(1, report.get<int>("schemaVersion"));
			EXPECT_FALSE(report.get<bool>("withinWindowExecutionClaim"));
			EXPECT_EQ("unknown", report.get<std::string>("temporalProvenance"));
			EXPECT_EQ("required-on-normal-entry-paths", report.get<std::string>("semantics"));
			return report;
		}

		const boost::property_tree::ptree& FirstRegion(const boost::property_tree::ptree& report)
		{
			return report.get_child("modules").front().second.get_child("functions").front().second;
		}

		std::set<uint32_t> Required(const boost::property_tree::ptree& region)
		{
			std::set<uint32_t> result;
			std::map<uint32_t, uint32_t> parents;
			for (const auto& node : region.get_child("nodes"))
				if (node.second.get<std::string>("immediateDominatorRva") != "null")
					parents.emplace(node.second.get<uint32_t>("rva"),
						node.second.get<uint32_t>("immediateDominatorRva"));
			for (const auto& item : region.get_child("implications"))
			{
				result.insert(item.second.get<uint32_t>("requiredRva"));
				EXPECT_EQ("strict-dominator", item.second.get<std::string>("witness.kind"));
				auto current = item.second.get<uint32_t>("witness.treeNodeRva");
				const auto required = item.second.get<uint32_t>("requiredRva");
				size_t steps = 0;
				while (current != required && parents.count(current) && steps++ <= parents.size())
					current = parents.at(current);
				EXPECT_EQ(required, current);
			}
			return result;
		}
	}

	TEST(CfgReportTest, ChainReportsConditionalStrictDominatorsOnlyFromMeasuredHit)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0x90, 0xeb, 0, 0x90, 0xeb, 0, 0xc3});
		const auto report = Report(fixture, {{0x1000, 7, L"chain", {}}}, {0x1006});
		const auto& region = FirstRegion(report);
		EXPECT_EQ("null", region.get<std::string>("exclusion"));
		EXPECT_EQ((std::set<uint32_t>{0x1000, 0x1003}), Required(region));
		EXPECT_TRUE(Required(FirstRegion(Report(fixture, {{0x1000, 7, L"chain", {}}}, {}))).empty());
	}

	TEST(CfgReportTest, DiamondDoesNotClaimEitherAlternativeArm)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0x75, 3, 0x90, 0xeb, 1, 0x90, 0xc3});
		const auto report = Report(fixture, {{0x1000, 7, L"diamond", {}}}, {0x1006});
		EXPECT_EQ((std::set<uint32_t>{0x1000}), Required(FirstRegion(report)));
	}

	TEST(CfgReportTest, MultipleRootsAndOutsideDirectEntriesRemoveEarlierDominators)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0x90, 0xeb, 0, 0x90, 0xeb, 0, 0xc3});
		fixture.Exports({0x1003});
		auto report = Report(fixture, {{0x1000, 7, L"roots", {}}}, {0x1006});
		EXPECT_EQ((std::set<uint32_t>{0x1003}), Required(FirstRegion(report)));
		fixture.Exports({0x1020});
		fixture.Code(0x1020, {0xe9, 0xde, 0xff, 0xff, 0xff});
		report = Report(fixture, {{0x1000, 7, L"outside", {}}}, {0x1006});
		EXPECT_EQ((std::set<uint32_t>{0x1003}), Required(FirstRegion(report)));
	}

	TEST(CfgReportTest, LoopRetainsSelfEdgeWithoutClaimingFutureExecution)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0x90, 0x75, 0xfd, 0xc3});
		const auto report = Report(fixture, {{0x1000, 4, L"loop", {}}}, {0x1003});
		const auto& region = FirstRegion(report);
		EXPECT_EQ((std::set<uint32_t>{0x1000}), Required(region));
		bool self = false;
		for (const auto& edge : region.get_child("edges"))
			self = self || (edge.second.get<uint32_t>("from") == 0x1000 &&
				edge.second.get<uint32_t>("to") == 0x1000);
		EXPECT_TRUE(self);
	}

	TEST(CfgReportTest, SupplementalLateSplitKeepsDecodedFallthroughAndOriginalMeasurementSite)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0x90, 0x90, 0xc3});
		const auto graph = BasicBlockDiscovery{}.DiscoverGraph(PeImage(fixture.bytes), {0x1001});
		ExpectBlocks(graph.catalogBlocks, {{0x1000, 3}});
		ExpectBlocks(graph.blocks, {{0x1000, 1}, {0x1001, 2}});
		EXPECT_TRUE(std::any_of(graph.edges.begin(), graph.edges.end(), [](const DecodedEdge& edge) {
			return edge.from == 0x1000 && edge.to == 0x1001 && edge.kind == FlowKind::Fallthrough;
		}));
		const auto report = Report(fixture,
			{{0x1000, 1, L"first", {}}, {0x1001, 2, L"interior", {}}}, {0x1000});
		const auto& regions = report.get_child("modules").front().second.get_child("functions");
		const auto& interior = regions.back().second;
		ASSERT_EQ(1u, interior.get_child("nodes").size());
		EXPECT_EQ("null", interior.get_child("nodes").front().second.get<std::string>("measuredSite"));
		EXPECT_TRUE(Required(interior).empty());
	}

	TEST(CfgReportTest, DirectCallsAreOpaqueAndContinuationIsConditional)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0xe8, 0x0b, 0, 0, 0, 0xc3});
		fixture.Code(0x1010, {0xc3});
		const auto report = Report(fixture,
			{{0x1000, 6, L"caller", {}}, {0x1010, 1, L"callee", {}}}, {0x1005});
		const auto& regions = report.get_child("modules").front().second.get_child("functions");
		EXPECT_EQ((std::set<uint32_t>{0x1000}), Required(regions.front().second));
		EXPECT_TRUE(Required(regions.back().second).empty());
		std::set<std::string> kinds;
		for (const auto& edge : regions.front().second.get_child("edges"))
			kinds.insert(edge.second.get<std::string>("kind"));
		EXPECT_EQ((std::set<std::string>{"opaque-direct-call", "conditional-normal-return"}), kinds);
	}

	TEST(CfgReportTest, ImportCallsAreOpaqueWithoutTreatingIatAsCode)
	{
		PeFixture fixture;
		fixture.Directory(1, 0x2100, 40);
		fixture.Rva(0x2100, 0x2200);
		fixture.Rva(0x2110, 0x1100);
		fixture.Rva(0x2200, 0x8000000000000001, 8);
		fixture.Rva(0x1100, PeFixture::Base + 0x1040, 8);
		fixture.Rva(0x1108, 0, 8);
		fixture.Code(0x1000, {0xff, 0x15, 0xfa, 0, 0, 0, 0xc3});
		const auto report = Report(fixture, {{0x1000, 7, L"import", {}}}, {0x1006});
		EXPECT_EQ((std::set<uint32_t>{0x1000}), Required(FirstRegion(report)));
		std::set<std::string> kinds;
		for (const auto& edge : FirstRegion(report).get_child("edges"))
			kinds.insert(edge.second.get<std::string>("kind"));
		EXPECT_EQ((std::set<std::string>{"opaque-import-call", "conditional-normal-return"}), kinds);
	}

	TEST(CfgReportTest, IndirectTransfersTrapsAmbiguityAndEligibilityAreExcluded)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0xff, 0xd0, 0xc3});
		auto report = Report(fixture, {{0x1000, 3, L"indirect", {}}}, {0x1002});
		EXPECT_EQ("unresolved-indirect-call", FirstRegion(report).get<std::string>("exclusion"));
		EXPECT_TRUE(Required(FirstRegion(report)).empty());
		fixture.Code(0x1000, {0xff, 0xe0});
		report = Report(fixture, {{0x1000, 2, L"jump", {}}}, {0x1000});
		EXPECT_EQ("unresolved-indirect-jump", FirstRegion(report).get<std::string>("exclusion"));
		fixture.Code(0x1000, {0xcc});
		report = Report(fixture, {{0x1000, 1, L"trap", {}}}, {0x1000});
		EXPECT_EQ("context-transfer-or-trap", FirstRegion(report).get<std::string>("exclusion"));
		fixture.Code(0x1000, {0x90, 0xc3});
		report = Report(fixture, {{0x1000, 2, L"a", {}}, {0x1001, 1, L"b", {}}}, {0x1000});
		EXPECT_EQ("ambiguous-overlapping-function-ranges", FirstRegion(report).get<std::string>("exclusion"));
		report = Report(fixture, {{0x1000, 2, L"eh", "eh-split-or-naked-function"}}, {0x1000});
		EXPECT_EQ("eh-split-or-naked-function", FirstRegion(report).get<std::string>("exclusion"));
	}

	TEST(CfgReportTest, Arm64GraphAndUnicodeSourceAttributionDoNotChangeImplications)
	{
		PeFixture fixture(0xaa64);
		fixture.Rva(0x1000, 0x14000001);
		fixture.Rva(0x1004, 0xd65f03c0);
		const std::wstring name = L"quote\" slash\\ newline\n \u03bb \U0001f600";
		const auto report = Report(fixture, {{0x1000, 8, name, {}}}, {0x1004},
			{{L"source\\quote\".cpp", IDebugInformationHandler::Line(7, 0x1000, 1, 8)}});
		EXPECT_EQ((std::set<uint32_t>{0x1000}), Required(FirstRegion(report)));
		ASSERT_EQ(2u, FirstRegion(report).get_child("nodes").size());
		for (const auto& node : FirstRegion(report).get_child("nodes"))
			EXPECT_EQ(7, node.second.get_child("source").front().second.get<int>("line"));
	}

	TEST(CfgReportTest, HybridOverridesAndOverlappingDecodesHaveNoImplications)
	{
		PeFixture fixture;
		fixture.Hybrid(0xa641);
		auto report = Report(fixture, {{0x1000, 5, L"hybrid", {}}}, {0x1000});
		EXPECT_EQ("hybrid-or-dynamic-relocation-image",
			report.get_child("modules").front().second.get<std::string>("exclusion"));
		EXPECT_TRUE(Required(FirstRegion(report)).empty());
		PeFixture overrideFixture;
		overrideFixture.Code(0x1000, {0xe9, 0x3b, 0, 0, 0});
		overrideFixture.Code(0x1040, {0xc3});
		overrideFixture.Code(0x1060, {0xc3});
		overrideFixture.FunctionOverride(1);
		report = Report(overrideFixture, {{0x1000, 5, L"override", {}}}, {0x1000});
		EXPECT_EQ("hybrid-or-dynamic-relocation-image",
			report.get_child("modules").front().second.get<std::string>("exclusion"));
		PeFixture overlap;
		overlap.Code(0x1000, {0xb8, 0, 0, 0, 0, 0xeb, 0xfa});
		report = Report(overlap, {{0x1000, 7, L"overlap", {}}}, {});
		EXPECT_EQ("decode-overlap-or-resource-failure",
			report.get_child("modules").front().second.get<std::string>("exclusion"));
	}

	TEST(CfgReportTest, MissingBytesAndUnwindHandlersAreExcluded)
	{
		PeFixture fixture;
		fixture.Put(0x190, 2);
		fixture.Code(0x1000, {0x90, 0x0f});
		auto report = Report(fixture, {{0x1000, 2, L"truncated", {}}}, {0x1000});
		EXPECT_NE("null", FirstRegion(report).get<std::string>("exclusion"));
		EXPECT_TRUE(Required(FirstRegion(report)).empty());
		PeFixture eh;
		eh.Code(0x1000, {0xc3});
		eh.Code(0x1020, {0xc3});
		eh.Directory(3, 0x2000, 12);
		eh.Rva(0x2000, 0x1000);
		eh.Rva(0x2004, 0x1001);
		eh.Rva(0x2008, 0x2080);
		eh.Rva(0x2080, 9, 1);
		eh.Rva(0x2084, 0x1020);
		report = Report(eh, {{0x1000, 1, L"handler", {}}}, {0x1000});
		EXPECT_EQ("eh-or-chained-unwind", FirstRegion(report).get<std::string>("exclusion"));
	}

	TEST(CfgReportTest, DecodeAndNodeLimitsExcludeRatherThanTruncateProofs)
	{
		PeFixture fixture;
		fixture.ResizeText(100002);
		fixture.Put(0x200 + 100001, 0xc3, 1);
		auto report = Report(fixture, {{0x1000, 100002, L"large", {}}}, {});
		EXPECT_EQ("decode-overlap-or-resource-failure",
			report.get_child("modules").front().second.get<std::string>("exclusion"));
		PeFixture nodes;
		nodes.ResizeText(1027);
		for (unsigned i = 0; i < 513; ++i)
			nodes.Code(0x1000 + 2 * i, {0xeb, 0});
		nodes.Code(0x1000 + 1026, {0xc3});
		report = Report(nodes, {{0x1000, 1027, L"nodes", {}}}, {});
		EXPECT_EQ("region-node-limit", FirstRegion(report).get<std::string>("exclusion"));
		EXPECT_TRUE(Required(FirstRegion(report)).empty());
		PeFixture implications;
		implications.ResizeText(201);
		std::vector<uint32_t> hits;
		for (unsigned i = 0; i < 100; ++i)
		{
			implications.Code(0x1000 + 2 * i, {0xeb, 0});
			hits.push_back(0x1000 + 2 * i);
		}
		implications.Code(0x1000 + 200, {0xc3});
		hits.push_back(0x1000 + 200);
		report = Report(implications, {{0x1000, 201, L"implication-limit", {}}}, hits);
		EXPECT_EQ("implication-output-limit", FirstRegion(report).get<std::string>("exclusion"));
		EXPECT_TRUE(Required(FirstRegion(report)).empty());
	}

	TEST(CfgReportTest, CatalogMismatchExcludesAndUnobservedSitesRemainUnknown)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0x90, 0xeb, 0, 0xc3});
		auto report = Report(fixture, {{0x1000, 4, L"catalog", {}}}, {0x1003}, {}, true);
		EXPECT_EQ("catalog-layout-mismatch",
			report.get_child("modules").front().second.get<std::string>("exclusion"));
		EXPECT_TRUE(Required(FirstRegion(report)).empty());
		report = Report(fixture, {{0x1000, 4, L"sampled", {}}}, {0x1003}, {}, false, true);
		EXPECT_EQ((std::set<uint32_t>{0x1000}), Required(FirstRegion(report)));
		const auto& site = FirstRegion(report).get_child("nodes").front().second.get_child("measuredSite");
		EXPECT_FALSE(site.get<bool>("selected"));
		EXPECT_FALSE(site.get<bool>("observed"));
		EXPECT_FALSE(site.get<bool>("executed"));
		const auto& original = report.get_child("modules").front().second.get_child("measuredSites").front().second;
		EXPECT_FALSE(original.get<bool>("selected"));
		EXPECT_FALSE(original.get<bool>("observed"));
		EXPECT_FALSE(original.get<bool>("executed"));
	}

	TEST(BasicBlockDiscoveryTest, Amd64CallsBranchesAndReturnSites)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0x75, 0x05, 0xe8, 0x09, 0, 0, 0, 0xeb, 0x02, 0xcc, 0xcc, 0xc3});
		fixture.Code(0x1010, {0x90, 0xc3});
		ExpectBlocks(fixture.Discover(),
			{{0x1000, 2}, {0x1002, 5}, {0x1007, 2}, {0x100b, 1}, {0x1010, 2}});
	}

	TEST(BasicBlockDiscoveryTest, BackwardTargetSplitsAnAlreadyDecodedBlock)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0x90, 0x90, 0x75, 0xfd, 0xc3});
		ExpectBlocks(fixture.Discover(), {{0x1000, 1}, {0x1001, 3}, {0x1004, 1}});
	}

	TEST(BasicBlockDiscoveryTest, Amd64InstructionsCrossChunksAndRejectInteriorTargets)
	{
		PeFixture fixture;
		fixture.ResizeText(64 * 1024 + 6);
		const size_t instruction = 0x200 + 64 * 1024 - 2;
		fixture.Put(instruction, 0x00000000b8, 5);
		fixture.Put(instruction + 5, 0xf975, 2);
		fixture.Put(instruction + 7, 0xc3, 1);
		ExpectBlocks(fixture.Discover(),
		    {{0x1000, 64 * 1024 - 2}, {0x10ffe, 7}, {0x11005, 1}});
		fixture.Put(instruction + 6, 0xfb, 1);
		EXPECT_THROW(fixture.Discover(), wil::ResultException);
	}

	TEST(BasicBlockDiscoveryTest, Arm64LinearBlocksContinueAcrossChunks)
	{
		PeFixture fixture(0xaa64);
		const uint32_t size = 64 * 1024 + 8;
		fixture.ResizeText(size);
		for (uint32_t offset = 0; offset < size - 4; offset += 4)
			fixture.Put(0x200 + offset, 0xd503201f);
		fixture.Put(0x200 + size - 4, 0xd65f03c0);
		ExpectBlocks(fixture.Discover(), {{0x1000, size}}, InstructionSet::Arm64);
	}

	TEST(BasicBlockDiscoveryTest, SparseHighRvasDoNotRequireAnImageSizedWorkspace)
	{
		PeFixture fixture;
		fixture.ResizeText(0x400, 0x70001000);
		fixture.Put(0x200, 0xc3, 1);
		ExpectBlocks(fixture.Discover(), {{0x70001000, 1}});
	}

	TEST(BasicBlockDiscoveryTest, InvalidDecodeKeepsOnlyCoveredInstructions)
	{
		PeFixture fixture;
		fixture.Put(0x190, 2);
		fixture.Code(0x1000, {0x90, 0x0f});
		ExpectBlocks(fixture.Discover(), {{0x1000, 1}});
		fixture.Code(0x1000, {0x0f});
		EXPECT_TRUE(fixture.Discover().empty());
	}

	TEST(BasicBlockDiscoveryTest, ReturnAndIndirectJumpDoNotSweepUnreachableCode)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0xc3, 0x90, 0xc3});
		ExpectBlocks(fixture.Discover(), {{0x1000, 1}});
		fixture.Code(0x1000, {0xff, 0xe0, 0x90, 0xc3});
		ExpectBlocks(fixture.Discover(), {{0x1000, 2}});
		fixture.Code(0x1000, {0xff, 0xd0, 0xc3});
		ExpectBlocks(fixture.Discover(), {{0x1000, 2}, {0x1002, 1}});
	}

	TEST(BasicBlockDiscoveryTest, UndefinedInstructionsTerminateAmd64Paths)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0x0f, 0x0b, 0x90, 0xc3});
		ExpectBlocks(fixture.Discover(), {{0x1000, 2}});
		fixture.Code(0x1000, {0x0f, 0xb9, 0xc0, 0x90, 0xc3});
		ExpectBlocks(fixture.Discover(), {{0x1000, 2}});
	}

	TEST(BasicBlockDiscoveryTest, OverlappingTargetsFailClosed)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0xb8, 0, 0, 0, 0, 0xeb, 0xfa});
		EXPECT_THROW(fixture.Discover(), wil::ResultException);
		fixture.Code(0x1000, {0xb8, 0, 0, 0, 0, 0xc3});
		fixture.Exports({0x1001});
		EXPECT_THROW(fixture.Discover(), wil::ResultException);
	}

	TEST(BasicBlockDiscoveryTest, Arm64ConditionalCallsAndDirectBranches)
	{
		PeFixture fixture(0xaa64);
		fixture.Rva(0x1000, 0xb4000060);
		fixture.Rva(0x1004, 0x94000003);
		fixture.Rva(0x1008, 0x14000003);
		fixture.Rva(0x100c, 0xd65f03c0);
		fixture.Rva(0x1010, 0xd503201f);
		fixture.Rva(0x1014, 0xd65f03c0);
		ExpectBlocks(fixture.Discover(), {{0x1000, 4}, {0x1004, 4}, {0x1008, 4},
			{0x100c, 4}, {0x1010, 4}, {0x1014, 4}}, InstructionSet::Arm64);
	}

	TEST(BasicBlockDiscoveryTest, Arm64IndirectCallsTrapsAndAlignment)
	{
		PeFixture fixture(0xaa64);
		fixture.Rva(0x1000, 0xd63f0200);
		fixture.Rva(0x1004, 0xd4200000);
		fixture.Rva(0x1008, 0xd65f03c0);
		ExpectBlocks(fixture.Discover(), {{0x1000, 4}, {0x1004, 4}}, InstructionSet::Arm64);
		fixture.Put(0xa8, 0x1001);
		EXPECT_TRUE(fixture.Discover().empty());
	}

	TEST(BasicBlockDiscoveryTest, ExportsIgnoreForwardersAndNonExecutableData)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0xc3});
		fixture.Code(0x1040, {0xc3});
		fixture.Exports({0x1040, 0x2060, 0x2200, 0});
		ExpectBlocks(fixture.Discover(), {{0x1000, 1}, {0x1040, 1}});
	}

	TEST(BasicBlockDiscoveryTest, Amd64RuntimeFunctionsHandlersAndChains)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0xc3});
		for (const auto rva : {0x1020u, 0x1030u, 0x1040u, 0x1060u})
			fixture.Code(rva, {0xc3});
		fixture.Directory(3, 0x2100, 24);
		fixture.Rva(0x2100, 0x1020);
		fixture.Rva(0x2104, 0x1021);
		fixture.Rva(0x2108, 0x2180);
		fixture.Rva(0x210c, 0x1030);
		fixture.Rva(0x2110, 0x1031);
		fixture.Rva(0x2114, 0x2190);
		fixture.Rva(0x2180, 9);
		fixture.Rva(0x2184, 0x1060);
		fixture.Rva(0x2190, 0x21);
		fixture.Rva(0x2194, 0x1040);
		fixture.Rva(0x2198, 0x1041);
		fixture.Rva(0x219c, 0x21b0);
		fixture.Rva(0x21b0, 1);
		ExpectBlocks(fixture.Discover(),
			{{0x1000, 1}, {0x1020, 1}, {0x1030, 1}, {0x1040, 1}, {0x1060, 1}});
		fixture.Rva(0x219c, 0x210d);
		EXPECT_THROW(PeImage(fixture.bytes), wil::ResultException);
	}

	TEST(BasicBlockDiscoveryTest, Arm64RuntimeFunctionsPackedUnpackedHandlersAndLinks)
	{
		PeFixture fixture(0xaa64);
		for (const auto rva : {0x1000u, 0x1020u, 0x1040u, 0x1060u, 0x1080u})
			fixture.Rva(rva, 0xd65f03c0);
		fixture.Directory(3, 0x2100, 24);
		fixture.Rva(0x2100, 0x1020);
		fixture.Rva(0x2104, 5);
		fixture.Rva(0x2108, 0x1040);
		fixture.Rva(0x210c, 0x2180);
		fixture.Rva(0x2110, 0x1080);
		fixture.Rva(0x2114, 0x2103);
		fixture.Rva(0x2180, 1u | (1u << 20) | (1u << 21) | (1u << 27));
		fixture.Rva(0x2184, 0xe4);
		fixture.Rva(0x2188, 0x1060);
		ExpectBlocks(fixture.Discover(), {{0x1000, 4}, {0x1020, 4}, {0x1040, 4},
			{0x1060, 4}, {0x1080, 4}}, InstructionSet::Arm64);
		fixture.Rva(0x2104, 0x2113);
		EXPECT_THROW(PeImage(fixture.bytes), wil::ResultException);
	}

	TEST(BasicBlockDiscoveryTest, TlsCfgAndEhContinuationTargets)
	{
		PeFixture fixture;
		for (const auto rva : {0x1000u, 0x1040u, 0x1060u, 0x1080u, 0x10a0u})
			fixture.Code(rva, {0xc3});
		fixture.Directory(9, 0x2100, 40);
		fixture.Rva(0x2118, PeFixture::Base + 0x2180, 8);
		fixture.Rva(0x2180, PeFixture::Base + 0x1040, 8);
		fixture.Rva(0x2188, 0x7ff000001000, 8);
		fixture.Directory(10, 0x2200, 280);
		fixture.Rva(0x2200, 280);
		fixture.Rva(0x2280, PeFixture::Base + 0x2400, 8);
		fixture.Rva(0x2288, 2, 8);
		fixture.Rva(0x2290, 0x10000400);
		fixture.Rva(0x2400, 0x1060);
		fixture.Rva(0x2404, 0, 1);
		fixture.Rva(0x2405, 0x1080);
		fixture.Rva(0x2409, 0, 1);
		fixture.Rva(0x2308, PeFixture::Base + 0x2480, 8);
		fixture.Rva(0x2310, 1, 8);
		fixture.Rva(0x2480, 0x10a0);
		ExpectBlocks(fixture.Discover(),
			{{0x1000, 1}, {0x1040, 1}, {0x1060, 1}, {0x1080, 1}, {0x10a0, 1}});
	}

	TEST(BasicBlockDiscoveryTest, DelayImportThunksAreRootsButIatIsData)
	{
		PeFixture fixture;
		fixture.Directory(13, 0x2100, 64);
		fixture.Rva(0x2100, 1);
		fixture.Rva(0x210c, 0x1100);
		fixture.Rva(0x2110, 0x2200);
		fixture.Rva(0x2118, 0x2240);
		fixture.Rva(0x2200, 0x8000000000000001, 8);
		fixture.Rva(0x1100, PeFixture::Base + 0x1040, 8);
		fixture.Rva(0x1108, 0, 8);
		fixture.Rva(0x2240, PeFixture::Base + 0x1060, 8);
		fixture.Code(0x1000, {0xff, 0x15, 0xfa, 0, 0, 0, 0xc3});
		fixture.Code(0x1040, {0xc3});
		fixture.Code(0x1060, {0xc3});
		const PeImage image(fixture.bytes);
		EXPECT_TRUE(image.IsImportSlot(0x1100));
		EXPECT_FALSE(image.GetCode(0x1100).data);
		ExpectBlocks(BasicBlockDiscovery().Discover(image),
			{{0x1000, 6}, {0x1006, 1}, {0x1040, 1}, {0x1060, 1}});
	}

	TEST(BasicBlockDiscoveryTest, RegularBoundImportsNeverBecomeLocalCodeRoots)
	{
		PeFixture fixture;
		fixture.Directory(1, 0x2100, 40);
		fixture.Rva(0x2100, 0x2200);
		fixture.Rva(0x2110, 0x1100);
		fixture.Rva(0x2200, 0x8000000000000001, 8);
		fixture.Rva(0x1100, PeFixture::Base + 0x1040, 8);
		fixture.Rva(0x1108, 0, 8);
		fixture.Code(0x1000, {0xff, 0x25, 0xfa, 0, 0, 0, 0xc3});
		fixture.Code(0x1040, {0xc3});
		ExpectBlocks(fixture.Discover(), {{0x1000, 6}});
	}

	TEST(BasicBlockDiscoveryTest, HybridCodeMapOverridesAllSupportedHeaderVariants)
	{
		for (const uint16_t machine : {uint16_t{0x8664}, uint16_t{0xa641},
			uint16_t{0xaa64}, uint16_t{0xa64e}})
		{
			SCOPED_TRACE(machine);
			PeFixture fixture;
			fixture.Hybrid(machine);
			const PeImage image(fixture.bytes);
			const auto blocks = BasicBlockDiscovery().Discover(image);
			ASSERT_EQ(4u, blocks.size());
			EXPECT_EQ(0x1000u, blocks[0].rva);
			EXPECT_EQ(5u, blocks[0].size);
			EXPECT_EQ(InstructionSet::Amd64, blocks[0].instructionSet);
			EXPECT_EQ(0x1020u, blocks[1].rva);
			EXPECT_EQ(InstructionSet::Arm64, blocks[1].instructionSet);
			EXPECT_EQ(0x1040u, blocks[2].rva);
			EXPECT_EQ(InstructionSet::Arm64, blocks[2].instructionSet);
			EXPECT_EQ(0x1060u, blocks[3].rva);
			EXPECT_EQ(InstructionSet::Amd64, blocks[3].instructionSet);
			EXPECT_FALSE(image.GetCode(0x1080).data);
		}
	}

	TEST(BasicBlockDiscoveryTest, MalformedOrUnknownHybridMetadataFailsClosed)
	{
		PeFixture fixture(0xa641);
		EXPECT_THROW(PeImage(fixture.bytes), wil::ResultException);
		fixture.Hybrid(0xa641);
		fixture.Rva(0x2300, 3);
		EXPECT_THROW(PeImage(fixture.bytes), wil::ResultException);
		fixture.Rva(0x2300, 2);
		fixture.Rva(0x2308, 0xffffffff);
		EXPECT_THROW(PeImage(fixture.bytes), wil::ResultException);
		fixture.Rva(0x2308, 4);
		fixture.Rva(0x2388, 0x1020 | 3);
		EXPECT_THROW(PeImage(fixture.bytes), wil::ResultException);
		fixture.Rva(0x2388, 0x1000 | 1);
		EXPECT_THROW(PeImage(fixture.bytes), wil::ResultException);
	}

	TEST(BasicBlockDiscoveryTest, HybridEntryAndRedirectionTablesProvideIndependentRoots)
	{
		PeFixture fixture;
		fixture.Hybrid(0xa641);
		fixture.Rva(0x230c, 0x2420);
		fixture.Rva(0x2330, 1);
		fixture.Rva(0x2420, 0x1030);
		fixture.Rva(0x2424, 0x1034);
		fixture.Rva(0x2428, 0x1040);
		fixture.Rva(0x2310, 0x2440);
		fixture.Rva(0x2334, 1);
		fixture.Rva(0x2440, 0x1070);
		fixture.Rva(0x2444, 0x1030);
		fixture.Rva(0x1030, 0xd65f03c0);
		fixture.Code(0x1070, {0xc3});
		const auto blocks = fixture.Discover();
		ASSERT_EQ(6u, blocks.size());
		EXPECT_EQ(0x1030u, blocks[2].rva);
		EXPECT_EQ(InstructionSet::Arm64, blocks[2].instructionSet);
		EXPECT_EQ(0x1070u, blocks[5].rva);
		EXPECT_EQ(InstructionSet::Amd64, blocks[5].instructionSet);
	}

	TEST(BasicBlockDiscoveryTest, DecodeCannotCrossAChpeCodeMapBoundary)
	{
		PeFixture fixture;
		fixture.Hybrid(0xa641);
		fixture.Rva(0x2384, 4);
		const auto blocks = fixture.Discover();
		ASSERT_EQ(3u, blocks.size());
		EXPECT_EQ(0x1020u, blocks[0].rva);
		EXPECT_EQ(0x1040u, blocks[1].rva);
		EXPECT_EQ(0x1060u, blocks[2].rva);
	}

	TEST(BasicBlockDiscoveryTest, Arm64FallthroughContinuesAcrossCompatibleCodeMapRanges)
	{
		PeFixture fixture;
		fixture.Hybrid(0xa641);
		fixture.Rva(0x1020, 0xd503201f);
		fixture.Rva(0x238c, 4);
		fixture.Rva(0x2390, 0x1024);
		fixture.Rva(0x2394, 0x3c);
		fixture.Rva(0x1024, 0xd65f03c0);
		const auto blocks = fixture.Discover();
		ASSERT_EQ(4u, blocks.size());
		EXPECT_EQ(0x1020u, blocks[1].rva);
		EXPECT_EQ(8u, blocks[1].size);
	}

	TEST(BasicBlockDiscoveryTest, MetadataCountsAndExtentsAreCheckedBeforeAccess)
	{
		PeFixture fixture;
		fixture.Exports({0x1040});
		fixture.Rva(0x2014, 0xffffffff);
		EXPECT_THROW(PeImage(fixture.bytes), wil::ResultException);
		fixture.Rva(0x2014, 1);
		fixture.Rva(0x201c, 0xfffffff0);
		EXPECT_THROW(PeImage(fixture.bytes), wil::ResultException);
		fixture = PeFixture();
		fixture.Directory(10, 0x2100, 280);
		fixture.Rva(0x2100, 280);
		fixture.Rva(0x2180, PeFixture::Base + 0x2200, 8);
		fixture.Rva(0x2188, 0xffffffffffffffff, 8);
		EXPECT_THROW(PeImage(fixture.bytes), wil::ResultException);
	}

	TEST(BasicBlockDiscoveryTest, TruncatedHeadersSectionsAndVirtualTailsAreRejected)
	{
		const PeFixture fixture;
		for (const auto size : {0u, 1u, 63u, 0x90u, 0x100u, 0x1ffu, 0x159fu})
		{
			SCOPED_TRACE(size);
			std::vector<uint8_t> truncated(fixture.bytes.begin(), fixture.bytes.begin() + size);
			EXPECT_THROW(PeImage(std::move(truncated)), wil::ResultException);
		}
		auto bad = fixture;
		bad.Put(0x1bc, 0x1100);
		EXPECT_THROW(PeImage(bad.bytes), wil::ResultException);
		bad = fixture;
		bad.Put(0x1c4, 0x400);
		EXPECT_THROW(PeImage(bad.bytes), wil::ResultException);
		bad = fixture;
		bad.Put(0x190, 0x800);
		bad.Put(0xa8, 0x1500);
		EXPECT_TRUE(bad.Discover().empty());
	}

	TEST(BasicBlockDiscoveryTest, CodeViewAndExactFileHashIdentifyTheImage)
	{
		PeFixture fixture;
		fixture.Directory(6, 0x2100, 28);
		fixture.Rva(0x210c, 2);
		fixture.Rva(0x2110, 24);
		fixture.Rva(0x2114, 0x2180);
		fixture.Rva(0x2118, fixture.Offset(0x2180));
		fixture.Rva(0x2180, 0x53445352);
		for (size_t i = 0; i < 16; ++i)
			fixture.Put(fixture.Offset(0x2184) + i, i + 1, 1);
		fixture.Rva(0x2194, 7);
		const PeImage first(fixture.bytes);
		const auto& identity = first.Identity();
		EXPECT_EQ(0x12345678u, identity.timeDateStamp);
		EXPECT_EQ(0xabcdefu, identity.checksum);
		EXPECT_EQ(7u, identity.pdbAge);
		EXPECT_EQ(16u, identity.pdbGuid.back());
		EXPECT_EQ(identity.imageHash, PeImage(fixture.bytes).Identity().imageHash);
		fixture.bytes.push_back(1);
		const PeImage changed(fixture.bytes);
		EXPECT_EQ(identity.timeDateStamp, changed.Identity().timeDateStamp);
		EXPECT_EQ(identity.checksum, changed.Identity().checksum);
		EXPECT_NE(identity.imageHash, changed.Identity().imageHash);
	}

	TEST(BasicBlockDiscoveryTest, MappedCodeComparisonNormalizesOnlyDir64Relocations)
	{
		PeFixture fixture;
		fixture.Code(0x1000, {0x48, 0xb8});
		fixture.Rva(0x1002, PeFixture::Base + 0x2200, 8);
		fixture.Code(0x100a, {0xc3});
		fixture.Directory(5, 0x2100, 12);
		fixture.Rva(0x2100, 0x1000);
		fixture.Rva(0x2104, 12);
		fixture.Rva(0x2108, 0xa002, 2);
		const PeImage image(fixture.bytes);
		const auto code = image.GetCode(0x1000);
		std::vector<uint8_t> live(code.data, code.data + 11);
		EXPECT_TRUE(image.MatchesMappedCode(0x1000, live.data(), live.size(), PeFixture::Base));
		const auto relocatedBase = PeFixture::Base + 0x100000;
		for (size_t i = 0; i < 8; ++i)
			live[2 + i] = static_cast<uint8_t>((relocatedBase + 0x2200) >> (8 * i));
		EXPECT_TRUE(image.MatchesMappedCode(0x1000, live.data(), live.size(), relocatedBase));
		EXPECT_TRUE(image.MatchesMappedCode(0x1004, live.data() + 4, 4, relocatedBase));
		EXPECT_FALSE(image.MatchesMappedCode(0x1000, live.data(), live.size(), PeFixture::Base));
		live[0] ^= 1;
		EXPECT_FALSE(image.MatchesMappedCode(0x1000, live.data(), live.size(), relocatedBase));
		fixture.Rva(0x2108, 0x3002, 2);
		EXPECT_THROW(PeImage(fixture.bytes), wil::ResultException);
	}

	TEST(BasicBlockDiscoveryTest, Arm64FunctionOverridesUseMappedBranchesAndPreserveIdentity)
	{
		PeFixture fixture(0xaa64);
		fixture.FunctionOverride();
		fixture.Rva(0x1000, 0x14000010);
		for (const auto rva : {0x1004u, 0x1040u, 0x1060u, 0x1080u})
			fixture.Rva(rva, 0xd65f03c0);
		PeImage image(fixture.bytes);
		const auto identity = image.Identity();
		EXPECT_EQ(std::vector<uint32_t>{0x1000}, image.FunctionOverrideRelocations());
		const auto code = image.GetCode(0x1000);
		std::vector<uint8_t> live(code.data, code.data + 8);
		live[0] = 0x20;
		EXPECT_FALSE(image.MatchesMappedCode(0x1000, live.data(), live.size(), PeFixture::Base));
		image.ApplyFunctionOverrideRelocation(0x1000, 0x14000020);
		EXPECT_EQ(identity.imageHash, image.Identity().imageHash);
		EXPECT_TRUE(image.MatchesMappedCode(0x1000, live.data(), live.size(), PeFixture::Base));
		ExpectBlocks(BasicBlockDiscovery{}.Discover(image),
			{{0x1000, 4}, {0x1040, 4}, {0x1060, 4}, {0x1080, 4}}, InstructionSet::Arm64);
		EXPECT_THROW(image.ApplyFunctionOverrideRelocation(0x1000, 0x94000020), wil::ResultException);
		EXPECT_THROW(image.ApplyFunctionOverrideRelocation(0x1004, 0x14000020), wil::ResultException);
		live[4] ^= 1;
		EXPECT_FALSE(image.MatchesMappedCode(0x1000, live.data(), live.size(), PeFixture::Base));
	}

	TEST(BasicBlockDiscoveryTest, Amd64FunctionOverridesSupportVersion2AndSectionRelativeTables)
	{
		PeFixture fixture;
		fixture.FunctionOverride(1, true, true);
		fixture.Code(0x1000, {0xe9, 0x3b, 0, 0, 0});
		for (const auto rva : {0x1040u, 0x1060u, 0x1080u})
			fixture.Code(rva, {0xc3});
		PeImage image(fixture.bytes);
		EXPECT_EQ(std::vector<uint32_t>{0x1001}, image.FunctionOverrideRelocations());
		image.ApplyFunctionOverrideRelocation(0x1001, 0x7b);
		ExpectBlocks(BasicBlockDiscovery{}.Discover(image),
			{{0x1000, 5}, {0x1040, 1}, {0x1060, 1}, {0x1080, 1}});
		const auto code = image.GetCode(0x1000);
		std::vector<uint8_t> live(code.data, code.data + 5);
		EXPECT_TRUE(image.MatchesMappedCode(0x1000, live.data(), live.size(), PeFixture::Base));
		live[0] = 0xe8;
		EXPECT_FALSE(image.MatchesMappedCode(0x1000, live.data(), live.size(), PeFixture::Base));
	}

	TEST(BasicBlockDiscoveryTest, MalformedAndOverlappingFunctionOverridesFailClosed)
	{
		PeFixture fixture(0xaa64);
		fixture.FunctionOverride();
		fixture.Rva(0x1000, 0x14000010);
		for (const auto& change : {
			std::pair<uint32_t, uint32_t>{0x2300, 3}, {0x2304, 63},
			{0x2314, 31}, {0x2318, 0x3000}, {0x231c, 0x100000},
			{0x2320, 6}, {0x2330, 0}, {0x2334, 0x3000},
			{0x2334, 0x20002000}, {0x2338, 2}, {0x233c, 16}})
		{
			auto bad = fixture;
			bad.Rva(change.first, change.second);
			EXPECT_THROW(PeImage(bad.bytes), wil::ResultException) << std::hex << change.first;
		}
		fixture.Directory(5, 0x2500, 12);
		fixture.Rva(0x2500, 0x1000);
		fixture.Rva(0x2504, 12);
		fixture.Rva(0x2508, 0xa000, 2);
		EXPECT_THROW(PeImage(fixture.bytes), wil::ResultException);
	}

	TEST(BasicBlockDiscoveryTest, TruncatedAndOverlappingCodeRelocationsFailClosed)
	{
		PeFixture fixture;
		fixture.Directory(5, 0x2100, 12);
		fixture.Rva(0x2100, 0x1000);
		fixture.Rva(0x2104, 12);
		fixture.Rva(0x2108, 0xa002, 2);
		fixture.Rva(0x210a, 0xa006, 2);
		EXPECT_THROW(PeImage(fixture.bytes), wil::ResultException);
		fixture.Rva(0x210a, 0, 2);
		fixture.Rva(0x2104, 0);
		EXPECT_THROW(PeImage(fixture.bytes), wil::ResultException);
		fixture.Rva(0x2104, 12);
		fixture.Directory(5, 0x2100, 11);
		EXPECT_THROW(PeImage(fixture.bytes), wil::ResultException);
	}
}
