#include <gtest/gtest.h>

#include <wil/result.h>

#include "CppCoverage/BasicBlockDiscovery.hpp"

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
