#include "stdafx.h"

#include <wil/result.h>
#include <wil/resource.h>

#include "CppCoverage/ArchitectureBreakpoint.hpp"
#include "CppCoverage/BreakpointJournal.hpp"
#include "CppCoverage/ThreadSuspension.hpp"

#include <array>
#include <atomic>
#include <thread>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace CppCoverageTest
{
	namespace
	{
		using CppCoverage::ArchitectureBreakpoint;
		using CppCoverage::InstructionSet;
		bool failJournalRestore = false;
		int failedProtectionRestores = 0;
		int failedCacheFlushes = 0;

		class CodePage
		{
		public:
			explicit CodePage(size_t size = 4096)
			    : data{static_cast<unsigned char*>(VirtualAlloc(
			          nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))}
			{
				if (!data)
					throw std::runtime_error("VirtualAlloc failed");
				std::memset(data, 0x90, size);
			}

			~CodePage()
			{
				VirtualFree(data, 0, MEM_RELEASE);
			}

			uint64_t Address(size_t offset = 0) const
			{
				return reinterpret_cast<uint64_t>(data + offset);
			}

			unsigned char* data;
		};
	}

	TEST(ArchitectureBreakpointTest, Amd64PatchPreservesAdjacentInstructions)
	{
		CodePage page;
		ArchitectureBreakpoint patch{GetCurrentProcess(), page.Address(1), InstructionSet::Amd64};
		patch.Install();
		EXPECT_EQ(0x90, page.data[0]);
		EXPECT_EQ(0xcc, page.data[1]);
		EXPECT_EQ(0x90, page.data[2]);
		patch.Restore();
		EXPECT_EQ(0x90, page.data[1]);
	}

	TEST(ArchitectureBreakpointTest, Arm64PatchRestoresWholeInstructionAndProtection)
	{
		CodePage page;
		const std::array<unsigned char, 4> instruction{{0xe0, 0x03, 0x01, 0xaa}};
		std::memcpy(page.data + 4, instruction.data(), instruction.size());
		DWORD previous = 0;
		ASSERT_TRUE(VirtualProtect(page.data, 4096, PAGE_EXECUTE_READ, &previous));
		ArchitectureBreakpoint patch{GetCurrentProcess(), page.Address(4), InstructionSet::Arm64};
		patch.Install();
		const std::array<unsigned char, 4> brk{{0x00, 0x00, 0x3e, 0xd4}};
		EXPECT_EQ(0, std::memcmp(page.data + 4, brk.data(), brk.size()));
		EXPECT_EQ(0x90, page.data[3]);
		EXPECT_EQ(0x90, page.data[8]);
		patch.Restore();
		EXPECT_EQ(0, std::memcmp(page.data + 4, instruction.data(), instruction.size()));
		MEMORY_BASIC_INFORMATION memory{};
		ASSERT_NE(0u, VirtualQuery(page.data, &memory, sizeof(memory)));
		EXPECT_EQ(PAGE_EXECUTE_READ, memory.Protect);
	}

	TEST(ArchitectureBreakpointTest, Arm64RejectsMisalignedAndApplicationBreakpoints)
	{
		CodePage page;
		EXPECT_THROW(
		    ArchitectureBreakpoint(GetCurrentProcess(), page.Address(1), InstructionSet::Arm64),
		    wil::ResultException);
		const std::array<unsigned char, 4> applicationBrk{{0x20, 0x00, 0x20, 0xd4}};
		std::memcpy(page.data, applicationBrk.data(), applicationBrk.size());
		EXPECT_THROW(
		    ArchitectureBreakpoint(GetCurrentProcess(), page.Address(), InstructionSet::Arm64),
		    wil::ResultException);
		page.data[0] = 0xcc;
		EXPECT_THROW(
		    ArchitectureBreakpoint(GetCurrentProcess(), page.Address(), InstructionSet::Amd64),
		    wil::ResultException);
	}

	TEST(ArchitectureBreakpointTest, ChangedInstructionsAreNeverOverwritten)
	{
		CodePage page;
		ArchitectureBreakpoint patch{GetCurrentProcess(), page.Address(), InstructionSet::Amd64};
		page.data[0] = 0xc3;
		EXPECT_THROW(patch.Install(), wil::ResultException);
		EXPECT_EQ(0xc3, page.data[0]);
		page.data[0] = 0x90;
		patch.Install();
		page.data[0] = 0xc3;
		EXPECT_THROW(patch.Restore(), wil::ResultException);
		EXPECT_EQ(0xc3, page.data[0]);
	}

	TEST(ArchitectureBreakpointTest, ExistingApplicationTrapsRemainApplicationOwned)
	{
		const std::array<uint8_t, 4> twoByteInt3{{0xcd, 3, 0x90, 0x90}};
		EXPECT_TRUE(ArchitectureBreakpoint::IsApplicationTrap(
		    InstructionSet::Amd64, twoByteInt3.data(), twoByteInt3.size()));
		const std::array<uint8_t, 4> armBrk{{0, 0, 0x3e, 0xd4}};
		EXPECT_TRUE(ArchitectureBreakpoint::IsApplicationTrap(
		    InstructionSet::Arm64, armBrk.data(), armBrk.size()));
		const std::array<uint8_t, 4> armNop{{0x1f, 0x20, 3, 0xd5}};
		EXPECT_FALSE(ArchitectureBreakpoint::IsApplicationTrap(
		    InstructionSet::Arm64, armNop.data(), armNop.size()));
		EXPECT_THROW(ArchitectureBreakpoint::IsApplicationTrap(
		    InstructionSet::Arm64, armBrk.data(), 3), wil::ResultException);
	}

	TEST(ArchitectureBreakpointTest, QueuedHitsCanRestoreTheSameSite)
	{
		CodePage page;
		for (const auto instructionSet : {InstructionSet::Amd64, InstructionSet::Arm64})
		{
			ArchitectureBreakpoint::Instruction original{
			    {{0x1f, 0x20, 0x03, 0xd5}}, ArchitectureBreakpoint::Encoding(instructionSet).size};
			std::memcpy(page.data, original.bytes.data(), original.size);
			{
				ArchitectureBreakpoint first{
				    GetCurrentProcess(), page.Address(), instructionSet, original};
				first.Install();
				first.Restore();
			}
			ArchitectureBreakpoint queued{
			    GetCurrentProcess(), page.Address(), instructionSet, original};
			EXPECT_NO_THROW(queued.VerifyRestored());
			EXPECT_NO_THROW(queued.Restore());
			EXPECT_EQ(0, std::memcmp(page.data, original.bytes.data(), original.size));
			page.data[0] ^= 0xff;
			EXPECT_THROW(queued.VerifyRestored(), wil::ResultException);
		}
	}

	TEST(ArchitectureBreakpointTest, ProgramCounterResumesTheOriginalInstruction)
	{
		EXPECT_EQ(0x1000u, ArchitectureBreakpoint::ResumeAddress(
		    InstructionSet::Amd64, 0x1001, 0x1000));
		EXPECT_EQ(0x1000u, ArchitectureBreakpoint::ResumeAddress(
		    InstructionSet::Amd64, 0x1000, 0x1000));
		EXPECT_EQ(0x1000u, ArchitectureBreakpoint::ResumeAddress(
		    InstructionSet::Arm64, 0x1000, 0x1000));
		EXPECT_EQ(0x1000u, ArchitectureBreakpoint::ResumeAddress(
		    InstructionSet::Arm64, 0x1004, 0x1000));
		EXPECT_THROW(ArchitectureBreakpoint::ResumeAddress(
		    InstructionSet::Arm64, 0x1008, 0x1000), wil::ResultException);
		EXPECT_THROW(ArchitectureBreakpoint::ResumeAddress(
		    InstructionSet::Amd64, 0x2001, 0x1000), wil::ResultException);
		EXPECT_THROW(ArchitectureBreakpoint::ResumeAddress(
		    InstructionSet::Arm64, 0x1001, 0x1001), wil::ResultException);
		EXPECT_THROW(ArchitectureBreakpoint::ResumeAddress(
		    static_cast<InstructionSet>(0), 0x1000, 0x1000), wil::ResultException);
	}

	TEST(ArchitectureBreakpointTest, LargeRangePatchesMixedInstructionSetsAndPreservesOtherBytes)
	{
		const size_t size = 2 * 1024 * 1024;
		CodePage page(size + 4096);
		const std::array<uint8_t, 4> instruction{{0xe0, 0x03, 0x01, 0xaa}};
		std::memcpy(page.data + size - 4, instruction.data(), instruction.size());
		page.data[1024] = 0xcc;
		std::vector<uint8_t> original(page.data, page.data + size);
		ArchitectureBreakpoint first{GetCurrentProcess(), page.Address(1), InstructionSet::Amd64};
		ArchitectureBreakpoint last{GetCurrentProcess(), page.Address(size - 4), InstructionSet::Arm64};
		DWORD previous = 0;
		ASSERT_TRUE(VirtualProtect(page.data, size, PAGE_EXECUTE_READ, &previous));
		ArchitectureBreakpoint::InstallRange(
		    GetCurrentProcess(), page.Address(), original, {&first, &last});
		auto expected = original;
		expected[1] = 0xcc;
		const auto encoding = ArchitectureBreakpoint::Encoding(InstructionSet::Arm64);
		std::memcpy(expected.data() + size - 4, encoding.bytes.data(), encoding.size);
		EXPECT_EQ(0, std::memcmp(page.data, expected.data(), size));
		EXPECT_EQ(0x90, page.data[size]);
		MEMORY_BASIC_INFORMATION memory{};
		ASSERT_NE(0u, VirtualQuery(page.data, &memory, sizeof(memory)));
		EXPECT_EQ(PAGE_EXECUTE_READ, memory.Protect);
		first.Restore();
		last.Restore();
		EXPECT_EQ(0, std::memcmp(page.data, original.data(), size));
	}

	TEST(ArchitectureBreakpointTest, RangeInstallationRejectsChangedInstructionsAndNeighbors)
	{
		CodePage page;
		std::vector<uint8_t> original(page.data, page.data + 4096);
		ArchitectureBreakpoint patch{GetCurrentProcess(), page.Address(1), InstructionSet::Amd64};
		page.data[200] = 0xc3;
		EXPECT_THROW(ArchitectureBreakpoint::InstallRange(
		    GetCurrentProcess(), page.Address(), original, {&patch}), wil::ResultException);
		EXPECT_EQ(0x90, page.data[1]);
		EXPECT_EQ(0xc3, page.data[200]);
		original[200] = 0xc3;
		page.data[1] = 0xc3;
		original[1] = 0xc3;
		EXPECT_THROW(ArchitectureBreakpoint::InstallRange(
		    GetCurrentProcess(), page.Address(), original, {&patch}), wil::ResultException);
		EXPECT_EQ(0xc3, page.data[1]);
	}

	TEST(ArchitectureBreakpointTest, RangeInstallationRejectsProtectionBoundariesAndOverlappingPatches)
	{
		CodePage page(8192);
		std::vector<uint8_t> original(page.data, page.data + 8192);
		ArchitectureBreakpoint first{GetCurrentProcess(), page.Address(1), InstructionSet::Amd64};
		ArchitectureBreakpoint last{GetCurrentProcess(), page.Address(4096), InstructionSet::Amd64};
		DWORD previous = 0;
		ASSERT_TRUE(VirtualProtect(page.data + 4096, 4096, PAGE_READONLY, &previous));
		EXPECT_THROW(ArchitectureBreakpoint::InstallRange(
		    GetCurrentProcess(), page.Address(), original, {&first, &last}), wil::ResultException);
		original.resize(4096);
		EXPECT_THROW(ArchitectureBreakpoint::InstallRange(
		    GetCurrentProcess(), page.Address(), original, {&last}), wil::ResultException);
		EXPECT_THROW(ArchitectureBreakpoint::InstallRange(
		    GetCurrentProcess(), page.Address(), original, {&first, &first}), wil::ResultException);
		EXPECT_EQ(0x90, page.data[1]);
		EXPECT_EQ(0x90, page.data[4096]);
	}

	TEST(ArchitectureBreakpointTest, RangeWriteFailureRestoresProtection)
	{
		CodePage page;
		std::vector<uint8_t> original(page.data, page.data + 4096);
		wil::unique_handle process{OpenProcess(
		    PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
		    FALSE, GetCurrentProcessId())};
		ASSERT_TRUE(process);
		ArchitectureBreakpoint patch{process.get(), page.Address(), InstructionSet::Amd64};
		DWORD previous = 0;
		ASSERT_TRUE(VirtualProtect(page.data, 4096, PAGE_EXECUTE_READ, &previous));
		EXPECT_THROW(ArchitectureBreakpoint::InstallRange(
		    process.get(), page.Address(), original, {&patch}), wil::ResultException);
		MEMORY_BASIC_INFORMATION memory{};
		ASSERT_NE(0u, VirtualQuery(page.data, &memory, sizeof(memory)));
		EXPECT_EQ(PAGE_EXECUTE_READ, memory.Protect);
		EXPECT_EQ(0x90, page.data[0]);
	}

	TEST(ArchitectureBreakpointTest, JournalRollsBackPartialArm64WriteAndProtection)
	{
		CodePage page;
		DWORD previous = 0;
		ASSERT_TRUE(VirtualProtect(page.data, 4096, PAGE_EXECUTE_READ, &previous));
		CppCoverage::BreakpointJournal::Operations operations;
		operations.write = [](HANDLE process, LPVOID address, LPCVOID bytes,
		                      SIZE_T size, SIZE_T* count) -> BOOL {
			if (size == 4 && *static_cast<const uint8_t*>(bytes) == 0)
			{
				WriteProcessMemory(process, address, bytes, 2, count);
				SetLastError(ERROR_PARTIAL_COPY);
				return FALSE;
			}
			return WriteProcessMemory(process, address, bytes, size, count);
		};
		CppCoverage::BreakpointJournal journal{GetCurrentProcess(), operations};
		const std::array<uint8_t, 4> trap{{0, 0, 0x3e, 0xd4}};
		EXPECT_THROW(journal.Write(page.Address(), trap.data(), trap.size()), wil::ResultException);
		EXPECT_FALSE(journal.Empty());
		EXPECT_EQ(0, page.data[0]);
		EXPECT_EQ(0x90, page.data[2]);
		EXPECT_NO_THROW(journal.Rollback());
		EXPECT_TRUE(journal.Empty());
		for (size_t i = 0; i < 4; ++i)
			EXPECT_EQ(0x90, page.data[i]);
		MEMORY_BASIC_INFORMATION memory{};
		ASSERT_NE(0u, VirtualQuery(page.data, &memory, sizeof(memory)));
		EXPECT_EQ(PAGE_EXECUTE_READ, memory.Protect);
	}

	TEST(ArchitectureBreakpointTest, JournalRetainsFailedCleanupAndRejectsForeignBytes)
	{
		CodePage page;
		failJournalRestore = true;
		CppCoverage::BreakpointJournal::Operations operations;
		operations.write = [](HANDLE process, LPVOID address, LPCVOID bytes,
		                      SIZE_T size, SIZE_T* count) -> BOOL {
			if (*static_cast<const uint8_t*>(bytes) == 0x90 && failJournalRestore)
			{
				failJournalRestore = false;
				SetLastError(ERROR_ACCESS_DENIED);
				return FALSE;
			}
			return WriteProcessMemory(process, address, bytes, size, count);
		};
		CppCoverage::BreakpointJournal journal{GetCurrentProcess(), operations};
		const uint8_t trap = 0xcc;
		journal.Write(page.Address(), &trap, 1);
		EXPECT_THROW(journal.Rollback(), wil::ResultException);
		EXPECT_FALSE(journal.Empty());
		EXPECT_EQ(trap, page.data[0]);
		page.data[0] = 0xc3;
		EXPECT_THROW(journal.Rollback(), wil::ResultException);
		EXPECT_FALSE(journal.Empty());
		EXPECT_EQ(0xc3, page.data[0]);
		page.data[0] = trap;
		EXPECT_NO_THROW(journal.Rollback());
		EXPECT_EQ(0x90, page.data[0]);
		EXPECT_TRUE(journal.Empty());
	}

	TEST(ArchitectureBreakpointTest, JournalRetriesFailedProtectionRestoration)
	{
		CodePage page;
		DWORD previous = 0;
		ASSERT_TRUE(VirtualProtect(page.data, 4096, PAGE_EXECUTE_READ, &previous));
		failedProtectionRestores = 2;
		CppCoverage::BreakpointJournal::Operations operations;
		operations.protect = [](HANDLE process, LPVOID address, SIZE_T size,
		                        DWORD protection, PDWORD previous) -> BOOL {
			if ((protection & ~PAGE_TARGETS_NO_UPDATE) == PAGE_EXECUTE_READ &&
			    failedProtectionRestores)
			{
				--failedProtectionRestores;
				SetLastError(ERROR_ACCESS_DENIED);
				return FALSE;
			}
			return VirtualProtectEx(process, address, size, protection, previous);
		};
		CppCoverage::BreakpointJournal journal{GetCurrentProcess(), operations};
		const uint8_t trap = 0xcc;
		EXPECT_THROW(journal.Write(page.Address(), &trap, 1), wil::ResultException);
		EXPECT_FALSE(journal.Empty());
		MEMORY_BASIC_INFORMATION memory{};
		ASSERT_NE(0u, VirtualQuery(page.data, &memory, sizeof(memory)));
		EXPECT_EQ(PAGE_EXECUTE_READWRITE, memory.Protect);
		EXPECT_NO_THROW(journal.Rollback());
		EXPECT_EQ(0x90, page.data[0]);
		ASSERT_NE(0u, VirtualQuery(page.data, &memory, sizeof(memory)));
		EXPECT_EQ(PAGE_EXECUTE_READ, memory.Protect);
	}

	TEST(ArchitectureBreakpointTest, JournalRetirementAndUnloadPreserveOriginalImage)
	{
		CodePage page;
		CppCoverage::BreakpointJournal journal{GetCurrentProcess()};
		const uint8_t trap = 0xcc;
		const uint8_t original = 0x90;
		journal.Write(page.Address(), &trap, 1);
		journal.Write(page.Address(), &original, 1);
		journal.Write(page.Address(1), &trap, 1);
		journal.ForgetUnloadedRange(page.Address(1), 1);
		journal.Rollback();
		EXPECT_EQ(original, page.data[0]);
		EXPECT_EQ(trap, page.data[1]);
		EXPECT_TRUE(journal.Empty());
	}

	TEST(ArchitectureBreakpointTest, JournalRetriesFailedInstructionCacheFlush)
	{
		CodePage page;
		failedCacheFlushes = 1;
		CppCoverage::BreakpointJournal::Operations operations;
		operations.flush = [](HANDLE process, LPCVOID address, SIZE_T size) -> BOOL {
			if (failedCacheFlushes)
			{
				--failedCacheFlushes;
				SetLastError(ERROR_ACCESS_DENIED);
				return FALSE;
			}
			return FlushInstructionCache(process, address, size);
		};
		CppCoverage::BreakpointJournal journal{GetCurrentProcess(), operations};
		const uint8_t trap = 0xcc;
		EXPECT_THROW(journal.Write(page.Address(), &trap, 1), wil::ResultException);
		EXPECT_EQ(trap, page.data[0]);
		EXPECT_FALSE(journal.Empty());
		EXPECT_NO_THROW(journal.Rollback());
		EXPECT_EQ(0x90, page.data[0]);
		EXPECT_TRUE(journal.Empty());
	}

	TEST(ArchitectureBreakpointTest, OwnedSuspensionFencesAndPreservesAnotherSuspendCount)
	{
		std::atomic<bool> stop{false};
		std::atomic<uint64_t> counter{0};
		std::thread worker{[&] {
			while (!stop.load())
				++counter;
		}};
		CppCoverage::ThreadSuspension held;
		bool otherHeld = false;
		auto cleanup = wil::scope_exit([&] {
			held.Resume();
			if (otherHeld)
				ResumeThread(worker.native_handle());
			stop.store(true);
			worker.join();
		});
		ASSERT_EQ(0u, SuspendThread(worker.native_handle()));
		otherHeld = true;
		held.Hold(worker.native_handle());
		held.Hold(worker.native_handle());
		const auto before = counter.load();
		for (size_t i = 0; i < 100; ++i)
			SwitchToThread();
		EXPECT_EQ(before, counter.load());
		held.Resume();
		EXPECT_EQ(1u, ResumeThread(worker.native_handle()));
		otherHeld = false;
	}
}
