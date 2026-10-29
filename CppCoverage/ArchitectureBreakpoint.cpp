#include "stdafx.h"
#include "ArchitectureBreakpoint.hpp"

#include <Windows.h>
#include <wil/result.h>
#include <wil/resource.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace CppCoverage
{
	namespace
	{
		ArchitectureBreakpoint::Instruction Read(
		    HANDLE process, uint64_t address, size_t size)
		{
			ArchitectureBreakpoint::Instruction result;
			result.size = size;
			SIZE_T read = 0;
			THROW_LAST_ERROR_IF_MSG(!ReadProcessMemory(process, reinterpret_cast<void*>(address),
			                       result.bytes.data(), size, &read), "Reading breakpoint instruction");
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), read != size, "Incomplete breakpoint instruction read");
			return result;
		}

		bool Equal(const ArchitectureBreakpoint::Instruction& lhs,
		           const ArchitectureBreakpoint::Instruction& rhs)
		{
			return lhs.size == rhs.size &&
			       std::memcmp(lhs.bytes.data(), rhs.bytes.data(), lhs.size) == 0;
		}

		void Write(HANDLE process, uint64_t address, const uint8_t* bytes, size_t size)
		{
			auto remote = reinterpret_cast<void*>(address);
			DWORD protection = 0;
			THROW_LAST_ERROR_IF_MSG(!VirtualProtectEx(process, remote, size,
			                      PAGE_EXECUTE_READWRITE | PAGE_TARGETS_NO_UPDATE, &protection), "Making breakpoint instruction writable");
			DWORD restoreProtection = protection;
			if (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
			                  PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
				restoreProtection |= PAGE_TARGETS_NO_UPDATE;
			auto restore = wil::scope_exit([&] {
				DWORD ignored = 0;
				LOG_IF_WIN32_BOOL_FALSE(VirtualProtectEx(
				    process, remote, size, restoreProtection, &ignored));
			});
			SIZE_T written = 0;
			const BOOL success = WriteProcessMemory(
			    process, remote, bytes, size, &written);
			const DWORD writeError = GetLastError();
			DWORD ignored = 0;
			THROW_LAST_ERROR_IF_MSG(!VirtualProtectEx(process, remote, size, restoreProtection, &ignored), "Restoring breakpoint page protection");
			restore.release();
			THROW_WIN32_IF_MSG(writeError, !success, "Writing breakpoint instruction");
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), written != size, "Incomplete breakpoint instruction write");
			THROW_LAST_ERROR_IF_MSG(!FlushInstructionCache(process, remote, size), "Flushing remote breakpoint instruction");
		}

		void Write(HANDLE process, uint64_t address,
		           const ArchitectureBreakpoint::Instruction& instruction)
		{
			Write(process, address, instruction.bytes.data(), instruction.size);
		}
	}

	ArchitectureBreakpoint::Instruction ArchitectureBreakpoint::Encoding(
	    InstructionSet instructionSet)
	{
		switch (instructionSet)
		{
			case InstructionSet::Amd64: return {{{0xcc, 0, 0, 0}}, 1};
			case InstructionSet::Arm64: return {{{0x00, 0x00, 0x3e, 0xd4}}, 4};
		}
		THROW_HR_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), "Unsupported breakpoint instruction set");
	}

	uint64_t ArchitectureBreakpoint::ResumeAddress(
	    InstructionSet instructionSet, uint64_t programCounter,
	    uint64_t exceptionAddress)
	{
		const auto encoding = Encoding(instructionSet);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), instructionSet == InstructionSet::Arm64 && (exceptionAddress & 3), "Unaligned ARM64 breakpoint address");
		const bool advanced =
		    exceptionAddress <= (std::numeric_limits<uint64_t>::max)() - encoding.size &&
		    programCounter == exceptionAddress + encoding.size;
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), programCounter != exceptionAddress && !advanced, "Thread context does not identify the trapped instruction; "
			    "this host/target context combination is unsupported");
		return exceptionAddress;
	}

	bool ArchitectureBreakpoint::IsApplicationTrap(
	    InstructionSet instructionSet, const uint8_t* bytes, size_t size)
	{
		const auto encoding = Encoding(instructionSet);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !bytes || size < encoding.size, "Truncated application instruction");
		if (instructionSet == InstructionSet::Amd64)
			return bytes[0] == 0xcc ||
			       (size >= 2 && bytes[0] == 0xcd && bytes[1] == 3);
		uint32_t instruction = 0;
		std::memcpy(&instruction, bytes, sizeof(instruction));
		return (instruction & 0xffe0001f) == 0xd4200000;
	}

	void ArchitectureBreakpoint::ValidateTarget(HANDLE process, uint16_t machine)
	{
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), machine != 0x8664 && machine != 0xaa64 && machine != 0xa641, "RVA collection supports AMD64, ARM64 and ARM64EC only");
#if defined(_M_ARM64) && !defined(_M_ARM64EC)
		(void)process;
#elif defined(_M_AMD64) && !defined(_M_ARM64EC)
		SYSTEM_INFO system{};
		GetNativeSystemInfo(&system);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), system.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 ||
		    machine != 0x8664, "Use the native ARM64 collector for ARM64, ARM64EC or AMD64-on-ARM64");
		BOOL wow64 = FALSE;
		THROW_LAST_ERROR_IF_MSG(!IsWow64Process(process, &wow64), "Querying target architecture");
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), wow64, "32-bit targets are unsupported by RVA collection");
#else
		(void)process;
		THROW_HR_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), "RVA collection requires a native AMD64 or ARM64 collector");
#endif
	}

	ArchitectureBreakpoint::ArchitectureBreakpoint(
	    HANDLE process, uint64_t address, InstructionSet instructionSet)
	    : ArchitectureBreakpoint(process, address, instructionSet,
	          Read(process, address, Encoding(instructionSet).size))
	{
	}

	ArchitectureBreakpoint::ArchitectureBreakpoint(
	    HANDLE process, uint64_t address, InstructionSet instructionSet,
	    Instruction original)
	    : process_{process}, address_{address}, instructionSet_{instructionSet},
	      original_{original}
	{
		const auto encoding = Encoding(instructionSet);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), instructionSet == InstructionSet::Arm64 && (address & 3), "Unaligned ARM64 breakpoint address");
		THROW_HR_IF_MSG(E_INVALIDARG, original_.size != encoding.size,
			"Invalid original breakpoint instruction size");
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), IsApplicationTrap(instructionSet, original_.bytes.data(), original_.size), "A discovered block begins with an application breakpoint");
	}

	void ArchitectureBreakpoint::InstallRange(
	    HANDLE process, uint64_t address, const std::vector<uint8_t>& original,
	    const std::vector<ArchitectureBreakpoint*>& patches)
	{
		THROW_HR_IF_MSG(E_INVALIDARG, original.empty() || original.size() > 2 * 1024 * 1024 ||
		    address > (std::numeric_limits<uint64_t>::max)() - original.size(),
		    "Invalid breakpoint installation range");
		MEMORY_BASIC_INFORMATION memory{};
		THROW_LAST_ERROR_IF_MSG(!VirtualQueryEx(process, reinterpret_cast<void*>(address),
		    &memory, sizeof(memory)), "Querying breakpoint installation range");
		const auto region = reinterpret_cast<uint64_t>(memory.BaseAddress);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
		    memory.State != MEM_COMMIT || (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) ||
		    address < region || address - region >= memory.RegionSize ||
		    original.size() > memory.RegionSize - (address - region),
		    "Breakpoint installation range crosses a memory protection boundary");
		auto modified = original;
		uint64_t end = address;
		for (const auto* patch : patches)
		{
			THROW_HR_IF_MSG(E_INVALIDARG, !patch || patch->process_ != process ||
			    patch->address_ < end || patch->address_ - address >= original.size() ||
			    patch->original_.size > original.size() - (patch->address_ - address),
			    "Unordered, overlapping or out-of-range breakpoint");
			const auto offset = static_cast<size_t>(patch->address_ - address);
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
			    std::memcmp(original.data() + offset, patch->original_.bytes.data(),
			                patch->original_.size) != 0,
			    "Code changed before range breakpoint installation");
			const auto encoding = Encoding(patch->instructionSet_);
			std::memcpy(modified.data() + offset, encoding.bytes.data(), encoding.size);
			end = patch->address_ + encoding.size;
		}
		if (patches.empty())
			return;
		std::vector<uint8_t> current(original.size());
		SIZE_T read = 0;
		THROW_LAST_ERROR_IF_MSG(!ReadProcessMemory(process, reinterpret_cast<void*>(address),
		    current.data(), current.size(), &read), "Verifying breakpoint installation range");
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
		    read != current.size() || current != original,
		    "Code changed before range breakpoint write");
		Write(process, address, modified.data(), modified.size());
	}

	void ArchitectureBreakpoint::Install() const
	{
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !Equal(Read(process_, address_, original_.size), original_), "Code changed before breakpoint installation");
		Write(process_, address_, Encoding(instructionSet_));
	}

	void ArchitectureBreakpoint::Restore() const
	{
		const auto current = Read(process_, address_, original_.size);
		if (Equal(current, original_))
			return;
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !Equal(current, Encoding(instructionSet_)), "An installed coverage breakpoint was modified");
		Write(process_, address_, original_);
	}

	void ArchitectureBreakpoint::ResumeThread(HANDLE thread) const
	{
#if defined(_M_ARM64) && !defined(_M_ARM64EC)
		CONTEXT context{};
		context.ContextFlags = CONTEXT_FULL;
		THROW_LAST_ERROR_IF_MSG(!GetThreadContext(thread, &context), "Reading native ARM64 thread context");
		context.Pc = ResumeAddress(instructionSet_, context.Pc, address_);
		THROW_LAST_ERROR_IF_MSG(!SetThreadContext(thread, &context), "Restoring native ARM64 thread PC");
#elif defined(_M_AMD64) && !defined(_M_ARM64EC)
		CONTEXT context{};
		context.ContextFlags = CONTEXT_CONTROL;
		THROW_LAST_ERROR_IF_MSG(!GetThreadContext(thread, &context), "Reading AMD64 thread context");
		context.Rip = ResumeAddress(instructionSet_, context.Rip, address_);
		THROW_LAST_ERROR_IF_MSG(!SetThreadContext(thread, &context), "Restoring AMD64 thread PC");
#else
		(void)thread;
		THROW_HR_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), "Unsupported collector architecture");
#endif
	}

	void ArchitectureBreakpoint::VerifyRestored() const
	{
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !Equal(Read(process_, address_, original_.size), original_), "Code changed after a one-shot coverage breakpoint");
	}

	size_t ArchitectureBreakpoint::Size() const
	{
		return original_.size;
	}
}
