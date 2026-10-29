#pragma once

#include <Windows.h>
#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "CppCoverageExport.hpp"
#include "PeImage.hpp"

namespace CppCoverage
{
	class CPPCOVERAGE_DLL ArchitectureBreakpoint
	{
	public:
		struct Instruction
		{
			std::array<uint8_t, 4> bytes{};
			size_t size = 0;
		};

		static Instruction Encoding(InstructionSet);
		static bool IsApplicationTrap(InstructionSet, const uint8_t* bytes, size_t size);
		static uint64_t ResumeAddress(
		    InstructionSet, uint64_t programCounter, uint64_t exceptionAddress);
		static void ValidateTarget(HANDLE process, uint16_t machine);

		ArchitectureBreakpoint(HANDLE process, uint64_t address, InstructionSet);
		ArchitectureBreakpoint(
		    HANDLE process, uint64_t address, InstructionSet, Instruction original);
		static void InstallRange(
		    HANDLE process, uint64_t address, const std::vector<uint8_t>& original,
		    const std::vector<ArchitectureBreakpoint*>& patches);
		void Install() const;
		void Restore() const;
		void VerifyRestored() const;
		void ResumeThread(HANDLE thread) const;
		size_t Size() const;

	private:
		HANDLE process_;
		uint64_t address_;
		InstructionSet instructionSet_;
		Instruction original_;
	};
}
