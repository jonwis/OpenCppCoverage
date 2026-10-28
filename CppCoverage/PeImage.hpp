#pragma once

#include "CppCoverageExport.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

namespace CppCoverage
{
	enum class InstructionSet : uint16_t
	{
		Amd64 = 0x8664,
		Arm64 = 0xaa64
	};

	struct BasicBlock
	{
		uint32_t rva;
		uint32_t size;
		InstructionSet instructionSet;
	};

	struct PeIdentity
	{
		uint16_t machine = 0;
		uint32_t timeDateStamp = 0;
		uint32_t sizeOfImage = 0;
		uint32_t checksum = 0;
		std::array<uint8_t, 16> pdbGuid{};
		uint32_t pdbAge = 0;
		std::array<uint8_t, 32> imageHash{};
	};

	struct PeCodeView
	{
		const uint8_t* data = nullptr;
		size_t size = 0;
		InstructionSet instructionSet = InstructionSet::Amd64;
	};

	class CPPCOVERAGE_DLL PeImage
	{
	public:
		// Malformed metadata, unsupported hybrid layouts, and resource limits throw runtime_error.
		// Input is limited to 512 MiB; metadata processing is limited to four million entries.
		explicit PeImage(const std::filesystem::path&);
		explicit PeImage(std::vector<uint8_t>);

		const PeIdentity& Identity() const;
		const std::vector<uint32_t>& Roots() const;
		const std::vector<BasicBlock>& CodeRanges() const;
		PeCodeView GetCode(uint32_t rva) const;
		bool VaToRva(uint64_t va, uint32_t& rva) const;
		bool IsImportSlot(uint32_t rva) const;
		bool ImportTarget(uint32_t slotRva, uint32_t& targetRva) const;
		// Compares raw code after DIR64 base relocation; ARM64X dynamic fixups remain differences.
		bool MatchesMappedCode(uint32_t rva, const uint8_t* bytes, size_t size,
			uint64_t mappedBase) const;

	private:
		struct Section
		{
			uint32_t rva;
			uint32_t virtualSize;
			uint32_t rawOffset;
			uint32_t rawSize;
			uint32_t characteristics;
		};
		struct Directory
		{
			uint32_t rva = 0;
			uint32_t size = 0;
		};
		struct ImportSlot
		{
			uint32_t rva;
			uint32_t target;
		};

		void Parse();
		void ParseHybrid(uint32_t metadataRva);
		void ParseExports();
		void ParseImports();
		void ParseTls();
		void ParseLoadConfig();
		void ParseDebug();
		void ParseRelocations();
		void ParseRuntimeFunctions(uint32_t rva, uint32_t size, bool arm64);
		void AddRoot(uint32_t rva);
		void Charge(size_t count);
		size_t RawOffset(uint32_t rva, size_t size) const;
		size_t Available(uint32_t rva) const;
		uint32_t Rva32(uint32_t rva, size_t offset = 0) const;
		uint64_t Rva64(uint32_t rva, size_t offset = 0) const;

		std::vector<uint8_t> bytes_;
		PeIdentity identity_;
		uint64_t imageBase_ = 0;
		uint32_t sizeOfHeaders_ = 0;
		uint32_t entryPoint_ = 0;
		bool hybrid_ = false;
		bool importsReady_ = false;
		std::array<Directory, 16> directories_{};
		std::vector<Section> sections_;
		std::vector<BasicBlock> codeRanges_;
		std::vector<uint32_t> roots_;
		std::vector<ImportSlot> imports_;
		std::vector<uint32_t> relocations_;
		size_t metadataEntries_ = 0;
	};
}
