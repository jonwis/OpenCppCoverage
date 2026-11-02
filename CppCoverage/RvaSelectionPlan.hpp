#pragma once

#include "CppCoverageExport.hpp"
#include "PeImage.hpp"
#include "SubstitutePdbSourcePath.hpp"
#include <filesystem>
#include <string>
#include <vector>

namespace CppCoverage
{
	class Patterns;

	struct RvaSelectionModule
	{
		std::wstring name;
		PeIdentity identity;
		// Digest of the complete Discover() catalog, including unselected blocks.
		std::string catalogSha256;
		std::vector<BasicBlock> blocks;
	};

	struct RvaSelectionPlan
	{
		std::vector<RvaSelectionModule> modules;
	};

	// SHA-256 of sorted, unique (LE u32 RVA, LE u32 size, LE u16 ISA) tuples.
	CPPCOVERAGE_DLL std::string RvaCatalogSha256(const std::vector<BasicBlock>&);
	CPPCOVERAGE_DLL const RvaSelectionModule* FindRvaSelection(
		const RvaSelectionPlan&, const PeIdentity&);
	// Schema 1: {schema,modules:[{name,identity,catalogSha256,blocks:[{rva,size,isa}]}]}.
	// Capture must verify the complete catalog digest and membership of every selected tuple.
	// Empty modules or blocks select nothing. Names are basename hints, never identity keys.
	CPPCOVERAGE_DLL RvaSelectionPlan ReadRvaSelectionPlan(const std::filesystem::path&);
	CPPCOVERAGE_DLL void WriteRvaSelectionPlan(
		const RvaSelectionPlan&, const std::filesystem::path&);
	CPPCOVERAGE_DLL void MakeRvaSelectionPlan(
		const std::filesystem::path& diff,
		const std::filesystem::path& sourceRoot,
		const std::vector<std::filesystem::path>& moduleDirectories,
		const Patterns& modulePatterns,
		const std::vector<SubstitutePdbSourcePath>& substitutions,
		unsigned expandLines,
		const std::filesystem::path& output);

	struct RvaSourceRegion
	{
		uint32_t first;
		uint32_t last;
	};
	struct RvaAddressRange
	{
		uint32_t rva;
		uint32_t size;
	};
	CPPCOVERAGE_DLL std::vector<RvaSourceRegion> ExpandRvaSourceLines(
		const std::vector<uint32_t>&, unsigned expansion, uint32_t lineCount);
	CPPCOVERAGE_DLL std::vector<BasicBlock> SelectRvaBlocks(
		const std::vector<BasicBlock>& catalog, const std::vector<RvaAddressRange>&);
}
