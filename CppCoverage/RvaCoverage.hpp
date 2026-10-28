#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "CppCoverageExport.hpp"
#include "PeImage.hpp"
#include "BasicBlockDiscovery.hpp"

namespace CppCoverage
{
	struct RvaBlock
	{
		BasicBlock block;
		bool executed = false;
	};

	struct RvaModule
	{
		std::filesystem::path path;
		PeIdentity identity;
		std::vector<RvaBlock> blocks;
	};

	struct RvaCoverage
	{
		std::wstring name;
		int exitCode = 0;
		std::vector<RvaModule> modules;
	};

	CPPCOVERAGE_DLL void WriteRvaCoverage(
	    const RvaCoverage&, const std::filesystem::path&);
	CPPCOVERAGE_DLL RvaCoverage ReadRvaCoverage(const std::filesystem::path&);
	CPPCOVERAGE_DLL bool IsRvaCoverage(const std::filesystem::path&);
}
