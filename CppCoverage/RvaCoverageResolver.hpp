#pragma once

#include "RvaCoverage.hpp"
#include "SubstitutePdbSourcePath.hpp"
#include "Plugin/Exporter/CoverageData.hpp"

namespace CppCoverage
{
	class CPPCOVERAGE_DLL RvaCoverageResolver
	{
	  public:
		Plugin::CoverageData Resolve(
		    const RvaCoverage&,
		    const std::vector<std::filesystem::path>& moduleDirectories,
		    const std::vector<SubstitutePdbSourcePath>& substitutions) const;
	};
}
