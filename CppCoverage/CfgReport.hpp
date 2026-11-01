#pragma once

#include "DebugInformationEnumerator.hpp"
#include "RvaCoverage.hpp"
#include <ostream>
#include <utility>

namespace CppCoverage
{
	struct CfgSourceLine
	{
		std::filesystem::path path;
		IDebugInformationHandler::Line line;
	};
	struct CfgModuleInput
	{
		std::filesystem::path image;
		RvaModule evidence;
		std::vector<IDebugInformationHandler::Function> functions;
		std::vector<CfgSourceLine> lines;
		bool resourceExhausted = false;
	};
	struct CfgDominance
	{
		std::vector<bool> reachable;
		std::vector<std::vector<bool>> dominators;
		bool workExhausted = false;
	};

	CPPCOVERAGE_DLL CfgDominance AnalyzeCfgDominance(size_t nodeCount,
		const std::vector<std::pair<size_t, size_t>>& normalEdges,
		const std::vector<size_t>& roots);

	// Describes structural implications conditional on the report's entry and normal-flow model.
	CPPCOVERAGE_DLL void WriteCfgReport(std::ostream&, const std::vector<CfgModuleInput>&);
}
