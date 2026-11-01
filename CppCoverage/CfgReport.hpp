#pragma once

#include "DebugInformationEnumerator.hpp"
#include "RvaCoverage.hpp"
#include <ostream>

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

	// Describes structural implications conditional on the report's entry and normal-flow model.
	CPPCOVERAGE_DLL void WriteCfgReport(std::ostream&, const std::vector<CfgModuleInput>&);
}
