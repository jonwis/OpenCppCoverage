#pragma once

#include "PeImage.hpp"

namespace CppCoverage
{
	class CPPCOVERAGE_DLL BasicBlockDiscovery
	{
	public:
		// Traverses metadata roots and direct edges; unknown indirect targets remain undiscovered.
		// Invalid decoding stops a path. Overlapping instructions and four million decodes throw.
		std::vector<BasicBlock> Discover(const PeImage&) const;
	};
}
