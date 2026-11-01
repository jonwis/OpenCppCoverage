#pragma once

#include "PeImage.hpp"
#include <string>

namespace CppCoverage
{
	enum class FlowKind { Fallthrough, Branch, Call, ImportCall, NormalReturn };
	struct DecodedEdge
	{
		uint32_t from;
		uint32_t to;
		FlowKind kind;
	};
	struct DecodeIssue
	{
		uint32_t rva;
		std::string reason;
	};
	struct DecodedGraph
	{
		std::vector<BasicBlock> blocks;
		std::vector<BasicBlock> catalogBlocks;
		std::vector<DecodedEdge> edges;
		std::vector<DecodeIssue> issues;
	};

	class CPPCOVERAGE_DLL BasicBlockDiscovery
	{
	public:
		// Traverses metadata roots and direct edges; unknown indirect targets remain undiscovered.
		// Invalid decoding stops a path. Overlapping instructions and four million decodes throw.
		std::vector<BasicBlock> Discover(const PeImage&) const;
		DecodedGraph DiscoverGraph(const PeImage&, const std::vector<uint32_t>& supplementalRoots) const;
	private:
		std::vector<BasicBlock> DiscoverImpl(const PeImage&,
			const std::vector<uint32_t>&, DecodedGraph*) const;
	};
}
