#include "CfgReport.hpp"

#include <Windows.h>
#include <algorithm>
#include <iomanip>
#include <limits>
#include <locale>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>

namespace CppCoverage
{
	namespace
	{
		constexpr size_t MaxNodes = 512;
		constexpr size_t MaxImplications = 4096;
		constexpr size_t MaxFunctions = 10000;
		constexpr size_t MaxLines = 100000;

		std::string Utf8(const std::wstring& value)
		{
			if (value.empty())
				return {};
			if (value.size() > static_cast<size_t>((std::numeric_limits<int>::max)()))
				throw std::runtime_error("CFG text exceeds the UTF-8 limit");
			const auto length = static_cast<int>(value.size());
			const auto size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
				value.data(), length, nullptr, 0, nullptr, nullptr);
			if (!size)
				throw std::runtime_error("Invalid CFG report Unicode");
			std::string result(size, '\0');
			if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
				value.data(), length, result.data(), size, nullptr, nullptr))
				throw std::runtime_error("Cannot encode CFG report Unicode");
			return result;
		}

		std::string Quote(const std::string& value)
		{
			std::ostringstream output;
			output << '"';
			for (const unsigned char byte : value)
			{
				switch (byte)
				{
				case '"': output << "\\\""; break;
				case '\\': output << "\\\\"; break;
				default:
					if (byte < 32)
						output << "\\u" << std::hex << std::setw(4) << std::setfill('0')
							<< static_cast<unsigned>(byte) << std::dec;
					else
						output << static_cast<char>(byte);
				}
			}
			output << '"';
			return output.str();
		}

		template<size_t Size>
		std::string Hex(const std::array<uint8_t, Size>& bytes)
		{
			std::ostringstream output;
			for (const auto byte : bytes)
				output << std::hex << std::setw(2) << std::setfill('0') << unsigned{byte};
			return output.str();
		}

		bool Contains(const BasicBlock& block, uint32_t rva)
		{
			return rva >= block.rva && uint64_t{rva} < uint64_t{block.rva} + block.size;
		}

		const char* Kind(FlowKind kind)
		{
			switch (kind)
			{
			case FlowKind::Branch: return "direct-branch";
			case FlowKind::Call: return "opaque-direct-call";
			case FlowKind::ImportCall: return "opaque-import-call";
			case FlowKind::NormalReturn: return "conditional-normal-return";
			default: return "decoded-fallthrough";
			}
		}

		void Region(std::ostream& output, const CfgModuleInput& input,
			const PeImage& image, const DecodedGraph& graph,
			const IDebugInformationHandler::Function& function, bool ambiguous)
		{
			const auto end = uint64_t{function.rva} + function.size;
			std::string exclusion = function.exclusion;
			if (ambiguous)
				exclusion = "ambiguous-overlapping-function-ranges";
			if (!function.size || function.rva >= image.Identity().sizeOfImage ||
				function.size > image.Identity().sizeOfImage - function.rva)
				exclusion = "invalid-function-range";
			std::vector<BasicBlock> nodes;
			for (const auto& block : graph.blocks)
				if (block.rva < end && uint64_t{block.rva} + block.size > function.rva)
				{
					if (block.rva < function.rva || uint64_t{block.rva} + block.size > end)
						exclusion = "decode-crosses-function-boundary";
					nodes.push_back(block);
				}
			for (const auto& range : image.UnsafeUnwindRanges())
				if (range.rva < end && uint64_t{range.rva} + range.size > function.rva)
					exclusion = "eh-or-chained-unwind";
			for (const auto& issue : graph.issues)
				if (issue.rva >= function.rva && issue.rva < end)
					exclusion = issue.reason;
			if (nodes.empty())
				exclusion = "no-validated-code";
			if (nodes.size() > MaxNodes)
				exclusion = "region-node-limit";
			uint64_t covered = function.rva;
			for (const auto& node : nodes)
			{
				if (node.rva != covered)
					exclusion = "incomplete-function-decode";
				covered = uint64_t{node.rva} + node.size;
				if (node.instructionSet != (image.Identity().machine == 0xaa64 ?
					InstructionSet::Arm64 : InstructionSet::Amd64))
					exclusion = "cross-isa-region";
			}
			if (covered != end)
				exclusion = "incomplete-function-decode";
			std::map<uint32_t, size_t> indices;
			for (size_t i = 0; i < nodes.size(); ++i)
				indices.emplace(nodes[i].rva, i);
			std::set<uint32_t> roots{function.rva};
			for (const auto root : image.Roots())
				if (root >= function.rva && root < end)
					roots.insert(root);
			for (const auto& other : input.functions)
				if (other.rva >= function.rva && other.rva < end)
					roots.insert(other.rva);
			std::set<std::tuple<uint32_t, uint32_t, FlowKind>> edges;
			for (const auto& edge : graph.edges)
			{
				if (edge.kind != FlowKind::ImportCall && edge.to >= function.rva && edge.to < end &&
					(edge.from < function.rva || edge.from >= end || edge.kind == FlowKind::Call))
					roots.insert(edge.to);
				if (edge.from < function.rva || edge.from >= end)
					continue;
				const auto node = std::find_if(nodes.begin(), nodes.end(),
					[&](const BasicBlock& block) { return Contains(block, edge.from); });
				if (node == nodes.end())
					continue;
				if (edge.kind == FlowKind::Fallthrough && Contains(*node, edge.to))
					continue;
				edges.emplace(node->rva, edge.to, edge.kind);
				if ((edge.kind == FlowKind::Fallthrough || edge.kind == FlowKind::NormalReturn) &&
					(edge.to < function.rva || edge.to >= end))
					exclusion = "continuation-exits-function-range";
				if (edge.kind != FlowKind::Call && edge.kind != FlowKind::ImportCall &&
					edge.to >= function.rva && edge.to < end &&
					!indices.count(edge.to))
					exclusion = "unvalidated-edge-target";
			}
			for (const auto root : roots)
				if (!indices.count(root))
					exclusion = "unvalidated-entry";
			if (edges.size() > MaxNodes * 3)
				exclusion = "region-edge-limit";

			std::vector<std::pair<uint32_t, uint32_t>> implications;
			std::map<uint32_t, uint32_t> immediateDominators;
			if (exclusion.empty())
			{
				const auto count = nodes.size();
				std::vector<std::vector<size_t>> predecessors(count);
				for (const auto& edge : edges)
					if (std::get<2>(edge) != FlowKind::Call &&
						std::get<2>(edge) != FlowKind::ImportCall && indices.count(std::get<1>(edge)))
						predecessors[indices.at(std::get<1>(edge))].push_back(indices.at(std::get<0>(edge)));
				// Synthetic-root edges make every recognized entry independent.
				std::vector<std::vector<bool>> dominators(count, std::vector<bool>(count, true));
				for (const auto root : roots)
				{
					auto& row = dominators[indices.at(root)];
					std::fill(row.begin(), row.end(), false);
					row[indices.at(root)] = true;
				}
				bool changed = true;
				size_t passes = 0;
				size_t work = 0;
				bool workExhausted = false;
				while (changed && ++passes <= count + 1)
				{
					changed = false;
					for (size_t i = 0; i < count; ++i)
					{
						if (roots.count(nodes[i].rva))
							continue;
						std::vector<bool> next(count, true);
						if (predecessors[i].empty())
							std::fill(next.begin(), next.end(), false);
						for (const auto predecessor : predecessors[i])
						{
							work += count;
							if (work > 8000000)
							{
								workExhausted = true;
								break;
							}
							for (size_t j = 0; j < count; ++j)
								next[j] = next[j] && dominators[predecessor][j];
						}
						if (workExhausted)
							break;
						next[i] = true;
						if (next != dominators[i])
						{
							dominators[i] = std::move(next);
							changed = true;
						}
					}
					if (workExhausted)
						break;
				}
				if (changed || workExhausted)
					exclusion = "dominator-work-limit";
				else
				{
					std::vector<size_t> depths(count);
					for (size_t i = 0; i < count; ++i)
						depths[i] = std::count(dominators[i].begin(), dominators[i].end(), true);
					for (size_t i = 0; i < count; ++i)
					{
						size_t nearest = count;
						for (size_t j = 0; j < count; ++j)
							if (j != i && dominators[i][j] &&
								(nearest == count || depths[j] > depths[nearest]))
								nearest = j;
						if (nearest != count)
							immediateDominators.emplace(nodes[i].rva, nodes[nearest].rva);
						const auto measured = std::find_if(input.evidence.blocks.begin(), input.evidence.blocks.end(),
							[&](const RvaBlock& site) { return site.block.rva == nodes[i].rva && site.executed; });
						if (measured == input.evidence.blocks.end())
							continue;
						for (size_t j = 0; j < count; ++j)
							if (j != i && dominators[i][j])
								implications.emplace_back(nodes[i].rva, nodes[j].rva);
					}
				}
				if (implications.size() > MaxImplications)
					exclusion = "implication-output-limit";
			}
			if (!exclusion.empty())
			{
				implications.clear();
				immediateDominators.clear();
			}
			output << "{\"rva\":" << function.rva << ",\"size\":" << function.size
				<< ",\"name\":" << Quote(Utf8(function.name)) << ",\"exclusion\":"
				<< (exclusion.empty() ? "null" : Quote(exclusion))
				<< ",\"syntheticRoot\":true,\"roots\":[";
			bool first = true;
			for (const auto root : roots)
			{
				if (!first) output << ',';
				first = false;
				output << root;
			}
			output << "],\"nodes\":[";
			first = true;
			if (nodes.size() <= MaxNodes)
				for (const auto& node : nodes)
				{
					if (!first) output << ',';
					first = false;
					output << "{\"rva\":" << node.rva << ",\"size\":" << node.size
						<< ",\"immediateDominatorRva\":";
					const auto dominator = immediateDominators.find(node.rva);
					if (dominator == immediateDominators.end())
						output << "null";
					else
						output << dominator->second;
					output << ",\"measuredSite\":";
					const auto site = std::lower_bound(input.evidence.blocks.begin(), input.evidence.blocks.end(), node.rva,
						[](const RvaBlock& block, uint32_t rva) { return block.block.rva < rva; });
					if (site == input.evidence.blocks.end() || site->block.rva != node.rva)
						output << "null";
					else
						output << "{\"selected\":" << (site->selected ? "true" : "false")
							<< ",\"observed\":" << (site->observed ? "true" : "false")
							<< ",\"executed\":" << (site->executed ? "true" : "false") << '}';
					output << ",\"source\":[";
					bool firstLine = true;
					size_t attributed = 0;
					for (const auto& source : input.lines)
						if (source.line.virtualAddress_ >= 0 &&
							static_cast<uint64_t>(source.line.virtualAddress_) < uint64_t{node.rva} + node.size &&
							static_cast<uint64_t>(source.line.virtualAddress_) +
								(std::max)(1ul, source.line.length_) > node.rva)
						{
							if (++attributed > 16)
								continue;
							if (!firstLine) output << ',';
							firstLine = false;
							output << "{\"path\":" << Quote(Utf8(source.path.wstring()))
								<< ",\"line\":" << source.line.lineNumber_ << '}';
						}
					output << "],\"sourceTruncated\":" << (attributed > 16 ? "true" : "false") << '}';
				}
			output << "],\"edges\":[";
			first = true;
			if (nodes.size() <= MaxNodes && edges.size() <= MaxNodes * 3)
				for (const auto& edge : edges)
				{
					if (!first) output << ',';
					first = false;
					output << "{\"from\":" << std::get<0>(edge) << ",\"to\":" << std::get<1>(edge)
						<< ",\"kind\":" << Quote(Kind(std::get<2>(edge))) << '}';
				}
			output << "],\"implications\":[";
			first = true;
			for (const auto& implication : implications)
			{
				if (!first) output << ',';
				first = false;
				output << "{\"measuredRva\":" << implication.first << ",\"requiredRva\":"
					<< implication.second << ",\"witness\":{\"kind\":\"strict-dominator\","
					"\"functionRva\":" << function.rva << ",\"treeNodeRva\":" << implication.first
					<< ",\"syntheticRoot\":true}}";
			}
			output << "]}";
		}
	}

	void WriteCfgReport(std::ostream& output, const std::vector<CfgModuleInput>& modules)
	{
		output.imbue(std::locale::classic());
		output.setf(std::ios::dec, std::ios::basefield);
		output.unsetf(std::ios::showbase | std::ios::showpos);
		output.width(0);
		output << "{\"schemaVersion\":1,\"semantics\":\"required-on-normal-entry-paths\","
			"\"temporalProvenance\":\"unknown\",\"withinWindowExecutionClaim\":false,"
			"\"normalFlowAssumptions\":[\"entry occurs at a listed root\","
			"\"no unlisted interior entry, callback, exception, or context transfer\","
			"\"opaque calls return normally to their decoded continuation\","
			"\"the matching file image describes the executing layout\","
			"\"a measured hit does not date its dominators within the capture window\"],"
			"\"modules\":[";
		bool first = true;
		for (const auto& original : modules)
		{
			if (!first) output << ',';
			first = false;
			auto input = original;
			std::sort(input.lines.begin(), input.lines.end(), [](const auto& left, const auto& right) {
				return std::tie(left.path, left.line.virtualAddress_, left.line.lineNumber_, left.line.length_) <
					std::tie(right.path, right.line.virtualAddress_, right.line.lineNumber_, right.line.length_);
			});
			const PeImage image(input.image);
			const auto& identity = image.Identity();
			const auto& recorded = input.evidence.identity;
			if (identity.machine != recorded.machine || identity.timeDateStamp != recorded.timeDateStamp ||
				identity.sizeOfImage != recorded.sizeOfImage || identity.checksum != recorded.checksum ||
				identity.pdbGuid != recorded.pdbGuid || identity.pdbAge != recorded.pdbAge ||
				identity.imageHash != recorded.imageHash)
				throw std::runtime_error("CFG report image identity changed");
			output << "{\"path\":" << Quote(Utf8(input.image.wstring()))
				<< ",\"identity\":{\"machine\":" << identity.machine << ",\"timeDateStamp\":" << identity.timeDateStamp
				<< ",\"sizeOfImage\":" << identity.sizeOfImage << ",\"checksum\":" << identity.checksum
				<< ",\"pdbGuid\":" << Quote(Hex(identity.pdbGuid)) << ",\"pdbAge\":" << identity.pdbAge
				<< ",\"imageHash\":" << Quote(Hex(identity.imageHash))
				<< "},\"catalogSiteCount\":" << input.evidence.blocks.size()
				<< ",\"catalogExclusion\":" << (input.evidence.blocks.size() > 8192 ?
					"\"catalog-site-output-limit\"" : "null") << ",\"measuredSites\":[";
			if (input.evidence.blocks.size() <= 8192)
				for (size_t i = 0; i < input.evidence.blocks.size(); ++i)
				{
					if (i) output << ',';
					const auto& site = input.evidence.blocks[i];
					output << "{\"rva\":" << site.block.rva << ",\"size\":" << site.block.size
						<< ",\"instructionSet\":" << static_cast<unsigned>(site.block.instructionSet)
						<< ",\"selected\":" << (site.selected ? "true" : "false")
						<< ",\"observed\":" << (site.observed ? "true" : "false")
						<< ",\"executed\":" << (site.executed ? "true" : "false") << '}';
				}
			output << "],\"peRoots\":[";
			bool firstRoot = true;
			for (const auto root : image.Roots())
			{
				if (!firstRoot) output << ',';
				firstRoot = false;
				output << root;
			}
			output << "],\"exclusion\":";
			std::string exclusion;
			if (!image.SupportsCfgReport() || (identity.machine != 0x8664 && identity.machine != 0xaa64))
				exclusion = "hybrid-or-dynamic-relocation-image";
			if (input.resourceExhausted || input.functions.size() > MaxFunctions || input.lines.size() > MaxLines)
				exclusion = "module-input-limit";
			if (input.functions.empty())
				exclusion = "no-machine-function-inventory";
			DecodedGraph graph;
			auto functions = input.functions;
			std::sort(functions.begin(), functions.end(), [](const auto& left, const auto& right) {
				return std::tie(left.rva, left.size, left.name) < std::tie(right.rva, right.size, right.name);
			});
			if (exclusion.empty())
			{
				std::vector<uint32_t> roots;
				for (const auto& function : functions)
					if (function.size && function.rva < identity.sizeOfImage &&
						function.size <= identity.sizeOfImage - function.rva)
						roots.push_back(function.rva);
				try
				{
					graph = BasicBlockDiscovery{}.DiscoverGraph(image, roots);
					if (graph.blocks.size() > 8192)
						exclusion = "module-node-limit";
					if (uint64_t{graph.blocks.size()} * input.lines.size() > 16000000 ||
						uint64_t{input.functions.size()} * (graph.blocks.size() + graph.edges.size()) > 16000000)
						exclusion = "module-work-limit";
					for (const auto& site : input.evidence.blocks)
					{
						const auto block = std::lower_bound(graph.catalogBlocks.begin(), graph.catalogBlocks.end(), site.block.rva,
							[](const BasicBlock& entry, uint32_t rva) { return entry.rva < rva; });
						if (block == graph.catalogBlocks.end() || block->rva != site.block.rva ||
							block->size != site.block.size || block->instructionSet != site.block.instructionSet)
							exclusion = "catalog-layout-mismatch";
					}
				}
				catch (const std::exception&)
				{
					exclusion = "decode-overlap-or-resource-failure";
				}
			}
			output << (exclusion.empty() ? "null" : Quote(exclusion)) << ",\"functions\":[";
			if (exclusion.empty())
			{
				std::vector<bool> ambiguous(functions.size(), false);
				uint64_t previousEnd = 0;
				for (size_t i = 0; i < functions.size(); ++i)
				{
					if (functions[i].rva < previousEnd)
					{
						ambiguous[i] = true;
						if (i) ambiguous[i - 1] = true;
					}
					previousEnd = (std::max)(previousEnd, uint64_t{functions[i].rva} + functions[i].size);
				}
				for (size_t i = 0; i < functions.size(); ++i)
				{
					if (i) output << ',';
					Region(output, input, image, graph, functions[i], ambiguous[i]);
				}
			}
			else if (functions.size() <= MaxFunctions)
				for (size_t i = 0; i < functions.size(); ++i)
				{
					if (i) output << ',';
					output << "{\"rva\":" << functions[i].rva << ",\"size\":" << functions[i].size
						<< ",\"name\":" << Quote(Utf8(functions[i].name))
						<< ",\"exclusion\":" << Quote(exclusion)
						<< ",\"roots\":[],\"nodes\":[],\"edges\":[],\"implications\":[]}";
				}
			output << "]}";
		}
		output << "]}\r\n";
		if (!output)
			throw std::runtime_error("Cannot write CFG report");
	}
}
