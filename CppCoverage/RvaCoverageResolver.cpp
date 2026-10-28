#include "stdafx.h"
#include "RvaCoverageResolver.hpp"

#include <Windows.h>
#include <wil/result.h>

#include <algorithm>
#include <cstdint>
#include <map>
#include <stdexcept>

#include "DebugInformationEnumerator.hpp"
#include "Plugin/Exporter/FileCoverage.hpp"
#include "Plugin/Exporter/ModuleCoverage.hpp"

namespace CppCoverage
{
	namespace
	{
		bool SameIdentity(const PeIdentity& left, const PeIdentity& right)
		{
			return left.machine == right.machine &&
			       left.timeDateStamp == right.timeDateStamp &&
			       left.sizeOfImage == right.sizeOfImage &&
			       left.checksum == right.checksum &&
			       left.pdbGuid == right.pdbGuid && left.pdbAge == right.pdbAge &&
			       left.imageHash == right.imageHash;
		}

		std::filesystem::path FindModule(
		    const RvaModule& module,
		    const std::vector<std::filesystem::path>& directories)
		{
			std::vector<std::filesystem::path> candidates{module.path};
			for (const auto& directory : directories)
				candidates.push_back(directory / module.path.filename());
			for (const auto& candidate : candidates)
			{
				try
				{
					if (SameIdentity(PeImage(candidate).Identity(), module.identity))
						return candidate;
				}
				catch (const std::exception&)
				{
				}
			}
			THROW_HR_MSG(HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND),
				"No matching image found for RVA coverage module: %ls. "
				"Supply its original binary or a module directory.", module.path.c_str());
		}

		std::wstring SymbolSearchPath()
		{
			const auto size = GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", nullptr, 0);
			if (size == 0)
				return {};
			std::wstring path(size, L'\0');
			const auto written =
			    GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", &path[0], size);
			THROW_LAST_ERROR_IF_MSG(written == 0, "Cannot read _NT_SYMBOL_PATH");
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER),
				written >= size, "_NT_SYMBOL_PATH changed while reading");
			path.resize(written);
			return path;
		}

		class ResolutionHandler : public IDebugInformationHandler
		{
		  public:
			ResolutionHandler(const RvaModule& module, Plugin::ModuleCoverage& output)
			    : module_{module}, output_{output}
			{
			}

			bool IsSourceFileSelected(const std::filesystem::path&) override
			{
				return true;
			}

			void OnSourceFile(const std::filesystem::path& path,
			                  const std::vector<Line>& lines) override
			{
				auto& result = files_[path];
				for (const auto& line : lines)
				{
					if (line.virtualAddress_ < 0 || line.lineNumber_ == 0)
						continue;
					const auto start = static_cast<uint64_t>(line.virtualAddress_);
					const auto end = start + (std::max)(uint64_t{1}, uint64_t{line.length_});
					const auto first = std::lower_bound(
					    module_.blocks.begin(), module_.blocks.end(), start,
					    [](const RvaBlock& block, uint64_t address) {
						    return uint64_t{block.block.rva} + block.block.size <= address;
					    });
					for (auto block = first;
					     block != module_.blocks.end() && block->block.rva < end;
					     ++block)
					{
						auto& executed = result[line.lineNumber_];
						executed = executed || block->executed;
					}
				}
			}

			void Finish()
			{
				for (const auto& file : files_)
				{
					if (file.second.empty())
						continue;
					auto& output = output_.AddFile(file.first);
					for (const auto& line : file.second)
						output.AddLine(line.first, line.second);
				}
			}

		  private:
			const RvaModule& module_;
			Plugin::ModuleCoverage& output_;
			std::map<std::filesystem::path, std::map<unsigned long, bool>> files_;
		};
	}

	Plugin::CoverageData RvaCoverageResolver::Resolve(
	    const RvaCoverage& coverage,
	    const std::vector<std::filesystem::path>& moduleDirectories,
	    const std::vector<SubstitutePdbSourcePath>& substitutions) const
	{
		Plugin::CoverageData output(coverage.name, coverage.exitCode);
		const auto symbolSearchPath = SymbolSearchPath();
		for (const auto& module : coverage.modules)
		{
			uint64_t end = 0;
			for (const auto& entry : module.blocks)
			{
				const auto& block = entry.block;
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), block.size == 0 || block.rva < end ||
				    uint64_t{block.rva} + block.size > module.identity.sizeOfImage, "Invalid RVA block ranges for resolution");
				end = uint64_t{block.rva} + block.size;
			}
			const auto image = FindModule(module, moduleDirectories);
			auto& resolvedModule = output.AddModule(image);
			ResolutionHandler handler(module, resolvedModule);
			DebugInformationEnumerator enumerator(substitutions, symbolSearchPath);
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_NOT_FOUND),
				!enumerator.Enumerate(image, handler),
				"Cannot load matching PDB for RVA coverage module: %ls. "
				"Place its PDB beside the image or set _NT_SYMBOL_PATH.", image.c_str());
			handler.Finish();
		}
		return output;
	}
}
