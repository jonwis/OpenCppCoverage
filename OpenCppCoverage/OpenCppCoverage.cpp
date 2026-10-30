// OpenCppCoverage is an open source code coverage for C++.
// Copyright (C) 2014 OpenCppCoverage
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "stdafx.h"
#include "OpenCppCoverage.hpp"

#include <iostream>
#include <algorithm>
#include <wil/result.h>

#include "CppCoverage/CodeCoverageRunner.hpp"
#include "CppCoverage/CoverageFilterSettings.hpp"
#include "CppCoverage/OptionsParser.hpp"
#include "CppCoverage/Options.hpp"
#include "CppCoverage/ProgramOptions.hpp"
#include "CppCoverage/CoverageDataMerger.hpp"
#include "CppCoverage/OptionsExport.hpp"
#include "CppCoverage/RunCoverageSettings.hpp"
#include "CppCoverage/ExportOptionParser.hpp"
#include "CppCoverage/RvaCoverageRunner.hpp"
#include "CppCoverage/RvaCoverageResolver.hpp"
#include "CppCoverage/RvaCoverage.hpp"
#include "CppCoverage/CoverageFilterManager.hpp"
#include "FileFilter/ModuleInfo.hpp"
#include "FileFilter/FileInfo.hpp"

#include "Exporter/Html/HtmlExporter.hpp"
#include "Exporter/CoberturaExporter.hpp"
#include "Exporter/Binary/BinaryExporter.hpp"
#include "Exporter/Binary/CoverageDataDeserializer.hpp"
#include "Exporter/Plugin/ExporterPluginManager.hpp"
#include "Exporter/Plugin/PluginLoader.hpp"

#include "Plugin/Exporter/IExportPlugin.hpp"
#include "Plugin/Exporter/ModuleCoverage.hpp"
#include "Plugin/Exporter/FileCoverage.hpp"

#include "Tools/Tool.hpp"
#include "Tools/Log.hpp"
#include "Tools/WarningManager.hpp"

namespace cov = CppCoverage;
namespace logging = boost::log;

namespace OpenCppCoverage
{
	namespace
	{
		//-----------------------------------------------------------------------------
		std::wstring GetDefaultPathPrefix(const cov::Options& options)
		{
			const auto* startInfo = options.GetStartInfo();

			if (startInfo)
			{
				auto path = startInfo->GetPath();
				fs::path runningCommandFilenamePath = path.filename().replace_extension("");
				
				return runningCommandFilenamePath.wstring();
			}

			return L"CoverageOutput";
		}

		//-------------------------------------------------------------------------
		std::filesystem::path GetTemplateFolder()
		{
			return Tools::GetExecutableFolder() / "Template";
		}

		//-------------------------------------------------------------------------
		std::filesystem::path GetPluginsExportFolder()
		{
			return Tools::GetExecutableFolder() / "Plugins" / "Exporter";
		}

		//-----------------------------------------------------------------------------
		void
		Export(const cov::Options& options,
		       const Exporter::ExporterPluginManager& exporterPluginManager,
		       const Plugin::CoverageData& coverage)
		{
			const auto& exports = options.GetExports();
			std::map<cov::OptionsExportType, std::unique_ptr<Exporter::IExporter>> exporters;
			
			exporters.emplace(cov::OptionsExportType::Html, 
				std::unique_ptr<Exporter::IExporter>(std::make_unique<Exporter::HtmlExporter>( GetTemplateFolder() )));
			exporters.emplace(cov::OptionsExportType::Cobertura, 
				std::unique_ptr<Exporter::IExporter>(std::make_unique<Exporter::CoberturaExporter>()));
			exporters.emplace(cov::OptionsExportType::Binary,
				std::unique_ptr<Exporter::IExporter>(std::make_unique<Exporter::BinaryExporter>()));
			
			auto defaultPathPrefix = GetDefaultPathPrefix(options);

			for (const auto& singleExport : exports)
			{
				auto exportType = singleExport.GetType();
				auto parameter = singleExport.GetParameter();

				if (exportType == cov::OptionsExportType::Plugin)
					exporterPluginManager.Export(
					    singleExport.GetName(), coverage, parameter);
				else
				{
					const auto& exporter = exporters.at(exportType);
					auto output =
					    (parameter)
					        ? fs::path{*parameter}
					        : exporter->GetDefaultPath(defaultPathPrefix);

					exporter->Export(coverage, output);
				}
			}
		}

		//-----------------------------------------------------------------------------
		std::vector<Plugin::CoverageData> LoadInputCoverageDatas(const cov::Options& options)
		{
			std::vector<Plugin::CoverageData> coverageDatas;
			Exporter::CoverageDataDeserializer coverageDataDeserializer;

			for (const auto& path : options.GetInputCoveragePaths())
			{				
				THROW_HR_IF_MSG(E_INVALIDARG, cov::IsRvaCoverage(path),
					"RVA coverage requires --resolve before it can be merged with source coverage.");
				auto errorMsg = "Cannot extract coverage data from " + path.string();

				LOG_INFO << L"Load coverage file: " << path.wstring();
				coverageDatas.push_back(coverageDataDeserializer.Deserialize(path, errorMsg));
			}
			return coverageDatas;
		}

		//-----------------------------------------------------------------------------
		void InitLogger(const cov::Options& options)
		{
			auto logLevel = logging::trivial::info;

			switch (options.GetLogLevel())
			{
				case cov::LogLevel::Verbose: logLevel = logging::trivial::debug; break;
				case cov::LogLevel::Quiet: logLevel = logging::trivial::error; break;
			}

			Tools::InitConsoleAndFileLog(L"LastCoverageResults.log");
			Tools::SetLoggerMinSeverity(logLevel);
		}

		Plugin::CoverageData FilterResolvedCoverage(
			cov::CoverageFilterManager& filters, const Plugin::CoverageData& coverage)
		{
			Plugin::CoverageData filtered{coverage.GetName(), coverage.GetExitCode()};
			for (const auto& module : coverage.GetModules())
			{
				auto& outputModule = filtered.AddModule(module->GetPath());
				FileFilter::ModuleInfo moduleInfo{nullptr, module->GetPath(), nullptr};
				for (const auto& file : module->GetFiles())
				{
					if (!filters.IsSourceFileSelected(file->GetPath().wstring()))
						continue;
					auto& outputFile = outputModule.AddFile(file->GetPath());
					FileFilter::FileInfo fileInfo{file->GetPath(), {}};
					for (const auto& line : file->GetLines())
					{
						FileFilter::LineInfo lineInfo{static_cast<int>(line.GetLineNumber()), 0, 0};
						if (filters.IsLineSelected(moduleInfo, fileInfo, lineInfo))
							outputFile.AddLine(line.GetLineNumber(), line.HasBeenExecuted());
					}
				}
			}
			return filtered;
		}

		//-----------------------------------------------------------------------------
		int Run(const cov::Options& options,
		        const Exporter::ExporterPluginManager& exporterPluginManager,
		        std::shared_ptr<Tools::WarningManager> warningManager)
		{
			InitLogger(options);

			auto coveraDatas = LoadInputCoverageDatas(options);
			const auto* startInfo = options.GetStartInfo();
			
			std::wostringstream ostr;
			ostr << std::endl << options;
			LOG_INFO << L"Start Program:" << ostr.str();

			cov::CodeCoverageRunner codeCoverageRunner{ warningManager };
			cov::CoverageFilterSettings coverageFilterSettings{ options.GetModulePatterns(), options.GetSourcePatterns() };
			auto exitCode = 0;
			if (options.GetResolvePath())
			{
				auto raw = cov::ReadRvaCoverage(*options.GetResolvePath());
				cov::CoverageFilterManager filters{
					coverageFilterSettings, options.GetUnifiedDiffSettingsCollection(),
					options.GetExcludedLineRegexes(), false};
				raw.modules.erase(std::remove_if(raw.modules.begin(), raw.modules.end(),
					[&](const cov::RvaModule& module) {
						return !filters.IsModuleSelected(module.path.wstring());
					}), raw.modules.end());
				auto resolvedData = cov::RvaCoverageResolver{}.Resolve(
					raw, options.GetModuleDirectories(), options.GetSubstitutePdbSourcePaths());
				auto resolved = FilterResolvedCoverage(filters, resolvedData);
				cov::CoverageDataMerger merger;
				if (options.IsAggregateByFileModeEnabled())
					merger.MergeFileCoverage(resolved);
				Export(options, exporterPluginManager, resolved);
				return 0;
			}

			if (startInfo)
			{
				size_t maxUnmatchPathsForWarning = (options.GetLogLevel() == cov::LogLevel::Verbose) 
					? std::numeric_limits<size_t>::max() : 30;

				cov::RunCoverageSettings runCoverageSettings(
				    *startInfo,
				    coverageFilterSettings,
				    options.GetUnifiedDiffSettingsCollection(),
				    options.GetExcludedLineRegexes(),
				    options.GetSubstitutePdbSourcePaths());

				runCoverageSettings.SetCoverChildren(options.IsCoverChildrenModeEnabled());
				if (options.GetProcessPatterns())
					runCoverageSettings.SetProcessPatterns(*options.GetProcessPatterns());
				runCoverageSettings.SetContinueAfterCppException(options.IsContinueAfterCppExceptionModeEnabled());
                runCoverageSettings.SetStopOnAssert(options.IsStopOnAssertModeEnabled());
                runCoverageSettings.SetMaxUnmatchPathsForWarning(maxUnmatchPathsForWarning);
				runCoverageSettings.SetOptimizedBuildSupport(options.IsOptimizedBuildSupportEnabled());
				if (options.IsSymbolFreeModeEnabled())
				{
					auto raw = cov::RvaCoverageRunner{}.RunCoverage(runCoverageSettings);
					for (const auto& output : options.GetExports())
					{
						auto path = output.GetParameter()
							? fs::path{ *output.GetParameter() }
							: fs::path{ GetDefaultPathPrefix(options) + L".cov" };
						cov::WriteRvaCoverage(raw, path);
					}
					return raw.exitCode;
				}
				auto coverageData = codeCoverageRunner.RunCoverage(runCoverageSettings);
				exitCode = coverageData.GetExitCode();
				coveraDatas.push_back(std::move(coverageData));
			}
			else if (options.GetDuration())
			{
				auto raw = cov::RvaCoverageRunner{}.CollectExisting(
				    coverageFilterSettings, *options.GetProcessPatterns(), *options.GetDuration());
				for (const auto& output : options.GetExports())
				{
					const auto path = output.GetParameter() ? fs::path{*output.GetParameter()} :
					    fs::path{GetDefaultPathPrefix(options) + L".cov"};
					cov::WriteRvaCoverage(raw, path);
				}
				return raw.exitCode;
			}
			cov::CoverageDataMerger	coverageDataMerger;

			auto coverageData = coverageDataMerger.Merge(coveraDatas);

			if (options.IsAggregateByFileModeEnabled())
				coverageDataMerger.MergeFileCoverage(coverageData);

			Export(options, exporterPluginManager, coverageData);
			LOG_INFO << L"The code coverage report is not what you expect? See the FAQ "
				L"https://github.com/OpenCppCoverage/OpenCppCoverage/wiki/FAQ.";

			if (exitCode)
				LOG_ERROR << L"Your program stop with error code: " << exitCode;
			return exitCode;
		}
	}

	//-----------------------------------------------------------------------------
	int OpenCppCoverage::Run(int argc,
	                         const char** argv,
	                         std::wostream* emptyOptionsExplanation) const
	{
		auto warningManager = std::make_shared<Tools::WarningManager>();
		std::vector<std::unique_ptr<cov::IOptionParser>> optionParsers;

		Exporter::ExporterPluginManager exporterPluginManager{
		    Exporter::PluginLoader<Plugin::IExportPlugin>{},
		    GetPluginsExportFolder()};

		auto exportPluginDescriptions =
		    exporterPluginManager.CreateExportPluginDescriptions();
		optionParsers.push_back(std::make_unique<cov::ExportOptionParser>(
		    std::move(exportPluginDescriptions)));
		cov::OptionsParser optionsParser{warningManager, std::move(optionParsers)};

		auto options = optionsParser.Parse(argc, argv, emptyOptionsExplanation);
		auto status = FailureExitCode;

		if (options)
		{
			try
			{
				status = ::OpenCppCoverage::Run(*options, exporterPluginManager, warningManager);
			}
			catch (const std::exception& e)
			{
				LOG_ERROR << "Error: " << e.what();
			}
			catch (...)
			{
				LOG_ERROR << "Unkown Error";
			}

			warningManager->DisplayWarnings();
			if (options->IsPlugingModeEnabled())
			{
				std::cout << "Press any key to continue... ";
				std::cin.get();
			}
		}

		return status;
	}
}