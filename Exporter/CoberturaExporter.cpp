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

#include <unordered_set>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <filesystem>

#include "CoberturaExporter.hpp"
#include "Plugin/Exporter/CoverageData.hpp"
#include "Plugin/Exporter/ModuleCoverage.hpp"
#include "Plugin/Exporter/FileCoverage.hpp"
#include "Plugin/Exporter/LineCoverage.hpp"
#include "CppCoverage/CoverageRateComputer.hpp"
#include "InvalidOutputFileException.hpp"

#include "Tools/Tool.hpp"

namespace property_tree = boost::property_tree;
namespace fs = std::filesystem;

namespace Exporter
{
	namespace
	{
		//-------------------------------------------------------------------------
		property_tree::wptree& AddChild(property_tree::wptree& tree, const std::wstring& name)
		{
			return tree.add_child(name, property_tree::wptree{});
		}

		//-------------------------------------------------------------------------
		std::wstring ToUft8WString(const fs::path& path)
		{
			auto str = Tools::ToUtf8String(path.wstring());
			auto utf8Str = Tools::LocalToWString(str);
			return utf8Str;
		}

		//-------------------------------------------------------------------------
		void SetCoverage(
			property_tree::wptree& node,
			const CppCoverage::CoverageRate& coverageRate)
		{
			node.put(L"<xmlattr>.line-rate", coverageRate.GetRate());
			node.put(L"<xmlattr>.branch-rate", 0);
			node.put(L"<xmlattr>.complexity", 0);
		}

		//-------------------------------------------------------------------------
		void FillFileTree(
			const CppCoverage::CoverageRateComputer& coverageRateComputer,
			property_tree::wptree& fileTree, 
			const Plugin::FileCoverage& file,
			bool visualStudio)
		{
			const auto& path = file.GetPath();
			const auto& coverageRate = coverageRateComputer.GetCoverageRate(file);

			fileTree.put(L"<xmlattr>.name", ToUft8WString(visualStudio ? path : path.filename()));
			fileTree.put(L"<xmlattr>.filename",
				ToUft8WString(visualStudio ? path : path.relative_path()));
			SetCoverage(fileTree, coverageRate);
			auto& methodsTree = AddChild(fileTree, L"methods");

			property_tree::wptree& linesTree = AddChild(fileTree, L"lines");

			for (const auto& line : file.GetLines())
			{
				property_tree::wptree& lineTree = AddChild(linesTree, L"line");

				lineTree.put(L"<xmlattr>.number", std::to_wstring(line.GetLineNumber()));
				lineTree.put(L"<xmlattr>.hits", line.HasBeenExecuted() ? L"1" : L"0");
			}

			if (visualStudio && !file.GetLines().empty())
			{
				// Microsoft's importer reads method lines; the model has file-level coverage.
				auto& methodTree = AddChild(methodsTree, L"method");
				methodTree.put(L"<xmlattr>.name", L"[file-level coverage]");
				methodTree.put(L"<xmlattr>.signature", L"");
				SetCoverage(methodTree, coverageRate);
				methodTree.add_child(L"lines", linesTree);
			}
		}

		//-------------------------------------------------------------------------
		void WriteSourceRoots(
			const Plugin::CoverageData& coverageData,
			property_tree::wptree& coverageTree)
		{
			std::unordered_set<std::wstring> rootPaths;

			for (const auto& module : coverageData.GetModules())
			{
				for (const auto& file : module->GetFiles())
				{
					const auto& path = file->GetPath();
					rootPaths.insert(path.root_name().wstring());
				}
			}

			auto& sourcesTree = AddChild(coverageTree, L"sources");

			for (const auto& rootPath : rootPaths)
				sourcesTree.add(L"source", rootPath);
		}

		//-------------------------------------------------------------------------
		void SetCoverageAttributes(property_tree::wptree& coverageTree,
		                           const CppCoverage::CoverageRate& coverageRate)
		{
			coverageTree.put(L"<xmlattr>.branches-covered", 0);
			coverageTree.put(L"<xmlattr>.branches-valid", 0);

			auto now = std::chrono::system_clock::now();
			auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
			coverageTree.put(L"<xmlattr>.timestamp", timestamp);
			coverageTree.put(L"<xmlattr>.lines-covered",
			                 coverageRate.GetExecutedLinesCount());
			coverageTree.put(L"<xmlattr>.lines-valid",
			                 coverageRate.GetTotalLinesCount());
			coverageTree.put(L"<xmlattr>.version", 0);
		}

		//-------------------------------------------------------------------------
		void FillCoverageTree(
			property_tree::wptree& root,
			const Plugin::CoverageData& coverageData,
			bool visualStudio)
		{
			CppCoverage::CoverageRateComputer coverageRateComputer(coverageData);
			auto& coverageTree = AddChild(root, L"coverage");
			const auto& coverageRate = coverageRateComputer.GetCoverageRate();
			SetCoverage(coverageTree, coverageRate);
			SetCoverageAttributes(coverageTree, coverageRate);

			if (visualStudio)
				AddChild(coverageTree, L"sources").add(L"source", L"");
			else
				WriteSourceRoots(coverageData, coverageTree);

			property_tree::wptree& packagesTree = AddChild(coverageTree, L"packages");

			size_t moduleIndex = 0;
			for (const auto& module : coverageData.GetModules())
			{
				// Do not create package if no files exists -> Coverage will not be visible by module
				if (!module->GetFiles().empty())
				{
					property_tree::wptree& packageTree = AddChild(packagesTree, L"package");
					property_tree::wptree& classesTree = AddChild(packageTree, L"classes");
					const auto& coverageRate = coverageRateComputer.GetCoverageRate(*module);

					auto moduleName = module->GetPath();
					if (visualStudio)
					{
						// The importer strips directories and the final extension from module names.
						moduleName = moduleName.filename().wstring() + L" [module " +
							std::to_wstring(++moduleIndex) + L"].coverage-module";
					}
					packageTree.put(L"<xmlattr>.name", ToUft8WString(moduleName));
					SetCoverage(packageTree, coverageRate);

					for (const auto& file : module->GetFiles())
					{
						property_tree::wptree& fileTree = AddChild(classesTree, L"class");
						FillFileTree(coverageRateComputer, fileTree, *file, visualStudio);
					}
				}
			}
		}
	}

	//-------------------------------------------------------------------------
	CoberturaExporter::CoberturaExporter() = default;

	CoberturaExporter::CoberturaExporter(bool visualStudio)
		: visualStudio_{visualStudio}
	{
	}

	//-------------------------------------------------------------------------
	std::filesystem::path CoberturaExporter::GetDefaultPath(const std::wstring& prefix) const
	{
		std::filesystem::path path{ prefix };
		
		path += visualStudio_ ? "Coverage.vs.xml" : "Coverage.xml";

		return path;		
	}

	//-------------------------------------------------------------------------
	void CoberturaExporter::Export(
		const Plugin::CoverageData& coverageData, 
		const std::filesystem::path& output)
	{
		Tools::CreateParentFolderIfNeeded(output);
		std::wofstream ofs{ output };

		if (!ofs)
			throw InvalidOutputFileException(output, "cobertura");
		Export(coverageData, ofs);
		Tools::ShowOutputMessage(L"Cobertura report generated: ", output);
	}

	//-------------------------------------------------------------------------
	void CoberturaExporter::Export(
		const Plugin::CoverageData& coverageData,
		std::wostream& ostream) const
	{
		using Ptree = property_tree::wptree;
		Ptree root;
		
		FillCoverageTree(root, coverageData, visualStudio_);

		property_tree::xml_writer_settings<Ptree::key_type> settings(' ', 2);
		property_tree::xml_parser::write_xml(ostream, root, settings);
	}
}
