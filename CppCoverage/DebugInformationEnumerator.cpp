//// OpenCppCoverage is an open source code coverage for C++.
//// Copyright (C) 2017 OpenCppCoverage
////
//// This program is free software: you can redistribute it and/or modify
//// it under the terms of the GNU General Public License as published by
//// the Free Software Foundation, either version 3 of the License, or
//// any later version.
////
//// This program is distributed in the hope that it will be useful,
//// but WITHOUT ANY WARRANTY; without even the implied warranty of
//// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//// GNU General Public License for more details.
////
//// You should have received a copy of the GNU General Public License
//// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#include "stdafx.h"
#include "DebugInformationEnumerator.hpp"

#include <Windows.h>
#include <diacreate.h>
#include <dia2.h>
#include <wrl/client.h>

#include <filesystem>
#include <set>
#include <boost/algorithm/string.hpp>

#include "tools/Log.hpp"

#include "CppCoverageException.hpp"

namespace CppCoverage
{
	using Microsoft::WRL::ComPtr;

	namespace
	{
		//----------------------------------------------------------------------
		class DiaString
		{
		  public:
			DiaString() = default;
			DiaString(const DiaString&) = delete;
			DiaString(DiaString&&) = delete;

			DiaString& operator=(const DiaString&) = delete;
			DiaString& operator=(DiaString&&) = delete;

			~DiaString()
			{
				ReleaseMemory();
			}

			BSTR* operator&()
			{
				ReleaseMemory();
				return &str_;
			}

			operator std::wstring() const
			{
				if (!str_)
					return L"";
				return str_;
			}

		  private:
			void ReleaseMemory()
			{
				if (str_ != nullptr)
				{
					// Cannot call SysFreeString as dia generated invalid BSTR
					// for x64.
					LocalFree(str_ - 2);
					str_ = nullptr;
				}
			}

			BSTR str_ = nullptr;
		};

		//----------------------------------------------------------------------
		template <typename Value, typename Collection, typename Fct>
		void EnumerateCollection(Collection& collection, Fct fct)
		{
			ComPtr<Value> value;
			ULONG celtFetched;
			while (collection.Next(1, &value, &celtFetched) == S_OK &&
			       celtFetched == 1 && value != nullptr)
			{
				fct(*value.Get());
				value = nullptr;
			}
		}

		//----------------------------------------------------------------------
		ComPtr<IDiaEnumSourceFiles> GetEnumSourceFiles(IDiaSession& session)
		{
			ComPtr<IDiaEnumTables> tables;
			if (session.getEnumTables(&tables) != S_OK || !tables)
				THROW("DIA: Cannot get tables");

			ComPtr<IDiaEnumSourceFiles> sourceFiles;

			EnumerateCollection<IDiaTable>(*tables.Get(), [&](IDiaTable& table) {
				if (!sourceFiles)
				{
					ComPtr<IDiaEnumSourceFiles> currentSourceFiles;
					if (table.QueryInterface(_uuidof(IDiaEnumSourceFiles),
					                         reinterpret_cast<void**>(
					                             currentSourceFiles.GetAddressOf())) ==
					    S_OK)
					{
						sourceFiles = currentSourceFiles;
					}
				}
			});

			return sourceFiles;
		}

		std::wstring CanonicalSourcePath(const std::filesystem::path& path)
		{
			auto name = std::filesystem::weakly_canonical(std::filesystem::absolute(path))
				.lexically_normal().wstring();
			boost::algorithm::to_lower(name);
			return name;
		}

		//----------------------------------------------------------------------
		struct DiaLoadCallback : public IDiaLoadCallback
		{
			explicit DiaLoadCallback(bool allowSymbolServer, std::filesystem::path* openedPdb)
			    : allowSymbolServer_{allowSymbolServer}, openedPdb_{openedPdb}
			{
			}

			//------------------------------------------------------------------
			HRESULT STDMETHODCALLTYPE QueryInterface(
			    REFIID riid,
			    _COM_Outptr_ void __RPC_FAR* __RPC_FAR* ppvObject) override
			{
				if (!ppvObject)
					return E_POINTER;
				*ppvObject = nullptr;

				if (riid == __uuidof(IUnknown) || riid == IID_IDiaLoadCallback)
				{
					*ppvObject = this;
					return S_OK;
				}

				return E_NOINTERFACE;
			}

			//------------------------------------------------------------------
			ULONG STDMETHODCALLTYPE AddRef() override
			{
				return 1; // On stack
			}

			//------------------------------------------------------------------
			ULONG STDMETHODCALLTYPE Release() override
			{
				return 1; // On stack
			}

			//------------------------------------------------------------------
			HRESULT STDMETHODCALLTYPE NotifyDebugDir(BOOL fExecutable,
			                                         DWORD cbData,
			                                         BYTE* pbData) override
			{
				return S_OK;
			}

			//------------------------------------------------------------------
			HRESULT STDMETHODCALLTYPE NotifyOpenDBG(LPCOLESTR dbgPath,
			                                        HRESULT resultCode) override
			{
				return S_OK;
			}

			//------------------------------------------------------------------
			HRESULT STDMETHODCALLTYPE NotifyOpenPDB(LPCOLESTR pdbPath,
			                                        HRESULT resultCode) override
			{
				if (openedPdb_ && pdbPath && resultCode == S_OK)
				{
					try
					{
						*openedPdb_ = pdbPath;
					}
					catch (...)
					{
						return E_OUTOFMEMORY;
					}
				}
				LOG_DEBUG << "Try to load pdb from " << pdbPath << ": "
				          << (resultCode == S_OK ? "Success" : "Failed");
				return S_OK;
			}

			//------------------------------------------------------------------
			HRESULT STDMETHODCALLTYPE RestrictRegistryAccess() override
			{
				return S_OK;
			}

			//------------------------------------------------------------------
			HRESULT STDMETHODCALLTYPE RestrictSymbolServerAccess() override
			{
				return allowSymbolServer_ ? S_FALSE : S_OK;
			}

			const bool allowSymbolServer_;
			std::filesystem::path* openedPdb_;
		};

		//----------------------------------------------------------------------
		ComPtr<IDiaDataSource>
		LoadDataForExe(const std::filesystem::path& path,
		               const std::wstring& symbolSearchPath, std::filesystem::path* openedPdb)
		{
			ComPtr<IDiaDataSource> sourcePtr;

			auto msDia = L"msdia140.dll";
			if (NoRegCoCreate(msDia,
			                  _uuidof(DiaSourceAlt),
			                  _uuidof(IDiaDataSource),
			                  reinterpret_cast<void**>(sourcePtr.GetAddressOf())) != S_OK)
			{
				THROW(std::wstring(L"DIA: Cannot register dia. Make sure ") +
				      msDia + L" is in the current directory.");
			}

			DiaLoadCallback diaLoadCallback(!symbolSearchPath.empty(), openedPdb);
			if (!sourcePtr ||
			    sourcePtr->loadDataForExe(
			        path.wstring().c_str(),
			        symbolSearchPath.empty() ? nullptr : symbolSearchPath.c_str(),
			        &diaLoadCallback) != S_OK)
			{
				return nullptr;
			}
			return sourcePtr;
		}
	}

	//--------------------------------------------------------------------------
	DebugInformationEnumerator::DebugInformationEnumerator(
	    const std::vector<SubstitutePdbSourcePath>& substitutePdbSourcePaths)
		: DebugInformationEnumerator(substitutePdbSourcePaths, L"")
	{
	}

	DebugInformationEnumerator::DebugInformationEnumerator(
	    const std::vector<SubstitutePdbSourcePath>& substitutePdbSourcePaths,
	    const std::wstring& symbolSearchPath)
		: substitutePdbSourcePaths_{substitutePdbSourcePaths},
		  symbolSearchPath_{symbolSearchPath}
	{
	}

	//-------------------------------------------------------------------------
	bool
	DebugInformationEnumerator::Enumerate(const std::filesystem::path& path,
	                                      IDebugInformationHandler& handler, bool enumerateFunctions)
	{
		std::filesystem::path openedPdb;
		auto sourcePtr = LoadDataForExe(path, symbolSearchPath_, &openedPdb);

		if (!sourcePtr)
			return false;
		if (!openedPdb.empty())
			handler.OnPdbFile(openedPdb);

		ComPtr<IDiaSession> sessionPtr;
		if (sourcePtr->openSession(&sessionPtr) != S_OK || !sessionPtr)
			THROW("DIA: Cannot open session.");

		if (enumerateFunctions)
		{
			ComPtr<IDiaSymbol> global;
			ComPtr<IDiaEnumSymbols> compilands;
			if (sessionPtr->get_globalScope(&global) != S_OK || !global ||
				global->findChildren(SymTagCompiland, nullptr, nsNone, &compilands) != S_OK || !compilands)
				THROW("DIA: Cannot enumerate machine functions.");
			EnumerateCollection<IDiaSymbol>(*compilands.Get(), [&](IDiaSymbol& compiland) {
				ComPtr<IDiaEnumSymbols> functions;
				if (compiland.findChildren(SymTagFunction, nullptr, nsNone, &functions) != S_OK || !functions)
					THROW("DIA: Cannot enumerate compiland functions.");
				EnumerateCollection<IDiaSymbol>(*functions.Get(), [&](IDiaSymbol& symbol) {
					IDebugInformationHandler::Function function;
					DWORD rva = 0;
					ULONGLONG length = 0;
					DiaString name;
					symbol.get_name(&name);
					function.name = name;
					if (symbol.get_relativeVirtualAddress(&rva) != S_OK ||
						symbol.get_length(&length) != S_OK || !length)
						function.exclusion = "missing-machine-function-range";
					function.rva = rva;
					function.size = length;
					BOOL eh = FALSE, seh = FALSE, eha = FALSE, split = FALSE, naked = FALSE;
					const auto ehResult = symbol.get_hasEH(&eh);
					const auto sehResult = symbol.get_hasSEH(&seh);
					const auto ehaResult = symbol.get_hasEHa(&eha);
					const auto splitResult = symbol.get_isSplitted(&split);
					const auto nakedResult = symbol.get_isNaked(&naked);
					for (const auto& annotation : {
						std::make_pair(ehResult, "hasEH"), std::make_pair(sehResult, "hasSEH"),
						std::make_pair(ehaResult, "hasEHa"), std::make_pair(splitResult, "isSplitted"),
						std::make_pair(nakedResult, "isNaked")})
						if (annotation.first != S_OK)
							function.uncertainties.push_back(std::string{"unavailable-dia-annotation:"} + annotation.second);
					if ((ehResult == S_OK && eh) || (sehResult == S_OK && seh) ||
						(ehaResult == S_OK && eha) || (splitResult == S_OK && split) ||
						(nakedResult == S_OK && naked))
						function.exclusion = "eh-split-or-naked-function";
					handler.OnFunction(function);
				});
			});
		}

		auto sourceFiles = GetEnumSourceFiles(*sessionPtr.Get());
		if (!sourceFiles)
			THROW("DIA: cannot get SourceFiles");

		EnumerateCollection<IDiaSourceFile>(
		    *sourceFiles.Get(), [&](IDiaSourceFile& sourceFile) {
			    auto filename = GetSourceFileName(sourceFile);
			    if (handler.IsSourceFileSelected(filename))
			    {
				    lines_.clear();
				    EnumLines(*sessionPtr.Get(), sourceFile, handler);
				    handler.OnSourceFile(filename, lines_);
			    }
		    });
		return true;
	}

	//----------------------------------------------------------------------
	void
	DebugInformationEnumerator::EnumLines(IDiaSession& session,
	                                      IDiaSourceFile& sourceFile,
	                                      IDebugInformationHandler& handler)
	{
		ComPtr<IDiaEnumSymbols> symbols;
		if (sourceFile.get_compilands(&symbols) != S_OK || !symbols)
			THROW("DIA: Cannot get compilands");

		bool checksumReported = false;
		EnumerateCollection<IDiaSymbol>(*symbols.Get(), [&](IDiaSymbol& symbol) {
			if (handler.WantsSourceProvenance())
			{
				DiaString pdbFilename;
				if (sourceFile.get_fileName(&pdbFilename) != S_OK)
					THROW("DIA: Cannot get source filename for checksum lookup");
				const std::wstring name = pdbFilename;
				ComPtr<IDiaEnumSourceFiles> matchingFiles;
				bool compilandChecksumReported = false;
				// Source-table records carry paths; compiland-bound records carry checksums.
				if (session.findFile(&symbol, name.c_str(), nsNone, &matchingFiles) == S_OK && matchingFiles)
					EnumerateCollection<IDiaSourceFile>(*matchingFiles.Get(), [&](IDiaSourceFile& matchingFile) {
						DWORD kind = 0, size = 0;
						std::vector<uint8_t> checksum;
						if (matchingFile.get_checksumType(&kind) == S_OK && kind != 0 &&
							SUCCEEDED(matchingFile.get_checksum(0, &size, nullptr)) &&
							size != 0 && size <= 64)
						{
							checksum.resize(size);
							DWORD written = 0;
							if (matchingFile.get_checksum(size, &written, checksum.data()) != S_OK ||
								written != size)
								checksum.clear();
						}
						handler.OnSourceChecksum(GetSourceFileName(sourceFile), kind, checksum);
						compilandChecksumReported = true;
					});
				if (!compilandChecksumReported)
					handler.OnSourceChecksum(GetSourceFileName(sourceFile), 0, {});
				checksumReported = true;
			}
			ComPtr<IDiaEnumLineNumbers> lines;

			if (session.findLines(&symbol, &sourceFile, &lines) != S_OK ||
			    !lines)
			{
				THROW("DIA: Cannot find lines");
			}

			EnumerateCollection<IDiaLineNumber>(
			    *lines.Get(), [&](IDiaLineNumber& lineNumber) {
				    OnNewLine(session, lineNumber, handler);
			    });
			if (handler.WantsSourceProvenance())
			{
				const auto sourcePath = GetSourceFileName(sourceFile);
				const auto sourceKey = CanonicalSourcePath(sourcePath);
				ComPtr<IDiaEnumSymbols> functions;
				if (symbol.findChildren(SymTagFunction, nullptr, nsNone, &functions) != S_OK || !functions)
				{
					handler.OnMappingDiagnostic(GetSourceFileName(sourceFile),
						"inline-line-enumeration-unavailable");
					return;
				}
				std::vector<ComPtr<IDiaSymbol>> scopes;
				EnumerateCollection<IDiaSymbol>(*functions.Get(), [&](IDiaSymbol& function) {
					scopes.emplace_back(&function);
				});
				std::set<DWORD> visited;
				while (!scopes.empty())
				{
					auto scope = std::move(scopes.back());
					scopes.pop_back();
					DWORD id = 0;
					if (scope->get_symIndexId(&id) != S_OK)
						THROW("DIA: Cannot get inline scope identity");
					if (!visited.insert(id).second)
						continue;
					if (visited.size() > 4000000)
						THROW("DIA: Inline scope limit exceeded");
					for (const auto tag : {SymTagInlineSite, SymTagBlock})
					{
						ComPtr<IDiaEnumSymbols> children;
						const auto result = scope->findChildren(tag, nullptr, nsNone, &children);
						if (FAILED(result))
							handler.OnMappingDiagnostic(sourcePath, "inline-scope-enumeration-unavailable");
						else if (children)
							EnumerateCollection<IDiaSymbol>(*children.Get(), [&](IDiaSymbol& child) {
								scopes.emplace_back(&child);
								if (tag != SymTagInlineSite)
									return;
								ComPtr<IDiaEnumLineNumbers> inlineLines;
								if (session.findInlineeLines(&child, &inlineLines) != S_OK || !inlineLines)
								{
									handler.OnMappingDiagnostic(sourcePath, "inline-line-enumeration-unavailable");
									return;
								}
								EnumerateCollection<IDiaLineNumber>(*inlineLines.Get(), [&](IDiaLineNumber& line) {
									ComPtr<IDiaSourceFile> inlineSource;
									if (line.get_sourceFile(&inlineSource) != S_OK || !inlineSource)
									{
										handler.OnMappingDiagnostic(sourcePath, "inline-source-file-unavailable");
										return;
									}
									if (CanonicalSourcePath(GetSourceFileName(*inlineSource.Get())) == sourceKey)
										OnNewLine(session, line, handler);
								});
							});
					}
				}
			}
		});
		if (handler.WantsSourceProvenance() && !checksumReported)
			handler.OnSourceChecksum(GetSourceFileName(sourceFile), 0, {});
	}

	//----------------------------------------------------------------------
	void
	DebugInformationEnumerator::OnNewLine(IDiaSession& session,
	                                      IDiaLineNumber& lineNumber,
	                                      IDebugInformationHandler& handler)
	{
		DWORD linenum = 0;
		if (lineNumber.get_lineNumber(&linenum) != S_OK)
			THROW("DIA: Cannot get line number");

		// Skip invalid lines
		if (linenum != 0x00f00f00 && linenum != 0x00feefee)
		{
			DWORD virtualAddress = 0;
			if (lineNumber.get_relativeVirtualAddress(&virtualAddress) != S_OK)
				THROW("DIA: Cannot get relative virtual address");
			DWORD length = 0;
			if (lineNumber.get_length(&length) != S_OK)
				THROW("DIA: Cannot get line length");

			ComPtr<IDiaSymbol> symbol;
			if (session.findSymbolByRVA(
			        virtualAddress, SymTagEnum::SymTagNull, &symbol) != S_OK ||
			    !symbol)
			{
				THROW("DIA: Cannot find symbol");
			}

			unsigned long symIndex = 0;
			if (symbol->get_symIndexId(&symIndex) != S_OK)
				THROW("DIA: Cannot get symIndex");

			lines_.emplace_back(linenum, virtualAddress, symIndex, length);
		}
	}

	//----------------------------------------------------------------------
	std::filesystem::path DebugInformationEnumerator::GetSourceFileName(
	    IDiaSourceFile& sourceFile) const
	{
		DiaString fileName;
		if (sourceFile.get_fileName(&fileName) != S_OK)
			THROW("DIA: Cannot get filename");
		std::wstring filenameStr = fileName;

		for (const auto& paths : substitutePdbSourcePaths_)
		{
			auto pdbStartPath = paths.GetPdbStartPath().wstring();

			if (boost::istarts_with(filenameStr, pdbStartPath))
			{
				auto startIndex = pdbStartPath.size();
				if (startIndex < filenameStr.size() && !pdbStartPath.empty() &&
				    pdbStartPath.back() != '\\' &&
				    filenameStr[startIndex] != '\\')
					continue;
				if (startIndex < filenameStr.size() && filenameStr[startIndex] == '\\')
					++startIndex;
				auto remainingPath = filenameStr.substr(startIndex);
				filenameStr = (paths.GetLocalPath() / remainingPath).wstring();
				break;
			}
		}

		return filenameStr;
	}
}
