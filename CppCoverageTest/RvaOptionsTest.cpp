#include "stdafx.h"

#include <optional>
#include <sstream>

#include "CppCoverage/Options.hpp"
#include "CppCoverage/OptionsParser.hpp"
#include "CppCoverage/ExportOptionParser.hpp"
#include "CppCoverage/IOptionParser.hpp"
#include "CppCoverage/ProcessFilter.hpp"
#include "CppCoverage/ExistingProcess.hpp"
#include "CppCoverage/HandleInformation.hpp"

namespace
{
	boost::optional<CppCoverage::Options> ParseRvaOptions(
		std::initializer_list<const char*> arguments)
	{
		std::vector<std::unique_ptr<CppCoverage::IOptionParser>> parsers;
		parsers.push_back(std::make_unique<CppCoverage::ExportOptionParser>(
			std::vector<CppCoverage::ExportPluginDescription>{}));
		CppCoverage::OptionsParser parser{nullptr, std::move(parsers)};
		std::vector<const char*> argv{"OpenCppCoverage"};
		argv.insert(argv.end(), arguments.begin(), arguments.end());
		std::wostringstream explanation;
		return parser.Parse(static_cast<int>(argv.size()), argv.data(), &explanation);
	}
}

TEST(RvaOptionsTest, SymbolFreeDefaultsToRawBinary)
{
	auto options = ParseRvaOptions({"--symbol-free", "--", "test.exe"});
	ASSERT_TRUE(options);
	ASSERT_TRUE(options->IsSymbolFreeModeEnabled());
	EXPECT_FALSE(options->IsProcessWatchEnabled());
	ASSERT_EQ(1u, options->GetExports().size());
	EXPECT_EQ(CppCoverage::OptionsExportType::Binary, options->GetExports()[0].GetType());
}

TEST(RvaOptionsTest, SymbolBasedCollectionRetainsHtmlDefault)
{
	auto options = ParseRvaOptions({"--", "test.exe"});
	ASSERT_TRUE(options);
	EXPECT_FALSE(options->IsSymbolFreeModeEnabled());
	EXPECT_FALSE(options->GetResolvePath());
	ASSERT_EQ(1u, options->GetExports().size());
	EXPECT_EQ(CppCoverage::OptionsExportType::Html, options->GetExports()[0].GetType());
}

TEST(RvaOptionsTest, CollectionRejectsReportsAndSourceFilters)
{
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--export_type", "html", "--", "test.exe"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--sources", "src", "--", "test.exe"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--unified_diff", "missing.diff", "--", "test.exe"}));
}

TEST(RvaOptionsTest, CollectionRequiresProgram)
{
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--resolve", __FILE__, "--", "test.exe"}));
}

TEST(RvaOptionsTest, ResolutionAcceptsSourceFiltersAndModuleDirectories)
{
	auto options = ParseRvaOptions({
		"--resolve", __FILE__, "--module_dir", ".", "--sources", "src",
		"--export_type", "cobertura:coverage.xml"});
	ASSERT_TRUE(options);
	EXPECT_TRUE(options->GetResolvePath());
	ASSERT_EQ(1u, options->GetModuleDirectories().size());
	EXPECT_EQ(CppCoverage::OptionsExportType::Cobertura, options->GetExports()[0].GetType());
}

TEST(RvaOptionsTest, ResolutionRejectsMissingInputAndProgram)
{
	EXPECT_FALSE(ParseRvaOptions({"--resolve", "missing-rva-input.cov"}));
	EXPECT_FALSE(ParseRvaOptions({"--resolve", __FILE__, "--", "test.exe"}));
	EXPECT_FALSE(ParseRvaOptions({"--module_dir", ".", "--", "test.exe"}));
}

TEST(RvaOptionsTest, ProcessFiltersRequireSymbolFreeAndValidMode)
{
	EXPECT_FALSE(ParseRvaOptions({"--processes", "*notepad*", "--", "test.exe"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--processes", "*notepad*"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--excluded_processes", "test.exe"}));
	EXPECT_FALSE(ParseRvaOptions({"--resolve", __FILE__, "--processes", "*"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--processes", "", "--", "test.exe"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--processes", "C:test.exe", "--", "test.exe"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--processes", "C:/test.exe", "--", "test.exe"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--excluded_processes", "a\\..\\b", "--", "test.exe"}));
}

TEST(RvaOptionsTest, ExistingProcessesRequireExplicitCohortModulesAndBound)
{
	auto options = ParseRvaOptions({"--symbol-free", "--processes", "fixture-*.exe",
	    "--excluded_processes", "*excluded*", "--modules", "fixture.dll", "--duration", "2"});
	ASSERT_TRUE(options);
	EXPECT_FALSE(options->GetStartInfo());
	EXPECT_FALSE(options->IsProcessWatchEnabled());
	ASSERT_TRUE(options->GetDuration());
	EXPECT_EQ(2u, *options->GetDuration());
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--processes", "*", "--duration", "1"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--modules", "*", "--duration", "1"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--processes", "*", "--modules", "*"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--processes", "*", "--modules", "*", "--duration", "0"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--processes", "*", "--modules", "*", "--duration", "-1"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--processes", "*", "--modules", "*", "--duration", "1", "--cover_children"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--processes", "*", "--modules", "*", "--duration", "1", "--continue_after_cpp_exception"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--duration", "1", "--", "test.exe"}));
}

TEST(RvaOptionsTest, RepeatedProcessFiltersAreIndependentOfModulesAndChildren)
{
	auto options = ParseRvaOptions({
	    "--symbol-free", "--processes", "te.processhost*", "--processes", "*notepad*",
	    "--excluded_processes", "*helper*", "--excluded_processes", "*blocked*",
	    "--modules", "shcore.dll", "--", "test.exe"});
	ASSERT_TRUE(options);
	ASSERT_TRUE(options->GetProcessPatterns());
	const CppCoverage::ProcessFilter filter{*options->GetProcessPatterns()};
	EXPECT_TRUE(filter.IsSelected(L"C:\\bin\\te.processhost.exe"));
	EXPECT_TRUE(filter.IsSelected(L"C:\\bin\\notepad.exe"));
	EXPECT_FALSE(filter.IsSelected(L"C:\\bin\\te.processhost-helper.exe"));
	EXPECT_FALSE(filter.IsSelected(L"C:\\bin\\blocked-notepad.exe"));
	EXPECT_FALSE(filter.IsSelected(L"C:\\bin\\shcore.dll"));
	EXPECT_FALSE(options->IsCoverChildrenModeEnabled());
	EXPECT_EQ(std::vector<std::wstring>{L"shcore.dll"}, options->GetModulePatterns().GetSelectedPatterns());
}

TEST(RvaOptionsTest, WatchRequiresExplicitExternalCollection)
{
	auto options = ParseRvaOptions({"--symbol-free", "--watch_processes",
		"--processes", "fixture-*.exe", "--modules", "fixture.dll", "--duration", "2"});
	ASSERT_TRUE(options);
	EXPECT_TRUE(options->IsProcessWatchEnabled());
	EXPECT_FALSE(ParseRvaOptions({"--watch_processes", "--", "test.exe"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--watch_processes", "--", "test.exe"}));
	EXPECT_FALSE(ParseRvaOptions({"--resolve", __FILE__, "--watch_processes"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--watch_processes", "--modules", "*", "--duration", "1"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--watch_processes", "--processes", "*", "--duration", "1"}));
	EXPECT_FALSE(ParseRvaOptions({"--symbol-free", "--watch_processes", "--processes", "*", "--modules", "*"}));
}

TEST(RvaOptionsTest, ExclusionsOnlySelectAllOtherLaunchedProcesses)
{
	auto options = ParseRvaOptions({
	    "--symbol-free", "--cover_children", "--excluded_processes", "*helper*", "--", "test.exe"});
	ASSERT_TRUE(options);
	ASSERT_TRUE(options->GetProcessPatterns());
	const CppCoverage::ProcessFilter filter{*options->GetProcessPatterns()};
	EXPECT_TRUE(filter.IsSelected(L"C:\\bin\\parent.exe"));
	EXPECT_FALSE(filter.IsSelected(L"C:\\bin\\child-helper.exe"));
	auto unfiltered = ParseRvaOptions({"--symbol-free", "--", "test.exe"});
	ASSERT_TRUE(unfiltered);
	EXPECT_FALSE(unfiltered->GetProcessPatterns());
}

TEST(ProcessFilterTest, WholeBasenameAndOrdinalCase)
{
	CppCoverage::Patterns patterns;
	patterns.AddSelectedPatterns(L"svchost.exe");
	patterns.AddSelectedPatterns(L"*notepad*");
	patterns.AddSelectedPatterns(L"te.processhost*");
	patterns.AddSelectedPatterns(L"\u00e5pp.exe");
	const CppCoverage::ProcessFilter filter{patterns};
	EXPECT_TRUE(filter.IsSelected(L"C:\\Windows\\System32\\SVCHOST.EXE"));
	EXPECT_FALSE(filter.IsSelected(L"C:\\bin\\old-svchost.exe"));
	EXPECT_FALSE(filter.IsSelected(L"C:\\bin\\svchost.exe.backup"));
	EXPECT_FALSE(filter.IsSelected(L"C:\\notepad\\other.exe"));
	EXPECT_TRUE(filter.IsSelected(L"C:\\bin\\my-notepad-copy.exe"));
	EXPECT_TRUE(filter.IsSelected(L"C:\\bin\\TE.ProcessHost42.exe"));
	EXPECT_TRUE(filter.IsSelected(L"C:\\bin\\\u00c5PP.EXE"));
}

TEST(ProcessFilterTest, PathsExtendedNamespacesAndExclusions)
{
	CppCoverage::Patterns patterns;
	patterns.AddSelectedPatterns(L"*system32\\runtimebroker*");
	patterns.AddSelectedPatterns(L"\\\\?\\C:\\tools\\app.exe");
	patterns.AddSelectedPatterns(L"\\\\server\\share\\app.exe");
	patterns.AddExcludedPatterns(L"*blocked*");
	const CppCoverage::ProcessFilter filter{patterns};
	EXPECT_TRUE(filter.IsSelected(L"C:\\Windows\\System32\\RuntimeBroker.exe"));
	EXPECT_FALSE(filter.IsSelected(L"C:\\other\\RuntimeBroker.exe"));
	EXPECT_FALSE(filter.IsSelected(L"C:\\system32\\runtimebroker-blocked.exe"));
	EXPECT_TRUE(filter.IsSelected(L"C:\\TOOLS\\app.exe"));
	EXPECT_TRUE(filter.IsSelected(L"\\\\?\\C:\\tools\\app.exe"));
	EXPECT_TRUE(filter.IsSelected(L"\\\\?\\UNC\\SERVER\\SHARE\\app.exe"));
}

TEST(ProcessFilterTest, StarsBacktrackAndOtherCharactersAreLiteral)
{
	CppCoverage::Patterns patterns;
	patterns.AddSelectedPatterns(L"a**b*b.exe");
	patterns.AddSelectedPatterns(L"app?[1].exe");
	const CppCoverage::ProcessFilter filter{patterns};
	EXPECT_TRUE(filter.IsSelected(L"C:\\bin\\abcb.exe"));
	EXPECT_TRUE(filter.IsSelected(L"C:\\bin\\axybzb.exe"));
	EXPECT_FALSE(filter.IsSelected(L"C:\\bin\\ab.exe"));
	EXPECT_TRUE(filter.IsSelected(L"C:\\bin\\app?[1].exe"));
	EXPECT_FALSE(filter.IsSelected(L"C:\\bin\\appx1.exe"));
}

namespace
{
	CppCoverage::ExistingProcess CurrentInstance()
	{
		CppCoverage::ExistingProcess process;
		process.id = GetCurrentProcessId();
		HANDLE duplicate = nullptr;
		if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
		    GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS))
			throw std::runtime_error{"Cannot duplicate test process handle"};
		process.handle.reset(duplicate);
		FILETIME exited{}, kernel{}, user{};
		if (!GetProcessTimes(process.handle.get(), &process.created, &exited, &kernel, &user))
			throw std::runtime_error{"Cannot query test process identity"};
		process.path = CppCoverage::HandleInformation{}.ComputeProcessFilename(process.handle.get());
		return process;
	}

	BOOL WINAPI KnownCritical(HANDLE, PBOOL value)
	{
		*value = TRUE;
		return TRUE;
	}

	BOOL WINAPI UnknownCritical(HANDLE, PBOOL)
	{
		SetLastError(ERROR_ACCESS_DENIED);
		return FALSE;
	}

	BOOL WINAPI AlreadyDebugged(HANDLE, PBOOL value)
	{
		*value = TRUE;
		return TRUE;
	}
}

TEST(ExistingProcessTest, CreationTimeAndPathIdentifyOneInstance)
{
	auto process = CurrentInstance();
	EXPECT_TRUE(process.SameInstance(process.handle.get()));
	++process.created.dwLowDateTime;
	EXPECT_FALSE(process.SameInstance(process.handle.get()));
	EXPECT_THROW(process.Validate(), std::exception);
}

TEST(ExistingProcessTest, CriticalOrUnknownCriticalAdmissionIsRefused)
{
	auto process = CurrentInstance();
	CppCoverage::ExistingProcess::AdmissionChecks checks;
	checks.critical = &KnownCritical;
	EXPECT_THROW(process.Validate(checks), std::exception);
	checks.critical = &UnknownCritical;
	EXPECT_THROW(process.Validate(checks), std::exception);
}

TEST(ExistingProcessTest, ExistingDebuggerAdmissionIsRefused)
{
	auto process = CurrentInstance();
	CppCoverage::ExistingProcess::AdmissionChecks checks;
	checks.debugged = &AlreadyDebugged;
	EXPECT_THROW(process.Validate(checks), std::exception);
}

TEST(ExistingProcessTest, DeniedAdmissionHasAnActionableDiagnostic)
{
	auto process = CurrentInstance();
	CppCoverage::ExistingProcess::AdmissionChecks checks;
	checks.critical = &UnknownCritical;
	try
	{
		process.Validate(checks);
		FAIL() << "Admission must fail when critical status cannot be queried";
	}
	catch (const std::exception& error)
	{
		const auto message = CppCoverage::ProcessAdmissionDiagnostic(error);
		EXPECT_NE(std::string::npos, message.find("Access denied"));
		EXPECT_NE(std::string::npos, message.find("critical"));
	}
	const std::runtime_error ordinary{"An unrelated admission failure"};
	EXPECT_EQ(ordinary.what(), CppCoverage::ProcessAdmissionDiagnostic(ordinary));
}

TEST(ExistingProcessTest, StaleAndExitedLaunchNoticesAreIgnored)
{
	std::wstring directory(32768, L'\0');
	const auto length = GetSystemDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
	ASSERT_GT(length, 0u);
	ASSERT_LT(length, directory.size());
	directory.resize(length);
	const auto path = directory + L"\\cmd.exe";
	auto command = L"\"" + path + L"\" /d /c exit 0";
	STARTUPINFOW startup{};
	startup.cb = sizeof(startup);
	PROCESS_INFORMATION info{};
	ASSERT_TRUE(CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, FALSE,
	    CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info));
	wil::unique_handle process{info.hProcess}, thread{info.hThread};
	const auto cleanup = wil::scope_exit([&] {
		if (WaitForSingleObject(process.get(), 0) == WAIT_TIMEOUT)
		{
			TerminateProcess(process.get(), ERROR_PROCESS_ABORTED);
			WaitForSingleObject(process.get(), 5000);
		}
	});
	FILETIME created{}, exited{}, kernel{}, user{};
	ASSERT_TRUE(GetProcessTimes(process.get(), &created, &exited, &kernel, &user));
	auto stale = created;
	stale.dwLowDateTime ^= 1;
	CppCoverage::Patterns patterns;
	patterns.AddSelectedPatterns(L"cmd.exe");
	EXPECT_NO_THROW(EXPECT_FALSE(CppCoverage::InspectExistingProcess(
	    patterns, info.dwProcessId, path, 0, stale)));
	ASSERT_NE(static_cast<DWORD>(-1), ResumeThread(thread.get()));
	ASSERT_EQ(static_cast<DWORD>(WAIT_OBJECT_0), WaitForSingleObject(process.get(), 10000));
	EXPECT_NO_THROW(EXPECT_FALSE(CppCoverage::InspectExistingProcess(
	    patterns, info.dwProcessId, path, 0, created)));
}
