#pragma once

#include <memory>

#include "CppCoverageExport.hpp"
#include "IDebugEventsHandler.hpp"
#include "RvaCoverage.hpp"

namespace CppCoverage
{
	class RunCoverageSettings;
	class CoverageFilterSettings;
	class Patterns;

	class CPPCOVERAGE_DLL RvaCoverageRunner : private IDebugEventsHandler
	{
	public:
		RvaCoverageRunner();
		~RvaCoverageRunner();
		RvaCoverage RunCoverage(const RunCoverageSettings&);
		RvaCoverage CollectExisting(
		    const CoverageFilterSettings&, const Patterns&, unsigned durationSeconds);

	private:
		struct State;
		std::unique_ptr<State> state_;
		void LoadModule(HANDLE process, HANDLE file, void* base);
		void OnCreateProcess(const CREATE_PROCESS_DEBUG_INFO&) override;
		void OnExitProcess(HANDLE, HANDLE, const EXIT_PROCESS_DEBUG_INFO&) override;
		void OnLoadDll(HANDLE, HANDLE, const LOAD_DLL_DEBUG_INFO&) override;
		void OnUnloadDll(HANDLE, HANDLE, const UNLOAD_DLL_DEBUG_INFO&) override;
		ExceptionType OnException(HANDLE, HANDLE, const EXCEPTION_DEBUG_INFO&) override;
		void OnBeforeContinue(HANDLE) override;
		void OnAttachedProcessReady(HANDLE) override;
		void OnPrepareDetach(HANDLE) override;
		void OnDetachedProcess(HANDLE) override;
	};
}
