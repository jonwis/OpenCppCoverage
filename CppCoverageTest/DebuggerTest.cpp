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

#include "CppCoverage/StartInfo.hpp"
#include "CppCoverage/Debugger.hpp"
#include "TestCoverageConsole/TestCoverageConsole.hpp"

#include "DebugEventsMock.hpp"

namespace cov = CppCoverage;

namespace CppCoverageTest
{
	TEST(DebuggerAttachTest, ApplicationExceptionsDoNotBlockPendingBootstrap)
	{
		for (DWORD code : {DWORD{0xe06d7363}, DWORD{0xe0424343}, DWORD{EXCEPTION_ACCESS_VIOLATION}})
			for (DWORD chance : {DWORD{0}, DWORD{1}})
			{
				EXCEPTION_DEBUG_INFO event{};
				event.dwFirstChance = chance;
				event.ExceptionRecord.ExceptionCode = code;
				event.ExceptionRecord.ExceptionAddress = reinterpret_cast<void*>(0x1000);
				for (DWORD thread : {DWORD{7}, DWORD{8}})
					EXPECT_EQ(DBG_EXCEPTION_NOT_HANDLED,
					    cov::Debugger::AttachExceptionDisposition(event, thread, false, 8, 0x2000));
			}
		EXCEPTION_DEBUG_INFO bootstrap{};
		bootstrap.dwFirstChance = 1;
		bootstrap.ExceptionRecord.ExceptionCode = EXCEPTION_BREAKPOINT;
		bootstrap.ExceptionRecord.ExceptionAddress = reinterpret_cast<void*>(0x2000);
		EXPECT_EQ(DBG_CONTINUE,
		    cov::Debugger::AttachExceptionDisposition(bootstrap, 8, false, 8, 0x2000));
	}

	TEST(DebuggerAttachTest, HeldOriginalThreadBreakpointsRemainApplicationOwned)
	{
		for (DWORD code : {DWORD{EXCEPTION_BREAKPOINT}, DWORD{0x4000001f}})
		{
			EXCEPTION_DEBUG_INFO event{};
			event.dwFirstChance = 1;
			event.ExceptionRecord.ExceptionCode = code;
			event.ExceptionRecord.ExceptionAddress = reinterpret_cast<void*>(0x2000);
			EXPECT_EQ(DBG_EXCEPTION_NOT_HANDLED,
			    cov::Debugger::AttachExceptionDisposition(event, 7, true, 8, 0x2000));
			EXPECT_THROW(cov::Debugger::AttachExceptionDisposition(event, 7, false, 8, 0x2000),
			    std::exception);
			EXPECT_EQ(DBG_CONTINUE,
			    cov::Debugger::AttachExceptionDisposition(event, 8, false, 8, 0x2000));
			event.dwFirstChance = 0;
			EXPECT_EQ(DBG_EXCEPTION_NOT_HANDLED,
			    cov::Debugger::AttachExceptionDisposition(event, 7, true, 8, 0x2000));
			EXPECT_THROW(cov::Debugger::AttachExceptionDisposition(event, 8, false, 8, 0x2000),
			    std::exception);
		}
	}

	//-----------------------------------------------------------------------------
	TEST(DebugerTest, Debug)
	{		
		cov::StartInfo startInfo{ TestCoverageConsole::GetOutputBinaryPath() };
		cov::Debugger debugger{ false, false, false };
		DebugEventsHandlerMock debugEventsHandlerMock;

		EXPECT_CALL(debugEventsHandlerMock, OnCreateProcess(testing::_));
		EXPECT_CALL(debugEventsHandlerMock, OnExitProcess(testing::_, testing::_, testing::_));
		EXPECT_CALL(debugEventsHandlerMock, OnLoadDll(testing::_, testing::_, testing::_)).Times(testing::AnyNumber());
		EXPECT_CALL(debugEventsHandlerMock, OnUnloadDll(testing::_, testing::_, testing::_)).Times(testing::AnyNumber());
		EXPECT_CALL(debugEventsHandlerMock, OnException(testing::_, testing::_, testing::_))
			.WillRepeatedly(testing::Return(cov::IDebugEventsHandler::ExceptionType::NotHandled));

		debugger.Debug(startInfo, debugEventsHandlerMock);
		ASSERT_EQ(0, debugger.GetRunningProcesses());
		ASSERT_EQ(0, debugger.GetRunningThreads());
	}	
}