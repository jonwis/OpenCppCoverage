#include "stdafx.h"

#include "Tools/Tool.hpp"
#include <wil/result.h>

namespace ToolsTests
{
	TEST(Process, PreservesEmptyUnicodeAndQuotedArguments)
	{
		const auto program = Tools::GetExecutableFolder() / L"ToolsTest.exe";
		for (const auto* argument : {
			L"", L"two words", L"a\\\"b", L"C:\\with space\\", L"\u03bb"})
		{
			std::string output;
			ASSERT_EQ(0, Tools::RunProcess(program, {L"--process-test-echo", argument}, &output));
			EXPECT_EQ(Tools::ToUtf8String(argument), output);
		}
	}

	TEST(Process, DrainsOutputLargerThanPipeBeforeWaiting)
	{
		const auto program = Tools::GetExecutableFolder() / L"ToolsTest.exe";
		std::string output;
		EXPECT_EQ(37, Tools::RunProcess(program, {L"--process-test-output"}, &output, true));
		EXPECT_EQ(std::string(65536, 'x') + "stderr", output);
		EXPECT_EQ(37, Tools::RunProcess(program, {L"--process-test-output"}, &output));
		EXPECT_EQ(std::string(65536, 'x'), output);
	}

	TEST(Process, ReturnsExitCodeWithoutCapturingOutput)
	{
		EXPECT_EQ(37, Tools::RunProcess(
			Tools::GetExecutableFolder() / L"ToolsTest.exe", {L"--process-test-exit"}));
	}

	TEST(Process, ReportsMissingProgram)
	{
		EXPECT_THROW(Tools::RunProcess(
			Tools::GetExecutableFolder() / L"missing-process.exe", {}), wil::ResultException);
	}
}
