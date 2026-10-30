// OpenCppCoverage is an open source code coverage for C++.
// Copyright (C) 2016 OpenCppCoverage
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
#include <tchar.h>
#include <iostream>
#include "Tools/Tool.hpp"

//-----------------------------------------------------------------------------
int _tmain(int argc, _TCHAR* argv[])
{
	if (argc == 3 && std::wstring{argv[1]} == L"--process-test-echo")
	{
		std::cout << Tools::ToUtf8String(argv[2]);
		return 0;
	}
	if (argc == 2 && std::wstring{argv[1]} == L"--process-test-output")
	{
		std::cout << std::string(65536, 'x');
		std::cerr << "stderr";
		return 37;
	}
	if (argc == 2 && std::wstring{argv[1]} == L"--process-test-exit")
		return 37;
	::testing::InitGoogleMock(&argc, argv);
	return RUN_ALL_TESTS();
}