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
#include "Tool.hpp"

#include <boost/optional/optional.hpp>
#include <filesystem>
#include <system_error>
#include <array>
#include <wil/resource.h>
#include <wil/result.h>

#include "Log.hpp"
#include "ToolsException.hpp"

namespace fs = std::filesystem;

namespace Tools
{
	namespace
	{
		void AppendArgument(std::wstring& commandLine, const std::wstring& argument)
		{
			THROW_HR_IF(E_INVALIDARG, argument.find(L'\0') != std::wstring::npos);
			commandLine += L"\"";
			size_t slashes = 0;
			for (const auto character : argument)
			{
				if (character == L'\\')
				{
					++slashes;
					continue;
				}
				commandLine.append(character == L'"' ? 2 * slashes + 1 : slashes, L'\\');
				commandLine += character;
				slashes = 0;
			}
			commandLine.append(2 * slashes, L'\\');
			commandLine += L"\" ";
		}

		wil::unique_handle InheritStandardHandle(DWORD kind)
		{
			const auto source = GetStdHandle(kind);
			wil::unique_handle result;
			if (source && source != INVALID_HANDLE_VALUE)
				THROW_IF_WIN32_BOOL_FALSE(DuplicateHandle(
					GetCurrentProcess(), source, GetCurrentProcess(),
					result.put(), 0, TRUE, DUPLICATE_SAME_ACCESS));
			return result;
		}

		//-----------------------------------------------------------------------------
		fs::path GetExecutablePath()
		{
			const int PathBufferSize = 40 * 1000;
			std::vector<wchar_t> filename(PathBufferSize);

			if (!GetModuleFileName(nullptr, &filename[0], static_cast<int>(filename.size())))
				THROW("Cannot get current executable path.");

			return fs::path{ &filename[0] };
		}
		
		//-------------------------------------------------------------------------
		std::string ToString(unsigned int pageCode, const std::wstring& str)
		{
			if (str.empty())
				return{};

			auto size = WideCharToMultiByte(pageCode, 0, str.c_str(),
				static_cast<int>(str.size()), nullptr, 0, nullptr, nullptr);
			std::vector<char> buffer(size);

			if (!WideCharToMultiByte(pageCode, 0, str.c_str(), static_cast<int>(str.size()),
				&buffer[0], static_cast<int>(buffer.size()), nullptr, nullptr))
			{
				throw std::runtime_error("Error in WideCharToMultiByte.");
			}

			return{ buffer.begin(), buffer.end() };
		}

		//-------------------------------------------------------------------------
		std::wstring ToWString(unsigned int pageCode, const std::string& str)
		{
			if (str.empty())
				return{};

			auto size = MultiByteToWideChar(pageCode, 0,
				str.c_str(), static_cast<int>(str.size()), nullptr, 0);
			std::vector<wchar_t> buffer(size);

			if (!MultiByteToWideChar(pageCode, 0, str.c_str(), static_cast<int>(str.size()),
				&buffer[0], static_cast<int>(buffer.size())))
			{
				throw std::runtime_error("Error in MultiByteToWideChar for " + str);
			}

			return{ buffer.begin(), buffer.end() };
		}
	}

	//-----------------------------------------------------------------------------
	fs::path GetExecutableFolder()
	{
		fs::path executablePath = GetExecutablePath();

		return executablePath.parent_path();
	}

	//-------------------------------------------------------------------------
	std::string ToLocalString(const std::wstring& str)
	{
		return ToString(CP_ACP, str);
	}

	//-------------------------------------------------------------------------
	std::string ToUtf8String(const std::wstring& str)
	{
		return ToString(CP_UTF8, str);
	}

	//-------------------------------------------------------------------------
	std::wstring LocalToWString(const std::string& str)
	{
		return ToWString(CP_ACP, str);
	}

	//-------------------------------------------------------------------------
	std::wstring Utf8ToWString(const std::string& str)
	{
		return ToWString(CP_UTF8, str);
	}

	//-------------------------------------------------------------------------
	boost::optional<std::wstring> Try(std::function<void()> action)
	{
		try
		{
			action();
		}
		catch (const std::exception& e)
		{
			return Tools::LocalToWString(e.what());
		}
		catch (...)
		{
			return std::wstring{L"Unkown exception"};
		}

		return boost::none;
	}

	//-------------------------------------------------------------------------
	void ShowOutputMessage(
		const std::wstring& message, 
		const std::filesystem::path& path)
	{
		LOG_INFO << GetSeparatorLine();
		LOG_INFO << message << path.wstring();
		LOG_INFO << GetSeparatorLine();
	}

	//-------------------------------------------------------------------------
	std::wstring GetSeparatorLine()
	{
		return L"----------------------------------------------------";
	}
	
	//---------------------------------------------------------------------
	void CreateParentFolderIfNeeded(const std::filesystem::path& path)
	{
		if (path.has_parent_path())
		{
			auto parentPath = path.parent_path();
			std::error_code er;

			std::filesystem::create_directories(parentPath, er);
			if (er)
			{
				THROW(L"Error when creating folder " << parentPath.wstring()
					<< L" Error code:" << er.value());
			}
		}
	}

	//---------------------------------------------------------------------
	bool FileExists(const std::filesystem::path& path)
	{
		std::error_code ignoredErrorCode;

		// Error can happen when the drive is not ready (DVD for example).
		return std::filesystem::exists(path, ignoredErrorCode);
	}

	int RunProcess(
		const std::filesystem::path& program,
		const std::vector<std::wstring>& arguments,
		std::string* output,
		bool captureStandardError)
	{
		std::wstring commandLine;
		AppendArgument(commandLine, program.wstring());
		for (const auto& argument : arguments)
			AppendArgument(commandLine, argument);
		THROW_HR_IF(E_INVALIDARG, commandLine.size() >= 32767);

		STARTUPINFOEXW startup{};
		startup.StartupInfo.cb = output ? sizeof(startup) : sizeof(startup.StartupInfo);
		wil::unique_handle reader, writer, input, error;
		wil::unique_hlocal attributes;
		std::array<HANDLE, 3> handles{};
		bool initialized = false;
		const auto cleanup = wil::scope_exit([&] {
			if (initialized)
				DeleteProcThreadAttributeList(startup.lpAttributeList);
		});
		if (output)
		{
			output->clear();
			SECURITY_ATTRIBUTES security{sizeof(security), nullptr, TRUE};
			THROW_IF_WIN32_BOOL_FALSE(CreatePipe(reader.put(), writer.put(), &security, 0));
			THROW_IF_WIN32_BOOL_FALSE(SetHandleInformation(reader.get(), HANDLE_FLAG_INHERIT, 0));
			input = InheritStandardHandle(STD_INPUT_HANDLE);
			if (!captureStandardError)
				error = InheritStandardHandle(STD_ERROR_HANDLE);
			handles[0] = writer.get();
			size_t count = 1;
			if (input)
				handles[count++] = input.get();
			if (error)
				handles[count++] = error.get();
			SIZE_T bytes = 0;
			InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
			THROW_LAST_ERROR_IF(bytes == 0);
			attributes.reset(THROW_IF_NULL_ALLOC(LocalAlloc(LMEM_FIXED, bytes)));
			startup.lpAttributeList = static_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributes.get());
			THROW_IF_WIN32_BOOL_FALSE(InitializeProcThreadAttributeList(
				startup.lpAttributeList, 1, 0, &bytes));
			initialized = true;
			THROW_IF_WIN32_BOOL_FALSE(UpdateProcThreadAttribute(
				startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
				handles.data(), count * sizeof(HANDLE), nullptr, nullptr));
			startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
			startup.StartupInfo.hStdInput = input.get();
			startup.StartupInfo.hStdOutput = writer.get();
			startup.StartupInfo.hStdError = captureStandardError ? writer.get() : error.get();
		}
		wil::unique_process_information process;
		THROW_IF_WIN32_BOOL_FALSE(CreateProcessW(
			program.c_str(), commandLine.data(), nullptr, nullptr, output != nullptr,
			output ? EXTENDED_STARTUPINFO_PRESENT : 0, nullptr, nullptr,
			&startup.StartupInfo, &process));
		writer.reset();
		input.reset();
		error.reset();
		if (output)
		{
			std::array<char, 4096> buffer;
			for (;;)
			{
				DWORD read = 0;
				if (!ReadFile(reader.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr))
				{
					const auto code = GetLastError();
					THROW_WIN32_IF(code, code != ERROR_BROKEN_PIPE);
					break;
				}
				if (!read)
					break;
				output->append(buffer.data(), read);
			}
		}
		const auto wait = WaitForSingleObject(process.hProcess, INFINITE);
		THROW_LAST_ERROR_IF(wait == WAIT_FAILED);
		THROW_HR_IF(E_UNEXPECTED, wait != WAIT_OBJECT_0);
		DWORD code = 0;
		THROW_IF_WIN32_BOOL_FALSE(GetExitCodeProcess(process.hProcess, &code));
		return static_cast<int>(code);
	}
}