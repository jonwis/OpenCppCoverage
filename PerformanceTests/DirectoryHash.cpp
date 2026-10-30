#include <windows.h>
#include <bcrypt.h>
#include <shlwapi.h>
#include <wil/com.h>
#include <wil/resource.h>
#include <wil/result.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cwchar>
#include <exception>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <vector>

namespace
{
	using Digest = std::array<unsigned char, 32>;

	uint64_t Ticks(FILETIME time)
	{
		return (uint64_t{time.dwHighDateTime} << 32) | time.dwLowDateTime;
	}

	struct Clock
	{
		LARGE_INTEGER counter{};
		uint64_t cpu;
		uint64_t creation;

		Clock()
		{
			THROW_LAST_ERROR_IF(!QueryPerformanceCounter(&counter));
			FILETIME created{}, exited{}, kernel{}, user{};
			THROW_LAST_ERROR_IF(!GetProcessTimes(
			    GetCurrentProcess(), &created, &exited, &kernel, &user));
			cpu = Ticks(kernel) + Ticks(user);
			creation = Ticks(created);
		}
	};

	struct Pass
	{
		uint64_t files = 0;
		uint64_t bytes = 0;
		size_t skippedReparsePoints = 0;
		Digest digest{};
		double seconds = 0;
		double cpuSeconds = 0;
	};

	Pass HashDirectory(const std::filesystem::path& directory)
	{
		Pass result;
		std::vector<std::filesystem::path> files;
		for (auto it = std::filesystem::recursive_directory_iterator{directory};
		     it != std::filesystem::recursive_directory_iterator{}; ++it)
		{
			const auto attributes = GetFileAttributesW(it->path().c_str());
			THROW_LAST_ERROR_IF(attributes == INVALID_FILE_ATTRIBUTES);
			if (attributes & FILE_ATTRIBUTE_REPARSE_POINT)
			{
				it.disable_recursion_pending();
				++result.skippedReparsePoints;
			}
			else if (it->is_regular_file())
				files.push_back(it->path());
		}
		std::sort(files.begin(), files.end(), [](const auto& lhs, const auto& rhs)
		{
			return lhs.native() < rhs.native();
		});
		wil::unique_bcrypt_algorithm algorithm;
		THROW_IF_NTSTATUS_FAILED(BCryptOpenAlgorithmProvider(
		    algorithm.put(), BCRYPT_SHA256_ALGORITHM, nullptr, 0));
		wil::unique_bcrypt_hash aggregate;
		THROW_IF_NTSTATUS_FAILED(BCryptCreateHash(
		    algorithm.get(), aggregate.put(), nullptr, 0, nullptr, 0, 0));
		std::array<unsigned char, 64 * 1024> buffer{};
		for (const auto& file : files)
		{
			wil::com_ptr<IStream> stream;
			THROW_IF_FAILED(SHCreateStreamOnFileEx(file.c_str(),
			    STGM_READ | STGM_SHARE_DENY_WRITE, 0, FALSE, nullptr, stream.put()));
			wil::unique_bcrypt_hash hash;
			THROW_IF_NTSTATUS_FAILED(BCryptCreateHash(
			    algorithm.get(), hash.put(), nullptr, 0, nullptr, 0, 0));
			for (;;)
			{
				ULONG read = 0;
				THROW_IF_FAILED(stream->Read(buffer.data(), static_cast<ULONG>(buffer.size()), &read));
				if (!read)
					break;
				THROW_IF_NTSTATUS_FAILED(BCryptHashData(hash.get(), buffer.data(), read, 0));
				result.bytes += read;
			}
			Digest digest{};
			THROW_IF_NTSTATUS_FAILED(BCryptFinishHash(
			    hash.get(), digest.data(), static_cast<ULONG>(digest.size()), 0));
			THROW_IF_NTSTATUS_FAILED(BCryptHashData(
			    aggregate.get(), digest.data(), static_cast<ULONG>(digest.size()), 0));
			++result.files;
		}
		THROW_IF_NTSTATUS_FAILED(BCryptFinishHash(
		    aggregate.get(), result.digest.data(), static_cast<ULONG>(result.digest.size()), 0));
		return result;
	}
}

int wmain(int argc, wchar_t** argv)
{
	if (argc != 3)
	{
		std::cerr << "Usage: DirectoryHash.exe <directory> <passes: 1..128>\n";
		return 2;
	}
	try
	{
		wchar_t* end = nullptr;
		const auto count = std::wcstoul(argv[2], &end, 10);
		const bool numeric = std::all_of(argv[2], end, [](wchar_t c) { return c >= L'0' && c <= L'9'; });
		THROW_HR_IF_MSG(E_INVALIDARG, !*argv[2] || *end || !numeric || !count || count > 128,
		               "Pass count must be between 1 and 128");
		const auto directory = std::filesystem::absolute(argv[1]);
		const auto attributes = GetFileAttributesW(directory.c_str());
		THROW_LAST_ERROR_IF(attributes == INVALID_FILE_ATTRIBUTES);
		THROW_HR_IF_MSG(E_INVALIDARG, !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
		               (attributes & FILE_ATTRIBUTE_REPARSE_POINT),
		               "Input must be a directory without a reparse point");
		LARGE_INTEGER frequency{};
		THROW_LAST_ERROR_IF(!QueryPerformanceFrequency(&frequency));
		std::vector<Pass> passes;
		passes.reserve(count);
		const Clock start;
		FILETIME now{};
		GetSystemTimePreciseAsFileTime(&now);
		const auto startupSeconds = static_cast<double>(Ticks(now) - start.creation) / 10000000;
		for (unsigned long i = 0; i < count; ++i)
		{
			const Clock before;
			auto pass = HashDirectory(directory);
			const Clock after;
			pass.seconds = static_cast<double>(after.counter.QuadPart - before.counter.QuadPart) /
			               frequency.QuadPart;
			pass.cpuSeconds = static_cast<double>(after.cpu - before.cpu) / 10000000;
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
			    !passes.empty() && (pass.files != passes.front().files ||
			        pass.bytes != passes.front().bytes || pass.digest != passes.front().digest ||
			        pass.skippedReparsePoints != passes.front().skippedReparsePoints),
			    "Directory contents changed between passes");
			passes.push_back(pass);
		}
		const Clock finish;
		std::cout << std::fixed << std::setprecision(9)
		          << "{\"startupSeconds\":" << startupSeconds
		          << ",\"workSeconds\":"
		          << static_cast<double>(finish.counter.QuadPart - start.counter.QuadPart) / frequency.QuadPart
		          << ",\"workCpuSeconds\":" << static_cast<double>(finish.cpu - start.cpu) / 10000000
		          << ",\"passes\":[";
		for (size_t i = 0; i < passes.size(); ++i)
		{
			const auto& pass = passes[i];
			if (i)
				std::cout << ',';
			std::cout << "{\"pass\":" << i + 1 << ",\"files\":" << pass.files
			          << ",\"bytes\":" << pass.bytes << ",\"skippedReparsePoints\":" << pass.skippedReparsePoints
			          << ",\"seconds\":" << pass.seconds << ",\"cpuSeconds\":" << pass.cpuSeconds
			          << ",\"digest\":\"";
			for (const auto byte : pass.digest)
				std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(byte);
			std::cout << std::dec << "\"}";
		}
		std::cout << "]}\n";
		return 0;
	}
	catch (const std::exception& error)
	{
		std::cerr << error.what() << '\n';
		return 1;
	}
}
