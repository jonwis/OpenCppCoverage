#include "stdafx.h"
#include "RvaCoverage.hpp"

#include <Windows.h>
#include <wil/result.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <limits>
#include <stdexcept>

namespace CppCoverage
{
	namespace
	{
		constexpr std::array<uint8_t, 8> Magic{{'O', 'C', 'C', 'R', 'V', 'A', 'C', 0}};
		constexpr uint32_t Version = 1;
		constexpr size_t MaxFileSize = 256 * 1024 * 1024;
		constexpr uint32_t MaxStringLength = 32767;
		constexpr uint32_t MaxModules = 65536;
		constexpr uint32_t MaxBlocks = 16 * 1024 * 1024;
		constexpr size_t BlockRecordSize = 11;
		constexpr size_t MinModuleSize = 76;

		void ValidateString(const std::wstring& text, bool path)
		{
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), text.size() > MaxStringLength || (path && text.empty()), "invalid string length");
			const bool extendedPath = path && text.compare(0, 4, L"\\\\?\\") == 0;
			const size_t drive = extendedPath ? 4 : 0;
			for (size_t i = 0; i < text.size(); ++i)
			{
				const auto c = static_cast<uint32_t>(text[i]);
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), c == 0 || c > 0xffff, "invalid UTF-16 string");
				if (c >= 0xd800 && c <= 0xdbff)
				{
					THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), ++i == text.size() ||
					    text[i] < 0xdc00 || text[i] > 0xdfff, "invalid UTF-16 surrogate pair");
				}
				else THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), c >= 0xdc00 && c <= 0xdfff, "invalid UTF-16 surrogate pair");
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), path && (c < 32 || c == '<' || c == '>' ||
				             c == '"' || c == '|' || (c == '?' && !(extendedPath && i == 2)) ||
				             c == '*' ||
				             (c == ':' && (i != drive + 1 ||
				              !((text[drive] >= L'A' && text[drive] <= L'Z') ||
				                (text[drive] >= L'a' && text[drive] <= L'z'))))), "invalid module path");
			}
			if (path)
			{
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), extendedPath &&
				    !(text.size() > 7 && text[5] == L':' && text[6] == L'\\') &&
				    !(text.size() > 8 && text.compare(4, 4, L"UNC\\") == 0), "invalid extended module path");
				const auto filename = std::filesystem::path(text).filename();
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), filename.empty() || filename == L"." || filename == L"..", "module path has no filename");
			}
		}

		void ValidateModule(const RvaModule& module)
		{
			ValidateString(module.path.wstring(), true);
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), (module.identity.machine != 0x8664 &&
			     module.identity.machine != 0xaa64 &&
			     module.identity.machine != 0xa641) ||
			    module.identity.sizeOfImage == 0 ||
			    module.blocks.size() > MaxBlocks, "invalid module identity or block count");
			uint64_t end = 0;
			for (const auto& entry : module.blocks)
			{
				const auto& block = entry.block;
				const auto instructionSet = static_cast<uint16_t>(block.instructionSet);
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), (instructionSet != 0x8664 && instructionSet != 0xaa64) ||
				    (module.identity.machine == 0xaa64 && instructionSet != 0xaa64) ||
				    block.size == 0 || block.rva < end ||
				    uint64_t{block.rva} + block.size > module.identity.sizeOfImage ||
				    (instructionSet == 0xaa64 &&
				     ((block.rva & 3) != 0 || (block.size & 3) != 0)), "invalid or overlapping block");
				end = uint64_t{block.rva} + block.size;
			}
		}

		class Writer
		{
		  public:
			void Integer(uint32_t value, size_t width)
			{
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), bytes.size() > MaxFileSize - width, "file too large");
				for (size_t i = 0; i < width; ++i)
					bytes.push_back(static_cast<uint8_t>(value >> (8 * i)));
			}

			void String(const std::wstring& value)
			{
				Integer(static_cast<uint32_t>(value.size()), 4);
				for (const auto c : value)
					Integer(static_cast<uint16_t>(c), 2);
			}

			std::vector<uint8_t> bytes;
		};

		class Reader
		{
		  public:
			explicit Reader(const std::vector<uint8_t>& bytes) : bytes_{bytes} {}

			uint32_t Integer(size_t width)
			{
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), width > Remaining(), "truncated file");
				uint32_t value = 0;
				for (size_t i = 0; i < width; ++i)
					value |= uint32_t{bytes_[offset_++]} << (8 * i);
				return value;
			}

			std::wstring String(bool path)
			{
				const auto length = Integer(4);
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), length > MaxStringLength || length > Remaining() / 2, "invalid string length");
				std::wstring text;
				text.reserve(length);
				for (uint32_t i = 0; i < length; ++i)
					text.push_back(static_cast<wchar_t>(Integer(2)));
				ValidateString(text, path);
				return text;
			}

			size_t Remaining() const { return bytes_.size() - offset_; }

		  private:
			const std::vector<uint8_t>& bytes_;
			size_t offset_ = 0;
		};
	}

	void WriteRvaCoverage(const RvaCoverage& coverage,
	                      const std::filesystem::path& path)
	{
		ValidateString(coverage.name, false);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), coverage.modules.size() > MaxModules, "too many modules");
		Writer writer;
		writer.bytes.insert(writer.bytes.end(), Magic.begin(), Magic.end());
		writer.Integer(Version, 4);
		writer.String(coverage.name);
		writer.Integer(static_cast<uint32_t>(coverage.exitCode), 4);
		writer.Integer(static_cast<uint32_t>(coverage.modules.size()), 4);
		size_t totalBlocks = 0;
		for (const auto& module : coverage.modules)
		{
			ValidateModule(module);
			totalBlocks += module.blocks.size();
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), totalBlocks > MaxBlocks, "too many blocks");
			writer.String(module.path.wstring());
			writer.Integer(module.identity.machine, 2);
			writer.Integer(module.identity.timeDateStamp, 4);
			writer.Integer(module.identity.sizeOfImage, 4);
			writer.Integer(module.identity.checksum, 4);
			for (const auto byte : module.identity.pdbGuid)
				writer.Integer(byte, 1);
			writer.Integer(module.identity.pdbAge, 4);
			for (const auto byte : module.identity.imageHash)
				writer.Integer(byte, 1);
			writer.Integer(static_cast<uint32_t>(module.blocks.size()), 4);
			for (const auto& block : module.blocks)
			{
				writer.Integer(block.block.rva, 4);
				writer.Integer(block.block.size, 4);
				writer.Integer(static_cast<uint16_t>(block.block.instructionSet), 2);
				writer.Integer(block.executed ? 1 : 0, 1);
			}
		}
		std::ofstream stream(path, std::ios::binary | std::ios::trunc);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !stream ||
		    !stream.write(reinterpret_cast<const char*>(writer.bytes.data()),
		                  static_cast<std::streamsize>(writer.bytes.size())), "Cannot write RVA coverage file");
		stream.close();
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !stream, "Cannot finish RVA coverage file");
	}

	RvaCoverage ReadRvaCoverage(const std::filesystem::path& path)
	{
		std::ifstream stream(path, std::ios::binary | std::ios::ate);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !stream, "Cannot open RVA coverage file");
		const auto size = stream.tellg();
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), size < 0 || size > static_cast<std::streamoff>(MaxFileSize), "invalid file size");
		std::vector<uint8_t> bytes(static_cast<size_t>(size));
		stream.seekg(0);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !bytes.empty() &&
		    !stream.read(reinterpret_cast<char*>(bytes.data()),
		                 static_cast<std::streamsize>(bytes.size())), "truncated file");
		Reader reader(bytes);
		for (const auto byte : Magic)
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), reader.Integer(1) != byte, "incorrect format signature");
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), reader.Integer(4) != Version, "unsupported version");
		RvaCoverage coverage;
		coverage.name = reader.String(false);
		const auto exitCode = reader.Integer(4);
		int32_t signedExitCode;
		std::memcpy(&signedExitCode, &exitCode, sizeof(exitCode));
		coverage.exitCode = signedExitCode;
		const auto moduleCount = reader.Integer(4);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), moduleCount > MaxModules || moduleCount > reader.Remaining() / MinModuleSize, "invalid module count");
		coverage.modules.reserve(moduleCount);
		size_t totalBlocks = 0;
		for (uint32_t i = 0; i < moduleCount; ++i)
		{
			RvaModule module;
			module.path = reader.String(true);
			module.identity.machine = static_cast<uint16_t>(reader.Integer(2));
			module.identity.timeDateStamp = reader.Integer(4);
			module.identity.sizeOfImage = reader.Integer(4);
			module.identity.checksum = reader.Integer(4);
			for (auto& byte : module.identity.pdbGuid)
				byte = static_cast<uint8_t>(reader.Integer(1));
			module.identity.pdbAge = reader.Integer(4);
			for (auto& byte : module.identity.imageHash)
				byte = static_cast<uint8_t>(reader.Integer(1));
			const auto blockCount = reader.Integer(4);
			totalBlocks += blockCount;
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), totalBlocks > MaxBlocks ||
			    blockCount > reader.Remaining() / BlockRecordSize, "invalid block count");
			module.blocks.reserve(blockCount);
			for (uint32_t j = 0; j < blockCount; ++j)
			{
				RvaBlock block;
				block.block.rva = reader.Integer(4);
				block.block.size = reader.Integer(4);
				block.block.instructionSet =
				    static_cast<InstructionSet>(reader.Integer(2));
				const auto executed = reader.Integer(1);
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), executed > 1, "invalid executed state");
				block.executed = executed != 0;
				module.blocks.push_back(block);
			}
			ValidateModule(module);
			coverage.modules.push_back(std::move(module));
		}
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), reader.Remaining() != 0, "trailing bytes");
		return coverage;
	}

	bool IsRvaCoverage(const std::filesystem::path& path)
	{
		std::ifstream stream(path, std::ios::binary);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !stream, "Cannot open coverage file");
		std::array<uint8_t, Magic.size()> signature{};
		return stream.read(reinterpret_cast<char*>(signature.data()),
		                   static_cast<std::streamsize>(signature.size())) &&
		       signature == Magic;
	}
}
