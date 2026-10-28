#include "PeImage.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <utility>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>
#include <wil/resource.h>
#include <wil/result.h>

namespace CppCoverage
{
	namespace
	{
		constexpr size_t MaxFileSize = 512u * 1024u * 1024u;
		constexpr size_t MaxMetadataEntries = 4u * 1024u * 1024u;
		constexpr uint32_t Execute = 0x20000000;
		constexpr uint16_t Amd64 = 0x8664;
		constexpr uint16_t Arm64 = 0xaa64;
		constexpr uint16_t Arm64EC = 0xa641;
		constexpr uint16_t Arm64X = 0xa64e;

		bool Fits(size_t offset, size_t size, size_t limit)
		{
			return offset <= limit && size <= limit - offset;
		}

		uint64_t Read(const std::vector<uint8_t>& bytes, size_t offset, size_t size)
		{
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(Fits(offset, size, bytes.size())), "Truncated PE field");
			uint64_t value = 0;
			for (size_t i = 0; i < size; ++i)
				value |= static_cast<uint64_t>(bytes[offset + i]) << (8 * i);
			return value;
		}

		uint32_t Add(uint32_t rva, size_t offset)
		{
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(offset <= (std::numeric_limits<uint32_t>::max)() - rva), "PE RVA overflow");
			return rva + static_cast<uint32_t>(offset);
		}

		std::vector<uint8_t> ReadFile(const std::filesystem::path& path)
		{
			std::ifstream stream(path, std::ios::binary | std::ios::ate);
			THROW_HR_IF_MSG(E_FAIL, !stream, "Cannot open PE image: %ls", path.c_str());
			const auto length = stream.tellg();
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(length >= 0 && static_cast<uint64_t>(length) <= MaxFileSize), "PE image exceeds the 512 MiB input limit");
			std::vector<uint8_t> bytes(static_cast<size_t>(length));
			stream.seekg(0);
			if (!bytes.empty())
			{
				stream.read(reinterpret_cast<char*>(bytes.data()),
					static_cast<std::streamsize>(bytes.size()));
				THROW_HR_IF_MSG(E_FAIL, !stream, "Cannot read complete PE image: %ls", path.c_str());
			}
			return bytes;
		}

		std::array<uint8_t, 32> HashImage(const std::vector<uint8_t>& bytes)
		{
			wil::unique_bcrypt_algorithm algorithm;
			THROW_IF_NTSTATUS_FAILED_MSG(BCryptOpenAlgorithmProvider(
				algorithm.put(), BCRYPT_SHA256_ALGORITHM, nullptr, 0),
				"Cannot initialize SHA-256 provider");
			wil::unique_bcrypt_hash hash;
			THROW_IF_NTSTATUS_FAILED_MSG(
				BCryptCreateHash(algorithm.get(), hash.put(), nullptr, 0, nullptr, 0, 0),
				"Cannot create SHA-256 hash");
			std::array<uint8_t, 32> result{};
			THROW_IF_NTSTATUS_FAILED(BCryptHashData(
				hash.get(), const_cast<PUCHAR>(bytes.data()),
				static_cast<ULONG>(bytes.size()), 0));
			THROW_IF_NTSTATUS_FAILED(BCryptFinishHash(
				hash.get(), result.data(), static_cast<ULONG>(result.size()), 0));
			return result;
		}
	}

	PeImage::PeImage(const std::filesystem::path& path) : PeImage(ReadFile(path))
	{
	}

	PeImage::PeImage(std::vector<uint8_t> bytes) : bytes_(std::move(bytes))
	{
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(bytes_.size() <= MaxFileSize), "PE image exceeds the 512 MiB input limit");
		Parse();
		identity_.imageHash = HashImage(bytes_);
	}

	const PeIdentity& PeImage::Identity() const
	{
		return identity_;
	}

	const std::vector<uint32_t>& PeImage::Roots() const
	{
		return roots_;
	}

	const std::vector<BasicBlock>& PeImage::CodeRanges() const
	{
		return codeRanges_;
	}

	void PeImage::Charge(size_t count)
	{
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(count <= MaxMetadataEntries - metadataEntries_), "PE metadata exceeds the discovery resource limit");
		metadataEntries_ += count;
	}

	size_t PeImage::Available(uint32_t rva) const
	{
		if (rva < sizeOfHeaders_)
			return sizeOfHeaders_ - rva;
		auto it = std::upper_bound(sections_.begin(), sections_.end(), rva,
			[](uint32_t value, const Section& section) { return value < section.rva; });
		if (it == sections_.begin())
			return 0;
		--it;
		const auto delta = rva - it->rva;
		return delta < it->rawSize ? it->rawSize - delta : 0;
	}

	size_t PeImage::RawOffset(uint32_t rva, size_t size) const
	{
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(size <= Available(rva) && size != 0), "PE RVA is not backed by file bytes");
		if (rva < sizeOfHeaders_)
			return rva;
		auto it = std::upper_bound(sections_.begin(), sections_.end(), rva,
			[](uint32_t value, const Section& section) { return value < section.rva; });
		--it;
		return static_cast<size_t>(it->rawOffset) + rva - it->rva;
	}

	uint32_t PeImage::Rva32(uint32_t rva, size_t offset) const
	{
		return static_cast<uint32_t>(Read(bytes_, RawOffset(Add(rva, offset), 4), 4));
	}

	uint64_t PeImage::Rva64(uint32_t rva, size_t offset) const
	{
		return Read(bytes_, RawOffset(Add(rva, offset), 8), 8);
	}

	bool PeImage::VaToRva(uint64_t va, uint32_t& rva) const
	{
		if (va < imageBase_ || va - imageBase_ >= identity_.sizeOfImage)
			return false;
		rva = static_cast<uint32_t>(va - imageBase_);
		return true;
	}

	bool PeImage::IsImportSlot(uint32_t rva) const
	{
		auto it = std::upper_bound(imports_.begin(), imports_.end(), rva,
			[](uint32_t value, const ImportSlot& slot) { return value < slot.rva; });
		return it != imports_.begin() && rva - (--it)->rva < 8;
	}

	bool PeImage::ImportTarget(uint32_t slotRva, uint32_t& targetRva) const
	{
		const auto it = std::lower_bound(imports_.begin(), imports_.end(), slotRva,
			[](const ImportSlot& slot, uint32_t value) { return slot.rva < value; });
		if (it == imports_.end() || it->rva != slotRva || !it->target ||
			!GetCode(it->target).data)
			return false;
		targetRva = it->target;
		return true;
	}

	bool PeImage::MatchesMappedCode(uint32_t rva, const uint8_t* bytes, size_t size,
		uint64_t mappedBase) const
	{
		const auto code = GetCode(rva);
		if (!bytes || !size || !code.data || size > code.size ||
			mappedBase > (std::numeric_limits<uint64_t>::max)() - identity_.sizeOfImage)
			return false;
		const auto end = static_cast<uint64_t>(rva) + size;
		auto relocation = std::lower_bound(relocations_.begin(), relocations_.end(), rva);
		if (relocation != relocations_.begin() && rva - *std::prev(relocation) < 8)
			--relocation;
		size_t position = 0;
		for (; relocation != relocations_.end() && *relocation < end; ++relocation)
		{
			const auto start = (std::max)(rva, *relocation);
			const auto first = static_cast<size_t>(start - rva);
			if (first > position &&
				std::memcmp(code.data + position, bytes + position, first - position))
				return false;
			const auto adjusted = Rva64(*relocation) + (mappedBase - imageBase_);
			const auto last = (std::min)(end, static_cast<uint64_t>(*relocation) + 8);
			for (auto current = static_cast<uint64_t>(start); current < last; ++current)
				if (bytes[current - rva] !=
					static_cast<uint8_t>(adjusted >> ((current - *relocation) * 8)))
					return false;
			position = static_cast<size_t>(last - rva);
		}
		return position == size ||
			std::memcmp(code.data + position, bytes + position, size - position) == 0;
	}

	PeCodeView PeImage::GetCode(uint32_t rva) const
	{
		auto range = std::upper_bound(codeRanges_.begin(), codeRanges_.end(), rva,
			[](uint32_t value, const BasicBlock& block) { return value < block.rva; });
		if (range == codeRanges_.begin())
			return {};
		--range;
		if (rva - range->rva >= range->size ||
			(range->instructionSet == InstructionSet::Arm64 && (rva & 3)))
			return {};
		size_t size = range->size - (rva - range->rva);
		if (importsReady_)
		{
			const auto slot = std::upper_bound(imports_.begin(), imports_.end(), rva,
				[](uint32_t value, const ImportSlot& entry) { return value < entry.rva; });
			if (slot != imports_.begin() && rva - std::prev(slot)->rva < 8)
				return {};
			if (slot != imports_.end())
				size = (std::min)(size, static_cast<size_t>(slot->rva - rva));
		}
		return {bytes_.data() + RawOffset(rva, size), size, range->instructionSet};
	}

	void PeImage::AddRoot(uint32_t rva)
	{
		if (rva && GetCode(rva).data)
		{
			Charge(1);
			roots_.push_back(rva);
		}
	}

	void PeImage::Parse()
	{
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(Read(bytes_, 0, 2) == 0x5a4d), "Invalid DOS signature");
		const auto pe = static_cast<size_t>(Read(bytes_, 0x3c, 4));
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(pe >= 64 && Read(bytes_, pe, 4) == 0x4550), "Invalid PE signature");
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(Fits(pe, 24, bytes_.size())), "Truncated COFF header");
		identity_.machine = static_cast<uint16_t>(Read(bytes_, pe + 4, 2));
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(identity_.machine == Amd64 || identity_.machine == Arm64 ||
			identity_.machine == Arm64EC || identity_.machine == Arm64X), "Unsupported PE machine");
		const auto sectionCount = static_cast<size_t>(Read(bytes_, pe + 6, 2));
		identity_.timeDateStamp = static_cast<uint32_t>(Read(bytes_, pe + 8, 4));
		const auto optionalSize = static_cast<size_t>(Read(bytes_, pe + 20, 2));
		const auto optional = pe + 24;
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(optionalSize >= 112 && Fits(optional, optionalSize, bytes_.size())), "Truncated PE64 optional header");
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(Read(bytes_, optional, 2) == 0x20b), "Only PE32+ images are supported");
		entryPoint_ = static_cast<uint32_t>(Read(bytes_, optional + 16, 4));
		imageBase_ = Read(bytes_, optional + 24, 8);
		identity_.sizeOfImage = static_cast<uint32_t>(Read(bytes_, optional + 56, 4));
		sizeOfHeaders_ = static_cast<uint32_t>(Read(bytes_, optional + 60, 4));
		identity_.checksum = static_cast<uint32_t>(Read(bytes_, optional + 64, 4));
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(sizeOfHeaders_ <= bytes_.size() && sizeOfHeaders_ <= identity_.sizeOfImage &&
			identity_.sizeOfImage != 0 &&
			imageBase_ <= (std::numeric_limits<uint64_t>::max)() - identity_.sizeOfImage), "Invalid PE image dimensions");
		const auto directoryCount = static_cast<size_t>(Read(bytes_, optional + 108, 4));
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(directoryCount <= (optionalSize - 112) / 8), "Truncated PE directory table");
		for (size_t i = 0; i < (std::min)(directoryCount, directories_.size()); ++i)
		{
			directories_[i] = {
				static_cast<uint32_t>(Read(bytes_, optional + 112 + i * 8, 4)),
				static_cast<uint32_t>(Read(bytes_, optional + 116 + i * 8, 4))};
			if (i != 4 && directories_[i].size)
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(directories_[i].rva != 0 &&
					directories_[i].rva < identity_.sizeOfImage &&
					directories_[i].size <= identity_.sizeOfImage - directories_[i].rva), "Invalid PE data directory extent");
		}
		const auto table = optional + optionalSize;
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(sectionCount != 0 && Fits(table, sectionCount * 40, sizeOfHeaders_)), "Invalid PE section table");
		for (size_t i = 0; i < sectionCount; ++i)
		{
			const auto offset = table + i * 40;
			Section section{
				static_cast<uint32_t>(Read(bytes_, offset + 12, 4)),
				static_cast<uint32_t>(Read(bytes_, offset + 8, 4)),
				static_cast<uint32_t>(Read(bytes_, offset + 20, 4)),
				static_cast<uint32_t>(Read(bytes_, offset + 16, 4)),
				static_cast<uint32_t>(Read(bytes_, offset + 36, 4))};
			const auto mapped = (std::max)(section.virtualSize, section.rawSize);
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(section.rva >= sizeOfHeaders_ && section.rva < identity_.sizeOfImage &&
				mapped <= identity_.sizeOfImage - section.rva &&
				(section.rawSize == 0 || (section.rawOffset >= sizeOfHeaders_ &&
					Fits(section.rawOffset, section.rawSize, bytes_.size())))), "Invalid PE section extent");
			sections_.push_back(section);
		}
		std::sort(sections_.begin(), sections_.end(),
			[](const Section& a, const Section& b) { return a.rva < b.rva; });
		for (size_t i = 1; i < sections_.size(); ++i)
		{
			const auto& previous = sections_[i - 1];
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(static_cast<uint64_t>(previous.rva) +
				(std::max)(previous.virtualSize, previous.rawSize) <= sections_[i].rva), "Overlapping PE virtual sections");
		}
		auto rawSections = sections_;
		std::sort(rawSections.begin(), rawSections.end(),
			[](const Section& a, const Section& b) { return a.rawOffset < b.rawOffset; });
		uint64_t previousEnd = 0;
		for (const auto& section : rawSections)
		{
			if (!section.rawSize)
				continue;
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(section.rawOffset >= previousEnd), "Overlapping PE raw sections");
			previousEnd = static_cast<uint64_t>(section.rawOffset) + section.rawSize;
		}
		for (const auto& section : sections_)
		{
			const auto size = (std::min)(section.rawSize,
				section.virtualSize ? section.virtualSize : section.rawSize);
			if ((section.characteristics & Execute) && size)
				codeRanges_.push_back({section.rva, size,
					identity_.machine == Amd64 ? InstructionSet::Amd64 : InstructionSet::Arm64});
		}

		ParseLoadConfig();
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(hybrid_ || (identity_.machine != Arm64EC && identity_.machine != Arm64X)), "ARM64EC/ARM64X requires valid CHPE metadata");
		ParseImports();
		ParseRelocations();
		ParseExports();
		ParseTls();
		const auto& exception = directories_[3];
		if (exception.size)
			ParseRuntimeFunctions(exception.rva, exception.size,
				identity_.machine == Arm64 || identity_.machine == Arm64X ||
				identity_.machine == Arm64EC);
		ParseDebug();
		AddRoot(entryPoint_);
		std::sort(roots_.begin(), roots_.end());
		roots_.erase(std::unique(roots_.begin(), roots_.end()), roots_.end());
		roots_.erase(std::remove_if(roots_.begin(), roots_.end(),
			[this](uint32_t rva) { return !GetCode(rva).data; }), roots_.end());
	}

	void PeImage::ParseHybrid(uint32_t rva)
	{
		// LLVM Object/COFF.h: chpe_metadata and chpe_range_entry (versions 1 and 2).
		const auto version = Rva32(rva);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(version == 1 || version == 2), "Unsupported CHPE metadata version");
		RawOffset(rva, version == 1 ? 80 : 92);
		const auto map = Rva32(rva, 4);
		const auto count = Rva32(rva, 8);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(count != 0 && count <= Available(map) / 8), "Invalid CHPE CodeMap");
		Charge(count);
		std::vector<BasicBlock> ranges;
		uint64_t end = 0;
		for (uint32_t i = 0; i < count; ++i)
		{
			const auto encoded = Rva32(map, static_cast<size_t>(i) * 8);
			const auto start = encoded & ~3u;
			const auto type = encoded & 3u;
			const auto size = Rva32(map, static_cast<size_t>(i) * 8 + 4);
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(type <= 2 && start >= end && start < identity_.sizeOfImage &&
				size <= identity_.sizeOfImage - start &&
				(type == 2 || !(size & 3))), "Malformed CHPE code range");
			end = static_cast<uint64_t>(start) + size;
			if (!size)
				continue;
			auto codeIt = std::upper_bound(codeRanges_.begin(), codeRanges_.end(), start,
				[](uint32_t value, const BasicBlock& code) { return value < code.rva; });
			if (codeIt != codeRanges_.begin())
				--codeIt;
			for (; codeIt != codeRanges_.end() && codeIt->rva < end; ++codeIt)
			{
				const auto& code = *codeIt;
				const auto first = (std::max)(start, code.rva);
				const auto last = (std::min)(end, static_cast<uint64_t>(code.rva) + code.size);
				if (first < last)
				{
					Charge(1);
					ranges.push_back({first, static_cast<uint32_t>(last - first),
						type == 2 ? InstructionSet::Amd64 : InstructionSet::Arm64});
				}
			}
		}
		codeRanges_ = std::move(ranges);
		hybrid_ = true;
		AddRoot(Rva32(rva, 40));
		const auto entryTable = Rva32(rva, 12);
		const auto entryCount = Rva32(rva, 48);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(entryCount <= Available(entryTable) / 12), "Invalid CHPE entry point table");
		Charge(entryCount);
		for (uint32_t i = 0; i < entryCount; ++i)
		{
			const auto offset = static_cast<size_t>(i) * 12;
			const auto first = Rva32(entryTable, offset);
			const auto last = Rva32(entryTable, offset + 4);
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(first <= last && last <= identity_.sizeOfImage), "Invalid CHPE entry point extent");
			AddRoot(first);
			AddRoot(Rva32(entryTable, offset + 8));
		}
		const auto redirect = Rva32(rva, 16);
		const auto redirectCount = Rva32(rva, 52);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(redirectCount <= Available(redirect) / 8), "Invalid CHPE redirection table");
		Charge(redirectCount);
		for (uint32_t i = 0; i < redirectCount; ++i)
		{
			AddRoot(Rva32(redirect, static_cast<size_t>(i) * 8));
			AddRoot(Rva32(redirect, static_cast<size_t>(i) * 8 + 4));
		}
		const auto extra = Rva32(rva, 64);
		const auto extraSize = Rva32(rva, 68);
		if (extraSize)
			ParseRuntimeFunctions(extra, extraSize,
				identity_.machine == Amd64 || identity_.machine == Arm64EC);
	}

	void PeImage::ParseLoadConfig()
	{
		const auto& directory = directories_[10];
		if (!directory.size)
			return;
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(directory.size >= 4), "Truncated load configuration");
		RawOffset(directory.rva, directory.size);
		const auto size = Rva32(directory.rva);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(size >= 4 && size <= directory.size), "Invalid load configuration size");
		if (size >= 208)
		{
			const auto metadata = Rva64(directory.rva, 200);
			if (metadata)
			{
				uint32_t metadataRva = 0;
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(VaToRva(metadata, metadataRva)), "Invalid CHPE metadata pointer");
				ParseHybrid(metadataRva);
			}
		}
		const auto stride = size >= 148 ? 4u + (Rva32(directory.rva, 144) >> 28) : 4u;
		const auto readTable = [&](size_t pointerOffset, size_t countOffset, bool iat)
		{
			if (size < countOffset + 8)
				return;
			const auto table = Rva64(directory.rva, pointerOffset);
			const auto count = Rva64(directory.rva, countOffset);
			if (!count)
				return;
			uint32_t tableRva = 0;
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(VaToRva(table, tableRva) && count <= Available(tableRva) / stride), "Invalid load configuration target table");
			Charge(static_cast<size_t>(count));
			for (uint64_t i = 0; i < count; ++i)
			{
				const auto target = Rva32(tableRva, static_cast<size_t>(i) * stride);
				if (iat)
				{
					RawOffset(target, 8);
					imports_.push_back({target, 0});
				}
				else
					AddRoot(target);
			}
		};
		readTable(128, 136, false);
		readTable(160, 168, true);
		readTable(176, 184, false);
		readTable(264, 272, false);
	}

	void PeImage::ParseExports()
	{
		const auto& directory = directories_[0];
		if (!directory.size)
			return;
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(directory.size >= 40), "Truncated export directory");
		RawOffset(directory.rva, directory.size);
		const auto count = Rva32(directory.rva, 20);
		const auto table = Rva32(directory.rva, 28);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(count <= Available(table) / 4), "Invalid export address table");
		Charge(count);
		for (uint32_t i = 0; i < count; ++i)
		{
			const auto target = Rva32(table, static_cast<size_t>(i) * 4);
			if (target < directory.rva || target - directory.rva >= directory.size)
				AddRoot(target);
		}
	}

	void PeImage::ParseImports()
	{
		const auto readSlots = [&](uint32_t table, uint32_t lookup, bool delay)
		{
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(table != 0), "Missing import address table");
			const auto count = Available(table) / 8;
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(count != 0), "Invalid import address table");
			for (size_t i = 0; i < count; ++i)
			{
				Charge(1);
				const auto slot = Add(table, i * 8);
				const auto value = Rva64(slot);
				const auto name = lookup ? Rva64(lookup, i * 8) : value;
				uint32_t target = 0;
				if (delay && value && !(value >> 63))
					VaToRva(value, target);
				imports_.push_back({slot, target});
				if (!name)
					return;
			}
			THROW_HR_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), "Unterminated import address table");
		};
		for (const auto index : {1u, 13u})
		{
			const auto& directory = directories_[index];
			if (!directory.size)
				continue;
			const size_t stride = index == 1 ? 20 : 32;
			RawOffset(directory.rva, directory.size);
			bool terminated = false;
			for (size_t offset = 0; Fits(offset, stride, directory.size); offset += stride)
			{
				Charge(1);
				bool empty = true;
				for (size_t field = 0; field < stride; field += 4)
					empty = empty && Rva32(directory.rva, offset + field) == 0;
				if (empty)
				{
					terminated = true;
					break;
				}
				if (index == 1)
					readSlots(Rva32(directory.rva, offset + 16),
						Rva32(directory.rva, offset), false);
				else
				{
					const auto attributes = Rva32(directory.rva, offset);
					THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !((attributes & ~1u) == 0), "Unsupported delay import attributes");
					const auto pointer = [&](size_t field)
					{
						const auto value = Rva32(directory.rva, offset + field);
						if ((attributes & 1) || !value)
							return value;
						uint32_t result = 0;
						THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(VaToRva(value, result)), "Invalid delay import VA");
						return result;
					};
					readSlots(pointer(12), pointer(16), true);
					const auto unload = pointer(24);
					if (unload)
					{
						const auto count = Available(unload) / 8;
						bool end = false;
						for (size_t i = 0; i < count; ++i)
						{
							Charge(1);
							const auto value = Rva64(unload, i * 8);
							if (!value)
							{
								end = true;
								break;
							}
							uint32_t target = 0;
							if (!(value >> 63) && VaToRva(value, target))
								AddRoot(target);
						}
						THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(end), "Unterminated delay unload table");
					}
				}
			}
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(terminated), "Unterminated import descriptor table");
		}
		const auto& iat = directories_[12];
		if (iat.size)
		{
			RawOffset(iat.rva, iat.size);
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(!(iat.size & 7)), "Invalid IAT directory size");
			Charge(iat.size / 8);
			for (uint32_t i = 0; i < iat.size / 8; ++i)
				imports_.push_back({Add(iat.rva, static_cast<size_t>(i) * 8), 0});
		}
		std::sort(imports_.begin(), imports_.end(),
			[](const ImportSlot& a, const ImportSlot& b)
			{
				return a.rva != b.rva ? a.rva < b.rva : a.target > b.target;
			});
		imports_.erase(std::unique(imports_.begin(), imports_.end(),
			[](const ImportSlot& a, const ImportSlot& b) { return a.rva == b.rva; }), imports_.end());
		for (size_t i = 1; i < imports_.size(); ++i)
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(imports_[i].rva - imports_[i - 1].rva >= 8), "Overlapping import slots");
		importsReady_ = true;
		for (const auto& slot : imports_)
			AddRoot(slot.target);
	}

	void PeImage::ParseTls()
	{
		const auto& directory = directories_[9];
		if (!directory.size)
			return;
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(directory.size >= 40), "Truncated TLS directory");
		RawOffset(directory.rva, directory.size);
		const auto callbacks = Rva64(directory.rva, 24);
		if (!callbacks)
			return;
		uint32_t table = 0;
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(VaToRva(callbacks, table)), "Invalid TLS callback array");
		const auto count = Available(table) / 8;
		for (size_t i = 0; i < count; ++i)
		{
			Charge(1);
			const auto callback = Rva64(table, i * 8);
			if (!callback)
				return;
			uint32_t target = 0;
			if (VaToRva(callback, target))
				AddRoot(target);
		}
		THROW_HR_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), "Unterminated TLS callback array");
	}

	void PeImage::ParseRuntimeFunctions(uint32_t rva, uint32_t size, bool arm64)
	{
		RawOffset(rva, size);
		if (hybrid_)
		{
			const auto code = GetCode(Rva32(rva));
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(code.data != nullptr), "Unclassified hybrid runtime function");
			arm64 = code.instructionSet == InstructionSet::Arm64;
		}
		const size_t stride = arm64 ? 8 : 12;
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(size % stride == 0), "Truncated runtime function table");
		Charge(size / stride);
		std::vector<uint32_t> pending;
		for (size_t offset = 0; offset < size; offset += stride)
			pending.push_back(Add(rva, offset));
		std::set<uint32_t> visited;
		std::map<uint32_t, uint32_t> chains;
		const auto chain = [&](uint32_t record, uint32_t parent)
		{
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(parent != 0), "Null unwind chain");
			chains.emplace(record, parent);
			std::set<uint32_t> path;
			for (auto current = record;;)
			{
				Charge(1);
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(path.insert(current).second), "Cyclic unwind chain");
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(path.size() <= 256), "Unwind chain exceeds the discovery depth limit");
				const auto next = chains.find(current);
				if (next == chains.end())
					break;
				current = next->second;
			}
			pending.push_back(parent);
		};
		while (!pending.empty())
		{
			const auto record = pending.back();
			pending.pop_back();
			if (!visited.insert(record).second)
				continue;
			Charge(1);
			RawOffset(record, stride);
			const auto begin = Rva32(record);
			const auto unwind = Rva32(record, arm64 ? 4 : 8);
			if (!begin && !unwind)
				continue;
			AddRoot(begin);
			if (arm64)
			{
				const auto kind = unwind & 3;
				if (kind == 3)
				{
					chain(record, unwind & ~3u);
					continue;
				}
				uint32_t length = 0;
				if (kind == 1 || kind == 2)
					length = ((unwind >> 2) & 0x7ff) * 4;
				else
				{
					const auto header = Rva32(unwind);
					THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(((header >> 18) & 3) == 0), "Unsupported ARM64 unwind version");
					length = (header & 0x3ffff) * 4;
					uint32_t epilogs = (header >> 22) & 31;
					uint32_t words = header >> 27;
					size_t headerSize = 4;
					if (!epilogs && !words)
					{
						const auto extension = Rva32(unwind, 4);
						THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !((extension >> 24) == 0), "Invalid ARM64 extended unwind header");
						epilogs = extension & 0xffff;
						words = (extension >> 16) & 0xff;
						headerSize = 8;
					}
					if (header & (1u << 21))
						epilogs = 0;
					const auto handlerOffset = headerSize + static_cast<size_t>(epilogs) * 4 +
						static_cast<size_t>(words) * 4;
					RawOffset(unwind, handlerOffset + ((header & (1u << 20)) ? 4 : 0));
					if (header & (1u << 20))
						AddRoot(Rva32(unwind, handlerOffset));
				}
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(length != 0 && begin < identity_.sizeOfImage &&
					length <= identity_.sizeOfImage - begin), "Invalid ARM64 runtime function extent");
			}
			else
			{
				const auto end = Rva32(record, 4);
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(begin < end && end <= identity_.sizeOfImage), "Invalid AMD64 runtime function extent");
				if (unwind & 1)
				{
					chain(record, unwind & ~1u);
					continue;
				}
				const auto offset = RawOffset(unwind, 4);
				const auto version = bytes_[offset] & 7;
				const auto flags = bytes_[offset] >> 3;
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !((version == 1 || version == 2) && (flags & ~7) == 0 &&
					!((flags & 4) && (flags & 3))), "Unsupported AMD64 unwind header");
				const auto count = bytes_[offset + 2];
				const auto tail = 4 + ((static_cast<size_t>(count) + 1) & ~size_t{1}) * 2;
				RawOffset(unwind, tail + ((flags & 4) ? 12 : (flags & 3) ? 4 : 0));
				if (flags & 4)
					chain(record, Add(unwind, tail));
				else if (flags & 3)
					AddRoot(Rva32(unwind, tail));
			}
		}
	}

	void PeImage::ParseDebug()
	{
		const auto& directory = directories_[6];
		if (!directory.size)
			return;
		RawOffset(directory.rva, directory.size);
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(directory.size % 28 == 0), "Truncated debug directory");
		Charge(directory.size / 28);
		for (size_t offset = 0; offset < directory.size; offset += 28)
		{
			if (Rva32(directory.rva, offset + 12) != 2)
				continue;
			const auto size = Rva32(directory.rva, offset + 16);
			const auto address = Rva32(directory.rva, offset + 20);
			const auto pointer = Rva32(directory.rva, offset + 24);
			const auto raw = pointer ? static_cast<size_t>(pointer) : RawOffset(address, size);
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(Fits(raw, size, bytes_.size())), "Truncated CodeView record");
			if (size < 4 || Read(bytes_, raw, 4) != 0x53445352)
				continue;
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(size >= 24), "Truncated RSDS record");
			std::copy_n(bytes_.begin() + raw + 4, 16, identity_.pdbGuid.begin());
			identity_.pdbAge = static_cast<uint32_t>(Read(bytes_, raw + 20, 4));
			return;
		}
	}

	void PeImage::ParseRelocations()
	{
		const auto& directory = directories_[5];
		if (!directory.size)
			return;
		RawOffset(directory.rva, directory.size);
		for (size_t offset = 0; offset < directory.size;)
		{
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(Fits(offset, 8, directory.size)), "Truncated base relocation block");
			const auto page = Rva32(directory.rva, offset);
			const auto size = Rva32(directory.rva, offset + 4);
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(!(page & 0xfff) && page < identity_.sizeOfImage &&
				size >= 8 && !(size & 1) && Fits(offset, size, directory.size)), "Invalid base relocation block");
			const auto count = (size - 8) / 2;
			Charge(count);
			for (size_t i = 0; i < count; ++i)
			{
				const auto raw = RawOffset(Add(directory.rva, offset + 8 + i * 2), 2);
				const auto entry = static_cast<uint16_t>(Read(bytes_, raw, 2));
				const auto type = entry >> 12;
				if (!type)
					continue;
				const auto target = Add(page, entry & 0xfff);
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(target < identity_.sizeOfImage), "Invalid base relocation target");
				const uint32_t width = type == 10 ? 8 : 1;
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(width <= identity_.sizeOfImage - target), "Base relocation exceeds image");
				auto range = std::upper_bound(codeRanges_.begin(), codeRanges_.end(), target,
					[](uint32_t value, const BasicBlock& code) { return value < code.rva; });
				if (range != codeRanges_.begin())
					--range;
				bool code = false;
				for (; range != codeRanges_.end() && range->rva <
					static_cast<uint64_t>(target) + 8; ++range)
					code = code || static_cast<uint64_t>(range->rva) + range->size > target;
				if (code)
				{
					THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(type == 10), "Unsupported base relocation in executable code");
					RawOffset(target, 8);
					relocations_.push_back(target);
				}
			}
			offset += size;
		}
		std::sort(relocations_.begin(), relocations_.end());
		for (size_t i = 1; i < relocations_.size(); ++i)
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), !(relocations_[i] - relocations_[i - 1] >= 8), "Overlapping code base relocations");
	}
}
