#include "stdafx.h"
#include "RvaSelectionPlan.hpp"
#include "BasicBlockDiscovery.hpp"
#include "DebugInformationEnumerator.hpp"
#include "Patterns.hpp"
#include "Wildcards.hpp"
#include "FileFilter/File.hpp"
#include "FileFilter/UnifiedDiffParser.hpp"

#include <bcrypt.h>
#include <wil/resource.h>
#include <wil/result.h>
#include <algorithm>
#include <atomic>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <tuple>

namespace CppCoverage
{
	namespace
	{
		namespace fs = std::filesystem;
		constexpr size_t MaxFileSize = 64 * 1024 * 1024;
		constexpr size_t MaxModules = 4096;
		constexpr size_t MaxBlocks = 250000;

		void Require(bool value, const char* message)
		{
			if (!value)
				throw std::runtime_error(message);
		}

		std::wstring Wide(const std::string& value)
		{
			if (value.empty())
				return {};
			const auto size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
				value.data(), static_cast<int>(value.size()), nullptr, 0);
			Require(size != 0, "Invalid UTF-8");
			std::wstring result(size, L'\0');
			Require(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
				static_cast<int>(value.size()), &result[0], size) == size, "Invalid UTF-8");
			return result;
		}

		std::string Utf8(const std::wstring& value)
		{
			if (value.empty())
				return {};
			const auto size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
				value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
			Require(size != 0, "Invalid UTF-16");
			std::string result(size, '\0');
			Require(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(),
				static_cast<int>(value.size()), &result[0], size, nullptr, nullptr) == size,
				"Invalid UTF-16");
			return result;
		}

		std::string ReadText(const fs::path& path)
		{
			std::ifstream input(path, std::ios::binary | std::ios::ate);
			Require(input.good(), "Cannot open input file");
			const auto size = input.tellg();
			Require(size >= 0 && static_cast<uint64_t>(size) <= MaxFileSize, "Input exceeds 64 MiB limit");
			std::string text(static_cast<size_t>(size), '\0');
			input.seekg(0);
			if (!text.empty())
				input.read(&text[0], static_cast<std::streamsize>(text.size()));
			Require(input.good(), "Cannot read input file");
			return text;
		}

		std::string Hex(const uint8_t* bytes, size_t count)
		{
			const char digits[] = "0123456789abcdef";
			std::string result;
			result.reserve(count * 2);
			for (size_t i = 0; i < count; ++i)
			{
				result.push_back(digits[bytes[i] >> 4]);
				result.push_back(digits[bytes[i] & 15]);
			}
			return result;
		}

		bool IsHex(const std::string& text, size_t count)
		{
			return text.size() == count * 2 && std::all_of(text.begin(), text.end(),
				[](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
		}

		template <size_t N>
		std::array<uint8_t, N> Unhex(const std::string& text)
		{
			Require(IsHex(text, N), "Invalid lowercase hexadecimal identity");
			std::array<uint8_t, N> result{};
			auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
			for (size_t i = 0; i < N; ++i)
				result[i] = static_cast<uint8_t>(digit(text[2 * i]) * 16 + digit(text[2 * i + 1]));
			return result;
		}

		std::vector<uint8_t> Hash(const std::string& bytes, LPCWSTR algorithmName, size_t size)
		{
			wil::unique_bcrypt_algorithm algorithm;
			THROW_IF_NTSTATUS_FAILED(BCryptOpenAlgorithmProvider(algorithm.put(), algorithmName, nullptr, 0));
			wil::unique_bcrypt_hash hash;
			THROW_IF_NTSTATUS_FAILED(BCryptCreateHash(algorithm.get(), hash.put(), nullptr, 0, nullptr, 0, 0));
			if (!bytes.empty())
				THROW_IF_NTSTATUS_FAILED(BCryptHashData(hash.get(),
					reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data())),
					static_cast<ULONG>(bytes.size()), 0));
			std::vector<uint8_t> result(size);
			THROW_IF_NTSTATUS_FAILED(BCryptFinishHash(hash.get(), result.data(), static_cast<ULONG>(size), 0));
			return result;
		}

		bool LessBlock(const BasicBlock& a, const BasicBlock& b)
		{
			return std::tie(a.rva, a.size, a.instructionSet) < std::tie(b.rva, b.size, b.instructionSet);
		}

		bool SameBlock(const BasicBlock& a, const BasicBlock& b)
		{
			return !LessBlock(a, b) && !LessBlock(b, a);
		}

		auto IntersectingBlocks(const std::vector<BasicBlock>& sorted, const RvaAddressRange& range)
		{
			Require(uint64_t{range.rva} + range.size <= uint64_t{UINT32_MAX} + 1, "PDB line range overflow");
			const auto first = std::lower_bound(sorted.begin(), sorted.end(), range.rva,
				[](const BasicBlock& block, uint32_t rva) { return uint64_t{block.rva} + block.size <= rva; });
			const auto last = range.size == 0 ? first :
				std::lower_bound(first, sorted.end(), uint64_t{range.rva} + range.size,
					[](const BasicBlock& block, uint64_t end) { return block.rva < end; });
			return std::make_pair(first, last);
		}

		bool SameIdentity(const PeIdentity& a, const PeIdentity& b)
		{
			return a.machine == b.machine && a.timeDateStamp == b.timeDateStamp &&
				a.sizeOfImage == b.sizeOfImage && a.checksum == b.checksum &&
				a.pdbGuid == b.pdbGuid && a.pdbAge == b.pdbAge && a.imageHash == b.imageHash;
		}

		std::string Quote(const std::string& value)
		{
			Wide(value);
			std::string result = "\"";
			const char digits[] = "0123456789abcdef";
			for (unsigned char c : value)
			{
				if (c == '"' || c == '\\')
				{
					result += '\\';
					result += static_cast<char>(c);
				}
				else if (c < 32)
				{
					result += "\\u00";
					result += digits[c >> 4];
					result += digits[c & 15];
				}
				else
					result += static_cast<char>(c);
			}
			return result + '"';
		}

		// Types are retained; JSON strings, booleans and floating-point values cannot become integers.
		struct Json
		{
			enum class Kind { Object, Array, String, Number } kind;
			std::map<std::string, Json> object;
			std::vector<Json> array;
			std::string text;
			uint32_t number = 0;
		};

		class JsonReader
		{
		public:
			explicit JsonReader(const std::string& text) : text_(text) {}
			Json Read()
			{
				if (text_.compare(0, 3, "\xef\xbb\xbf") == 0)
					index_ = 3;
				auto value = Value(0);
				Space();
				Require(index_ == text_.size(), "Trailing JSON data");
				return value;
			}
		private:
			void Space()
			{
				while (index_ < text_.size() && (text_[index_] == ' ' || text_[index_] == '\r' ||
					text_[index_] == '\n' || text_[index_] == '\t'))
					++index_;
			}
			bool Take(char c)
			{
				Space();
				if (index_ < text_.size() && text_[index_] == c)
				{
					++index_;
					return true;
				}
				return false;
			}
			void Need(char c) { Require(Take(c), "Invalid JSON punctuation"); }
			uint16_t Unicode()
			{
				Require(index_ + 4 <= text_.size(), "Truncated JSON unicode escape");
				uint16_t result = 0;
				for (int i = 0; i < 4; ++i)
				{
					const char c = text_[index_++];
					Require((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
						(c >= 'A' && c <= 'F'), "Invalid JSON unicode escape");
					result = static_cast<uint16_t>(result * 16 +
						(c <= '9' ? c - '0' : (c <= 'F' ? c - 'A' + 10 : c - 'a' + 10)));
				}
				return result;
			}
			std::string String()
			{
				Need('"');
				std::string value;
				while (index_ < text_.size())
				{
					auto c = static_cast<unsigned char>(text_[index_++]);
					if (c == '"')
					{
						Wide(value);
						Require(value.find('\0') == std::string::npos, "NUL in JSON string");
						return value;
					}
					Require(c >= 32, "Control character in JSON string");
					if (c != '\\')
						value += static_cast<char>(c);
					else
					{
						Require(index_ < text_.size(), "Truncated JSON escape");
						switch (text_[index_++])
						{
						case '"': value += '"'; break;
						case '\\': value += '\\'; break;
						case '/': value += '/'; break;
						case 'b': value += '\b'; break;
						case 'f': value += '\f'; break;
						case 'n': value += '\n'; break;
						case 'r': value += '\r'; break;
						case 't': value += '\t'; break;
						case 'u':
						{
							std::wstring utf16(1, static_cast<wchar_t>(Unicode()));
							if (utf16[0] >= 0xd800 && utf16[0] <= 0xdbff)
							{
								Require(index_ + 2 <= text_.size() && text_[index_] == '\\' &&
									text_[index_ + 1] == 'u', "Unpaired JSON surrogate");
								index_ += 2;
								const auto low = Unicode();
								Require(low >= 0xdc00 && low <= 0xdfff, "Unpaired JSON surrogate");
								utf16 += static_cast<wchar_t>(low);
							}
							value += Utf8(utf16);
							break;
						}
						default: Require(false, "Unknown JSON escape");
						}
					}
					Require(value.size() <= 32768, "JSON string too long");
				}
				throw std::runtime_error("Unterminated JSON string");
			}
			Json Value(unsigned depth)
			{
				Require(depth <= 8 && ++nodes_ <= 1100000, "JSON complexity limit exceeded");
				Space();
				Require(index_ < text_.size(), "Truncated JSON");
				if (Take('{'))
				{
					Json value{Json::Kind::Object};
					if (!Take('}'))
						do
						{
							auto key = String();
							Need(':');
							Require(value.object.emplace(key, Value(depth + 1)).second, "Duplicate JSON property");
						} while (Take(','));
					else return value;
					Need('}');
					return value;
				}
				if (Take('['))
				{
					Json value{Json::Kind::Array};
					if (!Take(']'))
						do { value.array.push_back(Value(depth + 1)); } while (Take(','));
					else return value;
					Need(']');
					return value;
				}
				if (text_[index_] == '"')
				{
					Json value{Json::Kind::String};
					value.text = String();
					return value;
				}
				Json value{Json::Kind::Number};
				const auto start = index_;
				uint64_t number = 0;
				while (index_ < text_.size() && text_[index_] >= '0' && text_[index_] <= '9')
				{
					number = number * 10 + text_[index_++] - '0';
					Require(number <= UINT32_MAX, "JSON integer overflow");
				}
				Require(index_ != start && (index_ - start == 1 || text_[start] != '0'), "Expected unsigned JSON integer");
				value.number = static_cast<uint32_t>(number);
				return value;
			}
			const std::string& text_;
			size_t index_ = 0;
			size_t nodes_ = 0;
		};

		const Json& Field(const Json& value, const char* name, Json::Kind kind)
		{
			Require(value.kind == Json::Kind::Object, "Expected JSON object");
			const auto found = value.object.find(name);
			Require(found != value.object.end() && found->second.kind == kind, "Missing or incorrectly typed JSON property");
			return found->second;
		}
		uint32_t Number(const Json& value, const char* name) { return Field(value, name, Json::Kind::Number).number; }
		const std::string& Text(const Json& value, const char* name) { return Field(value, name, Json::Kind::String).text; }
		void Fields(const Json& value, size_t count)
		{
			Require(value.kind == Json::Kind::Object && value.object.size() == count, "Unexpected JSON properties");
		}

		void Validate(const RvaSelectionPlan& plan)
		{
			Require(plan.modules.size() <= MaxModules, "Too many selection modules");
			size_t blocks = 0;
			std::set<std::string> identities;
			for (const auto& module : plan.modules)
			{
				const auto& identity = module.identity;
				const auto name = Utf8(module.name);
				Require(!name.empty() && name.size() <= 32768 &&
					module.name.find_first_of(L"\\/:*?\"<>|") == std::wstring::npos &&
					module.name != L"." && module.name != L".." &&
					std::none_of(module.name.begin(), module.name.end(), [](wchar_t c) { return c < 32; }),
					"Selection module name must be a basename");
				Require((identity.machine == 0x8664 || identity.machine == 0xaa64 ||
					identity.machine == 0xa641 || identity.machine == 0xa64e) &&
					identity.sizeOfImage != 0 &&
					std::any_of(identity.imageHash.begin(), identity.imageHash.end(), [](uint8_t b) { return b != 0; }),
					"Invalid selection image identity");
				Require(IsHex(module.catalogSha256, 32), "Invalid catalog SHA-256");
				std::ostringstream key;
				key << identity.machine << ',' << identity.timeDateStamp << ',' << identity.sizeOfImage <<
					',' << identity.checksum << ',' << Hex(identity.pdbGuid.data(), 16) <<
					',' << identity.pdbAge << ',' << Hex(identity.imageHash.data(), 32);
				Require(identities.insert(key.str()).second, "Duplicate selection image identity");
				blocks += module.blocks.size();
				Require(blocks <= MaxBlocks, "Too many selected blocks");
				uint64_t end = 0;
				for (const auto& block : module.blocks)
				{
					const auto isa = static_cast<uint16_t>(block.instructionSet);
					Require(block.size != 0 && block.rva >= end &&
						uint64_t{block.rva} + block.size <= identity.sizeOfImage &&
						(isa == 0x8664 || isa == 0xaa64) &&
						(isa != 0xaa64 || ((block.rva | block.size) & 3) == 0) &&
						(identity.machine != 0x8664 || isa == 0x8664) &&
						(identity.machine != 0xaa64 || isa == 0xaa64), "Invalid selected block range, order or ISA");
					end = uint64_t{block.rva} + block.size;
				}
			}
		}

		std::string Serialize(const RvaSelectionPlan& plan)
		{
			Validate(plan);
			std::ostringstream out;
			out << "{\"schema\":1,\"modules\":[";
			bool first = true;
			for (const auto& module : plan.modules)
			{
				if (!first) out << ',';
				first = false;
				const auto& id = module.identity;
				out << "{\"name\":" << Quote(Utf8(module.name)) << ",\"identity\":{\"machine\":" << id.machine <<
					",\"timeDateStamp\":" << id.timeDateStamp << ",\"sizeOfImage\":" << id.sizeOfImage <<
					",\"checksum\":" << id.checksum << ",\"pdbGuid\":" << Quote(Hex(id.pdbGuid.data(), 16)) <<
					",\"pdbAge\":" << id.pdbAge << ",\"imageHash\":" << Quote(Hex(id.imageHash.data(), 32)) <<
					"},\"catalogSha256\":" << Quote(module.catalogSha256) << ",\"blocks\":[";
				bool firstBlock = true;
				for (const auto& block : module.blocks)
				{
					if (!firstBlock) out << ',';
					firstBlock = false;
					out << "{\"rva\":" << block.rva << ",\"size\":" << block.size <<
						",\"isa\":" << static_cast<uint16_t>(block.instructionSet) << '}';
				}
				out << "]}";
			}
			out << "]}\r\n";
			auto text = out.str();
			Require(text.size() <= MaxFileSize, "Selection plan exceeds file limit");
			return text;
		}

		class StagedFile
		{
		public:
			explicit StagedFile(const fs::path& target)
			{
				static std::atomic<unsigned> next{0};
				for (unsigned attempt = 0; attempt < 100; ++attempt)
				{
					path = target;
					path += L".stage-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(next++);
					wil::unique_handle handle(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
						CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
					if (handle)
						return;
					Require(GetLastError() == ERROR_FILE_EXISTS, "Cannot stage output beside destination");
				}
				throw std::runtime_error("Cannot allocate staged output");
			}
			~StagedFile()
			{
				std::error_code error;
				fs::remove(path, error);
			}
			void Write(const std::string& text)
			{
				std::ofstream out(path, std::ios::binary | std::ios::trunc);
				out.write(text.data(), static_cast<std::streamsize>(text.size()));
				out.close();
				Require(out.good(), "Cannot write staged output");
			}
			void Publish(const fs::path& target)
			{
				THROW_IF_WIN32_BOOL_FALSE(MoveFileExW(path.c_str(), target.c_str(),
					MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH));
			}
			fs::path path;
		};

		std::wstring PathKey(const fs::path& path)
		{
			auto key = fs::weakly_canonical(fs::absolute(path)).lexically_normal().wstring();
			std::transform(key.begin(), key.end(), key.begin(), [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
			return key;
		}

		bool SamePath(const fs::path& a, const fs::path& b)
		{
			std::error_code error;
			return PathKey(a) == PathKey(b) || (fs::equivalent(a, b, error) && !error);
		}
	}

	std::string RvaCatalogSha256(const std::vector<BasicBlock>& catalog)
	{
		Require(catalog.size() <= 4000000, "Catalog exceeds discovery limit");
		auto sorted = catalog;
		std::sort(sorted.begin(), sorted.end(), LessBlock);
		sorted.erase(std::unique(sorted.begin(), sorted.end(), SameBlock), sorted.end());
		std::string bytes;
		bytes.reserve(sorted.size() * 10);
		for (const auto& block : sorted)
		{
			for (const auto value : {block.rva, block.size})
				for (unsigned i = 0; i < 4; ++i)
					bytes += static_cast<char>(value >> (8 * i));
			const auto isa = static_cast<uint16_t>(block.instructionSet);
			bytes += static_cast<char>(isa);
			bytes += static_cast<char>(isa >> 8);
		}
		const auto hash = Hash(bytes, BCRYPT_SHA256_ALGORITHM, 32);
		return Hex(hash.data(), hash.size());
	}

	const RvaSelectionModule* FindRvaSelection(const RvaSelectionPlan& plan, const PeIdentity& identity)
	{
		const RvaSelectionModule* result = nullptr;
		for (const auto& module : plan.modules)
			if (SameIdentity(module.identity, identity))
			{
				Require(result == nullptr, "Ambiguous selection image identity");
				result = &module;
			}
		return result;
	}

	RvaSelectionPlan ReadRvaSelectionPlan(const fs::path& path)
	{
		const auto text = ReadText(path);
		const auto root = JsonReader(text).Read();
		Fields(root, 2);
		Require(Number(root, "schema") == 1, "Unsupported selection plan schema");
		const auto& modules = Field(root, "modules", Json::Kind::Array).array;
		Require(modules.size() <= MaxModules, "Too many selection modules");
		RvaSelectionPlan plan;
		size_t count = 0;
		for (const auto& item : modules)
		{
			Fields(item, 4);
			RvaSelectionModule module;
			module.name = Wide(Text(item, "name"));
			module.catalogSha256 = Text(item, "catalogSha256");
			const auto& id = Field(item, "identity", Json::Kind::Object);
			Fields(id, 7);
			const auto machine = Number(id, "machine");
			Require(machine <= UINT16_MAX, "Invalid machine width");
			module.identity.machine = static_cast<uint16_t>(machine);
			module.identity.timeDateStamp = Number(id, "timeDateStamp");
			module.identity.sizeOfImage = Number(id, "sizeOfImage");
			module.identity.checksum = Number(id, "checksum");
			module.identity.pdbGuid = Unhex<16>(Text(id, "pdbGuid"));
			module.identity.pdbAge = Number(id, "pdbAge");
			module.identity.imageHash = Unhex<32>(Text(id, "imageHash"));
			const auto& blocks = Field(item, "blocks", Json::Kind::Array).array;
			count += blocks.size();
			Require(count <= MaxBlocks, "Too many selected blocks");
			for (const auto& block : blocks)
			{
				Fields(block, 3);
				const auto isa = Number(block, "isa");
				Require(isa <= UINT16_MAX, "Invalid ISA width");
				module.blocks.push_back({Number(block, "rva"), Number(block, "size"), static_cast<InstructionSet>(isa)});
			}
			plan.modules.push_back(std::move(module));
		}
		Validate(plan);
		return plan;
	}

	void WriteRvaSelectionPlan(const RvaSelectionPlan& plan, const fs::path& path)
	{
		const auto text = Serialize(plan);
		StagedFile staged(path);
		staged.Write(text);
		staged.Publish(path);
	}

	std::vector<RvaSourceRegion> ExpandRvaSourceLines(
		const std::vector<uint32_t>& lines, unsigned expansion, uint32_t lineCount)
	{
		std::vector<RvaSourceRegion> regions;
		if (!lineCount)
			return regions;
		for (const auto line : lines)
		{
			Require(line != 0, "Source line numbers are one-based");
			regions.push_back({
				(std::min)(lineCount, line > expansion ? line - expansion : 1u),
				static_cast<uint32_t>((std::min)(uint64_t{lineCount}, uint64_t{line} + expansion))});
		}
		std::sort(regions.begin(), regions.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
		std::vector<RvaSourceRegion> merged;
		for (const auto& region : regions)
		{
			if (!merged.empty() && uint64_t{region.first} <= uint64_t{merged.back().last} + 1)
				merged.back().last = (std::max)(merged.back().last, region.last);
			else
				merged.push_back(region);
		}
		return merged;
	}

	std::vector<BasicBlock> SelectRvaBlocks(
		const std::vector<BasicBlock>& catalog, const std::vector<RvaAddressRange>& ranges)
	{
		auto sorted = catalog;
		std::sort(sorted.begin(), sorted.end(), LessBlock);
		std::set<size_t> selected;
		for (const auto& range : ranges)
		{
			const auto intersecting = IntersectingBlocks(sorted, range);
			for (auto it = intersecting.first; it != intersecting.second; ++it)
				selected.insert(static_cast<size_t>(it - sorted.begin()));
		}
		std::vector<BasicBlock> result;
		for (auto index : selected)
			if (result.empty() || !SameBlock(result.back(), sorted[index]))
				result.push_back(sorted[index]);
		return result;
	}

	namespace
	{
		struct Source
		{
			fs::path path;
			std::string bytes;
			std::vector<uint32_t> changed;
			std::vector<RvaSourceRegion> expanded;
			std::set<uint32_t> mapped;
			bool seen = false;
			bool checksumVerified = false;
			bool checksumUnavailable = false;
		};

		uint32_t LineCount(const std::string& bytes)
		{
			if (bytes.empty())
				return 0;
			uint64_t count = 0;
			if (bytes.size() >= 2 && ((static_cast<uint8_t>(bytes[0]) == 0xff &&
				static_cast<uint8_t>(bytes[1]) == 0xfe) ||
				(static_cast<uint8_t>(bytes[0]) == 0xfe && static_cast<uint8_t>(bytes[1]) == 0xff)))
			{
				Require((bytes.size() & 1) == 0, "Odd-length UTF-16 source");
				const bool little = static_cast<uint8_t>(bytes[0]) == 0xff;
				for (size_t i = 2; i < bytes.size(); i += 2)
					if (bytes[i + (little ? 0 : 1)] == '\n' && bytes[i + (little ? 1 : 0)] == 0)
						++count;
				if (bytes.size() > 2 && !(bytes[bytes.size() - (little ? 2 : 1)] == '\n' &&
					bytes[bytes.size() - (little ? 1 : 2)] == 0))
					++count;
			}
			else
			{
				count = static_cast<uint64_t>(std::count(bytes.begin(), bytes.end(), '\n'));
				if (bytes.back() != '\n')
					++count;
			}
			Require(count <= UINT32_MAX, "Source line count overflow");
			return static_cast<uint32_t>(count);
		}

		fs::path CheckoutPath(const fs::path& root, const fs::path& relative)
		{
			Require(!relative.empty() && (!relative.has_root_path() || relative.is_absolute()),
				"Diff source path must be checkout-relative or fully qualified");
			for (const auto& part : relative.relative_path())
			{
				const auto text = part.wstring();
				Require(!text.empty() && text != L"." && text != L".." &&
					text.find_first_of(L":*?\"<>|") == std::wstring::npos &&
					text.back() != L' ' && text.back() != L'.' &&
					std::none_of(text.begin(), text.end(), [](wchar_t c) { return c < 32; }),
					"Unsafe or ambiguous diff source path");
			}
			const auto full = fs::canonical(root / relative);
			auto rootKey = PathKey(root);
			if (rootKey.back() != L'\\')
				rootKey += L'\\';
			Require(PathKey(full).compare(0, rootKey.size(), rootKey) == 0,
				"Diff source escapes source root");
			Require(fs::is_regular_file(full), "Diff source is not a regular file");
			return full;
		}

		bool SelectedModule(const fs::path& path, const Patterns& patterns)
		{
			bool selected = patterns.GetSelectedPatterns().empty();
			for (const auto& pattern : patterns.GetSelectedPatterns())
				if (Wildcards(pattern, patterns.IsRegexCaseSensitiv()).Match(path.wstring()))
					selected = true;
			for (const auto& pattern : patterns.GetExcludedPatterns())
				if (Wildcards(pattern, patterns.IsRegexCaseSensitiv()).Match(path.wstring()))
					return false;
			return selected;
		}

		std::wstring SymbolPath()
		{
			const auto size = GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", nullptr, 0);
			if (!size)
				return {};
			std::wstring value(size, L'\0');
			const auto written = GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", &value[0], size);
			Require(written && written < size, "_NT_SYMBOL_PATH changed while reading");
			value.resize(written);
			return value;
		}

		struct Explanation
		{
			std::vector<std::string> diagnostics;
			std::vector<std::string> mappings;
			std::vector<std::string> images;
			bool complete = true;

			void Diagnostic(const fs::path& path, const std::string& reason)
			{
				complete = false;
				diagnostics.push_back("{\"path\":" + Quote(Utf8(path.wstring())) +
					",\"reason\":" + Quote(reason) + "}");
			}

			std::string Serialize(const std::map<std::wstring, Source>& sources) const
			{
				std::ostringstream out;
				out << "{\"kind\":\"rva-selection-explanation\",\"schema\":1,\"completeness\":" <<
					Quote(complete ? "complete-for-available-dia-mappings" : "partial") <<
					",\"sources\":[";
				bool first = true;
				for (const auto& item : sources)
				{
					if (!first) out << ',';
					first = false;
					const auto& source = item.second;
					out << "{\"path\":" << Quote(Utf8(source.path.wstring())) << ",\"changed\":[";
					bool firstLine = true;
					for (auto line : source.changed)
					{
						if (!firstLine) out << ',';
						firstLine = false;
						out << line;
					}
					out << "],\"expanded\":[";
					firstLine = true;
					for (const auto& region : source.expanded)
					{
						if (!firstLine) out << ',';
						firstLine = false;
						out << "{\"first\":" << region.first << ",\"last\":" << region.last << '}';
					}
					out << "],\"checksum\":" << Quote(source.checksumVerified ?
						(source.checksumUnavailable ? "partially-verified" : "verified-in-encountered-pdbs") :
						"unverified") << '}';
				}
				out << ']';
				auto array = [&](const char* name, const std::vector<std::string>& values) {
					out << ",\"" << name << "\":[";
					bool firstValue = true;
					for (const auto& value : values)
					{
						if (!firstValue) out << ',';
						firstValue = false;
						out << value;
					}
					out << ']';
				};
				array("images", images);
				array("mappings", mappings);
				array("diagnostics", diagnostics);
				out << "}\r\n";
				Require(out.tellp() <= static_cast<std::streamoff>(MaxFileSize), "Explanation exceeds file limit");
				return out.str();
			}
		};

		class SelectionHandler : public IDebugInformationHandler
		{
		public:
			SelectionHandler(const fs::path& root, const fs::path& imagePath, const PeImage& image,
				const std::vector<BasicBlock>& catalog, std::map<std::wstring, Source>& sources,
				Explanation& explanation, const fs::path& output, const fs::path& report)
				: root_(root), imagePath_(imagePath), image_(image), catalog_(catalog),
				  sources_(sources), explanation_(explanation), output_(output), report_(report)
			{}

			bool WantsSourceProvenance() const override { return true; }
			bool IsSourceFileSelected(const fs::path& path) override
			{
				const auto found = sources_.find(PathKey(path.is_absolute() ? path : root_ / path));
				return found != sources_.end();
			}
			void OnPdbFile(const fs::path& path) override
			{
				Require(!SamePath(path, output_) && !SamePath(path, report_), "Output aliases a PDB");
				openedPdb = path;
			}
			void OnMappingDiagnostic(const fs::path& path, const std::string& reason) override
			{
				explanation_.Diagnostic(path, reason);
			}
			void OnSourceChecksum(const fs::path& path, uint32_t type, const std::vector<uint8_t>& expected) override
			{
				auto& source = Get(path);
				source.seen = true;
				LPCWSTR algorithm = nullptr;
				size_t size = 0;
				if (type == 1) { algorithm = BCRYPT_MD5_ALGORITHM; size = 16; }
				if (type == 2) { algorithm = BCRYPT_SHA1_ALGORITHM; size = 20; }
				if (type == 3) { algorithm = BCRYPT_SHA256_ALGORITHM; size = 32; }
				if (!algorithm || expected.size() != size)
				{
					source.checksumUnavailable = true;
					explanation_.Diagnostic(source.path, "source-checksum-unavailable-or-unsupported");
					return;
				}
				if (Hash(source.bytes, algorithm, size) != expected)
					throw std::runtime_error("Stale source checksum does not match PDB: " +
						Utf8(source.path.wstring()));
				source.checksumVerified = true;
			}
			void OnSourceFile(const fs::path& path, const std::vector<Line>& lines) override
			{
				auto& source = Get(path);
				source.seen = true;
				for (const auto& line : lines)
				{
					const auto region = std::lower_bound(source.expanded.begin(), source.expanded.end(), line.lineNumber_,
						[](const RvaSourceRegion& region, uint32_t number) { return region.last < number; });
					if (region == source.expanded.end() || region->first > line.lineNumber_)
						continue;
					Require(line.virtualAddress_ >= 0 &&
						static_cast<uint64_t>(line.virtualAddress_) < image_.Identity().sizeOfImage &&
						line.length_ <= image_.Identity().sizeOfImage - line.virtualAddress_,
						"PDB source range lies outside matching image");
					if (!line.length_)
					{
						explanation_.Diagnostic(source.path, "zero-length-pdb-line:" + std::to_string(line.lineNumber_));
						continue;
					}
					const auto rva = static_cast<uint32_t>(line.virtualAddress_);
					const auto blocks = IntersectingBlocks(catalog_, {rva, line.length_});
					if (blocks.first == blocks.second)
					{
						explanation_.Diagnostic(source.path, "no-executable-catalog-block:" + std::to_string(line.lineNumber_));
						continue;
					}
					source.mapped.insert(line.lineNumber_);
					for (auto it = blocks.first; it != blocks.second; ++it)
					{
						const auto& block = *it;
						selected_.emplace(block.rva, block);
						std::ostringstream mapping;
						mapping << "{\"image\":" << Quote(Utf8(imagePath_.wstring())) <<
							",\"source\":" << Quote(Utf8(source.path.wstring())) <<
							",\"line\":" << line.lineNumber_ << ",\"lineRva\":" << rva <<
							",\"lineSize\":" << line.length_ << ",\"blockRva\":" << block.rva <<
							",\"blockSize\":" << block.size << ",\"isa\":" <<
							static_cast<uint16_t>(block.instructionSet) << '}';
						explanation_.mappings.push_back(mapping.str());
						Require(explanation_.mappings.size() <= MaxBlocks, "Too many explanation mappings");
					}
				}
			}
			std::vector<BasicBlock> Selected() const
			{
				std::vector<BasicBlock> blocks;
				for (const auto& item : selected_)
					blocks.push_back(item.second);
				return blocks;
			}
			fs::path openedPdb;
		private:
			Source& Get(const fs::path& path)
			{
				const auto found = sources_.find(PathKey(path.is_absolute() ? path : root_ / path));
				Require(found != sources_.end(), "DIA returned an unselected source path");
				return found->second;
			}
			const fs::path& root_;
			const fs::path& imagePath_;
			const PeImage& image_;
			const std::vector<BasicBlock>& catalog_;
			std::map<std::wstring, Source>& sources_;
			Explanation& explanation_;
			const fs::path& output_;
			const fs::path& report_;
			std::map<uint32_t, BasicBlock> selected_;
		};

		bool UnsupportedMetadata(const fs::path& path, Explanation& explanation)
		{
			std::ifstream input(path, std::ios::binary);
			Require(input.good(), "Cannot open selected image");
			auto read = [&](uint32_t offset, size_t width) {
				input.clear();
				input.seekg(offset);
				uint32_t value = 0;
				for (size_t i = 0; i < width; ++i)
				{
					const auto c = input.get();
					Require(c != std::char_traits<char>::eof(), "Truncated selected PE image");
					value |= static_cast<uint32_t>(c) << (8 * i);
				}
				return value;
			};
			Require(read(0, 2) == 0x5a4d, "Selected image has no MZ header");
			const auto pe = read(0x3c, 4);
			Require(pe >= 64 && pe < 512 * 1024 * 1024 - 256 &&
				read(pe, 4) == 0x4550, "Invalid selected PE header");
			const auto machine = read(pe + 4, 2);
			if (machine != 0x8664 && machine != 0xaa64 && machine != 0xa641 && machine != 0xa64e)
			{
				input.clear();
				input.seekg(0, std::ios::end);
				const auto fileSize = input.tellg();
				Require(fileSize >= 0 && static_cast<uint64_t>(fileSize) <= 512 * 1024 * 1024,
					"Unsupported selected image exceeds input limit");
				const auto sections = read(pe + 6, 2);
				const auto optionalSize = read(pe + 20, 2);
				const auto optional = pe + 24;
				const auto magic = read(optional, 2);
				const auto imageSize = read(optional + 56, 4);
				const auto headersSize = read(optional + 60, 4);
				const uint64_t sectionTable = uint64_t{optional} + optionalSize;
				Require(machine != 0 && sections != 0 && imageSize != 0 &&
					((magic == 0x10b && optionalSize >= 96) || (magic == 0x20b && optionalSize >= 112)) &&
					sectionTable + uint64_t{sections} * 40 <= headersSize &&
					headersSize <= imageSize && headersSize <= static_cast<uint64_t>(fileSize),
					"Malformed unsupported selected image");
				for (uint32_t i = 0; i < sections; ++i)
				{
					const auto offset = static_cast<uint32_t>(sectionTable + uint64_t{i} * 40);
					const auto virtualSize = read(offset + 8, 4);
					const auto rva = read(offset + 12, 4);
					const auto rawSize = read(offset + 16, 4);
					const auto raw = read(offset + 20, 4);
					Require(rva >= headersSize && uint64_t{rva} + (std::max)(virtualSize, rawSize) <= imageSize &&
						(rawSize == 0 || (raw >= headersSize &&
							uint64_t{raw} + rawSize <= static_cast<uint64_t>(fileSize))),
						"Malformed unsupported selected image section");
				}
				explanation.Diagnostic(path, "unsupported-PE-machine:" + std::to_string(machine));
				return true;
			}
			return false;
		}

		void PublishPair(const std::string& planText, const fs::path& output,
			const std::string& explanationText, const fs::path& report)
		{
			StagedFile plan(output), explanation(report);
			plan.Write(planText);
			explanation.Write(explanationText);
			StagedFile backup(report);
			const bool hadReport = fs::exists(report);
			if (hadReport)
				THROW_IF_WIN32_BOOL_FALSE(CopyFileW(report.c_str(), backup.path.c_str(), FALSE));
			explanation.Publish(report);
			try
			{
				plan.Publish(output);
			}
			catch (...)
			{
				if (hadReport)
					backup.Publish(report);
				else
				{
					std::error_code error;
					fs::remove(report, error);
				}
				throw;
			}
		}
	}

	void MakeRvaSelectionPlan(
		const fs::path& diff, const fs::path& sourceRoot,
		const std::vector<fs::path>& moduleDirectories, const Patterns& modulePatterns,
		const std::vector<SubstitutePdbSourcePath>& substitutions, unsigned expandLines,
		const fs::path& output)
	{
		const auto root = fs::canonical(sourceRoot);
		Require(fs::is_directory(root), "Source root is not a directory");
		auto report = output;
		report += L".explain.json";
		Require(!SamePath(output, report) && !SamePath(diff, output) && !SamePath(diff, report),
			"Plan or explanation aliases an input");
		// Existing unrelated files are never treated as replaceable generated outputs.
		if (fs::exists(output))
			ReadRvaSelectionPlan(output);
		if (fs::exists(report))
		{
			const auto text = ReadText(report);
			const auto prior = JsonReader(text).Read();
			Require(Text(prior, "kind") == "rva-selection-explanation", "Explanation would overwrite an unrelated file");
		}
		auto diffBytes = ReadText(diff);
		if (diffBytes.compare(0, 3, "\xef\xbb\xbf") == 0)
			diffBytes.erase(0, 3);
		std::wistringstream stream(Wide(diffBytes));
		const auto files = FileFilter::UnifiedDiffParser().Parse(stream,
			FileFilter::UnifiedDiffParser::Mode::NewSideChanges);
		std::map<std::wstring, Source> sources;
		for (const auto& file : files)
		{
			if (file.GetSelectedLines().empty())
				continue;
			const auto path = CheckoutPath(root, file.GetPath());
			Require(!SamePath(path, output) && !SamePath(path, report), "Output aliases a changed source");
			auto& source = sources[PathKey(path)];
			source.path = path;
			for (int line : file.GetSelectedLines())
			{
				Require(line > 0, "Invalid new-side source line");
				source.changed.push_back(static_cast<uint32_t>(line));
			}
		}
		for (auto& item : sources)
		{
			auto& source = item.second;
			source.bytes = ReadText(source.path);
			std::sort(source.changed.begin(), source.changed.end());
			source.changed.erase(std::unique(source.changed.begin(), source.changed.end()), source.changed.end());
			const auto lineCount = LineCount(source.bytes);
			Require(std::all_of(source.changed.begin(), source.changed.end(),
				[&](uint32_t line) { return line <= uint64_t{lineCount} + 1; }),
				"Diff coordinates exceed the checked-out source file");
			source.expanded = ExpandRvaSourceLines(source.changed, expandLines, lineCount);
		}

		std::map<std::wstring, fs::path> images;
		for (const auto& directory : moduleDirectories)
		{
			Require(fs::is_directory(directory), "Module directory does not exist");
			for (const auto& entry : fs::recursive_directory_iterator(directory))
			{
				if (!entry.is_regular_file())
					continue;
				auto extension = entry.path().extension().wstring();
				std::transform(extension.begin(), extension.end(), extension.begin(),
					[](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
				if (extension != L".exe" && extension != L".dll")
					continue;
				if (!SelectedModule(entry.path(), modulePatterns))
					continue;
				Require(!SamePath(entry.path(), output) && !SamePath(entry.path(), report), "Output aliases a selected image");
				images.emplace(PathKey(entry.path()), fs::canonical(entry.path()));
				Require(images.size() <= MaxModules, "Too many supplied images");
			}
		}
		Explanation explanation;
		RvaSelectionPlan plan;
		const auto symbolPath = SymbolPath();
		for (const auto& item : images)
		{
			const auto& path = item.second;
			if (UnsupportedMetadata(path, explanation))
				continue;
			PeImage image(path);
			auto catalog = BasicBlockDiscovery().Discover(image);
			std::sort(catalog.begin(), catalog.end(), LessBlock);
			RvaSelectionModule module{path.filename().wstring(), image.Identity(), RvaCatalogSha256(catalog), {}};
			Require(FindRvaSelection(plan, module.identity) == nullptr, "Duplicate supplied image identity");
			SelectionHandler handler(root, path, image, catalog, sources, explanation, output, report);
			DebugInformationEnumerator enumerator(substitutions, symbolPath);
			if (!enumerator.Enumerate(path, handler))
				throw std::runtime_error("Cannot load matching PDB for selected image: " +
					Utf8(path.wstring()) + ". Place its PDB beside the image or set _NT_SYMBOL_PATH.");
			Require(!handler.openedPdb.empty(), "DIA did not identify the matching PDB");
			module.blocks = handler.Selected();
			for (const auto& block : module.blocks)
			{
				const auto code = image.GetCode(block.rva);
				Require(code.data && code.instructionSet == block.instructionSet && block.size <= code.size,
					"Catalog block does not match executable image layout");
			}
			explanation.images.push_back("{\"path\":" + Quote(Utf8(path.wstring())) +
				",\"pdb\":" + Quote(Utf8(handler.openedPdb.wstring())) +
				",\"catalogSha256\":" + Quote(module.catalogSha256) +
				",\"selectedBlocks\":" + std::to_string(module.blocks.size()) + "}");
			plan.modules.push_back(std::move(module));
		}
		for (const auto& item : sources)
		{
			const auto& source = item.second;
			if (!source.seen)
				explanation.Diagnostic(source.path, "unmapped-source-path:no-exact-checkout-path-in-supplied-PDBs");
			if (source.mapped.empty())
				explanation.Diagnostic(source.path, "no-executable-lines-in-expanded-regions");
			for (auto line : source.changed)
				if (source.mapped.find(line) == source.mapped.end())
					explanation.Diagnostic(source.path, "changed-line-without-executable-mapping:" + std::to_string(line));
		}
		for (auto* values : {&explanation.mappings, &explanation.diagnostics})
		{
			std::sort(values->begin(), values->end());
			values->erase(std::unique(values->begin(), values->end()), values->end());
		}
		PublishPair(Serialize(plan), output, explanation.Serialize(sources), report);
	}
}
