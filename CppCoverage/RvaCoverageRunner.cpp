#include "stdafx.h"
#include "RvaCoverageRunner.hpp"

#include <Windows.h>
#include <wil/result.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <cwchar>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <wil/resource.h>

#include "ArchitectureBreakpoint.hpp"
#include "BasicBlockDiscovery.hpp"
#include "CoverageFilterManager.hpp"
#include "Debugger.hpp"
#include "ExceptionHandler.hpp"
#include "HandleInformation.hpp"
#include "RunCoverageSettings.hpp"
#include "Tools/Log.hpp"

namespace CppCoverage
{
	namespace
	{
		constexpr DWORD EmulatedBreakpoint = 0x4000001f;

		struct PhaseClock
		{
			std::chrono::steady_clock::time_point wall = std::chrono::steady_clock::now();
			uint64_t cpu;

			PhaseClock()
			{
				FILETIME created{}, exited{}, kernel{}, user{};
				THROW_LAST_ERROR_IF(!GetThreadTimes(
				    GetCurrentThread(), &created, &exited, &kernel, &user));
				cpu = (uint64_t{kernel.dwHighDateTime} << 32) + kernel.dwLowDateTime +
				      (uint64_t{user.dwHighDateTime} << 32) + user.dwLowDateTime;
			}

			double WallMillisecondsSince(const PhaseClock& before) const
			{
				return std::chrono::duration<double, std::milli>(wall - before.wall).count();
			}

			double CpuMillisecondsSince(const PhaseClock& before) const
			{
				return static_cast<double>(cpu - before.cpu) / 10000;
			}
		};

		void Read(HANDLE process, uint64_t address, void* data, size_t size)
		{
			SIZE_T read = 0;
			THROW_LAST_ERROR_IF_MSG(!ReadProcessMemory(process, reinterpret_cast<void*>(address),
			                       data, size, &read), "Reading remote PE image");
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), read != size, "Incomplete remote PE image read");
		}

		template <typename T>
		T Read(HANDLE process, uint64_t address)
		{
			T result{};
			Read(process, address, &result, sizeof(result));
			return result;
		}

		struct RemoteImage
		{
			uint64_t base;
			IMAGE_FILE_HEADER file;
			IMAGE_OPTIONAL_HEADER64 optional;
		};

		RemoteImage ReadImage(HANDLE process, uint64_t base)
		{
			const auto dos = Read<IMAGE_DOS_HEADER>(process, base);
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), dos.e_magic != IMAGE_DOS_SIGNATURE ||
			    dos.e_lfanew < static_cast<LONG>(sizeof(dos)) ||
			    dos.e_lfanew > 1024 * 1024, "Invalid remote DOS header");
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), base > (std::numeric_limits<uint64_t>::max)() -
			               static_cast<uint32_t>(dos.e_lfanew) -
			               sizeof(IMAGE_NT_HEADERS64), "Invalid remote PE header address");
			const auto nt = base + static_cast<uint32_t>(dos.e_lfanew);
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), Read<DWORD>(process, nt) != IMAGE_NT_SIGNATURE, "Invalid remote PE signature");
			const auto file = Read<IMAGE_FILE_HEADER>(process, nt + sizeof(DWORD));
			const size_t directoryOffset = offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), file.SizeOfOptionalHeader < directoryOffset, "Unsupported remote PE optional header");
			IMAGE_OPTIONAL_HEADER64 optional{};
			Read(process, nt + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER),
			     &optional, (std::min)(size_t{file.SizeOfOptionalHeader}, sizeof(optional)));
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), optional.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
			    optional.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES ||
			    optional.NumberOfRvaAndSizes >
			        (file.SizeOfOptionalHeader - directoryOffset) / sizeof(IMAGE_DATA_DIRECTORY) ||
			    optional.SizeOfImage < sizeof(IMAGE_NT_HEADERS64) ||
			    base > (std::numeric_limits<uint64_t>::max)() - optional.SizeOfImage, "Invalid remote 64-bit PE image");
			return {base, file, optional};
		}

		uint64_t RemoteAddress(const RemoteImage& image, uint32_t rva, size_t size)
		{
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), rva >= image.optional.SizeOfImage ||
			    size > image.optional.SizeOfImage - rva, "Remote PE metadata is outside the image");
			return image.base + rva;
		}

		uint64_t ReadCodeRange(
		    HANDLE process, const RemoteImage& image, uint64_t address,
		    std::vector<uint8_t>& bytes)
		{
			MEMORY_BASIC_INFORMATION memory{};
			THROW_LAST_ERROR_IF_MSG(!VirtualQueryEx(process, reinterpret_cast<void*>(address),
			    &memory, sizeof(memory)), "Querying mapped code range");
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
			    memory.State != MEM_COMMIT || (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)),
			    "Mapped code range is not readable");
			SYSTEM_INFO system{};
			GetSystemInfo(&system);
			const auto first = (std::max)(image.base,
			    address - address % system.dwPageSize);
			const auto region = reinterpret_cast<uint64_t>(memory.BaseAddress);
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
			    first < region || first - region >= memory.RegionSize ||
			    region > (std::numeric_limits<uint64_t>::max)() - memory.RegionSize ||
			    first >= image.base + image.optional.SizeOfImage,
			    "Invalid mapped code region");
			const auto last = first + (std::min)({uint64_t{2 * 1024 * 1024},
			    region + memory.RegionSize - first,
			    image.base + image.optional.SizeOfImage - first});
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
			    address < first || address >= last, "Mapped code range exceeds image");
			bytes.resize(static_cast<size_t>(last - first));
			Read(process, first, bytes.data(), bytes.size());
			return first;
		}

		std::set<uint64_t> LoaderBreakpoints(HANDLE process, const RemoteImage& image)
		{
			std::set<uint64_t> result;
			if (image.optional.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
				return result;
			const auto& directory =
			    image.optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (!directory.VirtualAddress || !directory.Size)
				return result;
			RemoteAddress(image, directory.VirtualAddress, directory.Size);
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), directory.Size < sizeof(IMAGE_EXPORT_DIRECTORY), "Invalid remote export directory");
			const auto exports = Read<IMAGE_EXPORT_DIRECTORY>(
			    process, RemoteAddress(image, directory.VirtualAddress,
			                           sizeof(IMAGE_EXPORT_DIRECTORY)));
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), exports.NumberOfNames > 65536 || exports.NumberOfFunctions > 65536, "Remote export table is too large");
			if (!exports.NumberOfNames || !exports.NumberOfFunctions)
				return result;
			std::vector<DWORD> names(exports.NumberOfNames);
			std::vector<WORD> ordinals(exports.NumberOfNames);
			std::vector<DWORD> functions(exports.NumberOfFunctions);
			Read(process, RemoteAddress(image, exports.AddressOfNames,
			                            names.size() * sizeof(DWORD)),
			     names.data(), names.size() * sizeof(DWORD));
			Read(process, RemoteAddress(image, exports.AddressOfNameOrdinals,
			                            ordinals.size() * sizeof(WORD)),
			     ordinals.data(), ordinals.size() * sizeof(WORD));
			Read(process, RemoteAddress(image, exports.AddressOfFunctions,
			                            functions.size() * sizeof(DWORD)),
			     functions.data(), functions.size() * sizeof(DWORD));
			const char expected[] = "DbgUserBreakPoint";
			for (size_t i = 0; i < names.size(); ++i)
			{
				char name[sizeof(expected)]{};
				Read(process, RemoteAddress(image, names[i], sizeof(name)), name, sizeof(name));
				if (std::memcmp(name, "DbgBreakPoint", sizeof("DbgBreakPoint")) != 0 &&
				    std::memcmp(name, expected, sizeof(name)) != 0)
					continue;
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), ordinals[i] >= functions.size(), "Invalid remote export ordinal");
				const auto rva = functions[ordinals[i]];
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), rva >= directory.VirtualAddress &&
				    rva - directory.VirtualAddress < directory.Size, "Forwarded loader breakpoint is unsupported");
				result.insert(RemoteAddress(image, rva, 1));
			}
			return result;
		}

		bool SameIdentity(const PeIdentity& lhs, const PeIdentity& rhs)
		{
			return lhs.machine == rhs.machine &&
			       lhs.timeDateStamp == rhs.timeDateStamp &&
			       lhs.sizeOfImage == rhs.sizeOfImage &&
			       lhs.checksum == rhs.checksum &&
			       lhs.pdbGuid == rhs.pdbGuid && lhs.pdbAge == rhs.pdbAge &&
			       lhs.imageHash == rhs.imageHash;
		}

		void ValidateMappedInstructionSets(
		    HANDLE process, const RemoteImage& image, const std::vector<BasicBlock>& blocks)
		{
			std::vector<BasicBlock> ranges;
			bool hybrid = false;
			if (image.optional.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
			{
				const auto& directory =
				    image.optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
				if (directory.VirtualAddress && directory.Size)
				{
					THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), directory.Size < sizeof(uint32_t), "Truncated mapped load configuration");
					const auto config = RemoteAddress(image, directory.VirtualAddress, directory.Size);
					const auto size = Read<uint32_t>(process, config);
					THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), size < sizeof(uint32_t) || size > directory.Size, "Mapped load configuration exceeds its directory");
					if (size >= 208)
					{
						const auto metadata = Read<uint64_t>(process, config + 200);
						if (metadata)
						{
							hybrid = true;
							THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), metadata < image.base ||
							    metadata - image.base > image.optional.SizeOfImage - 12, "Invalid mapped CHPE metadata pointer");
							const auto version = Read<uint32_t>(process, metadata);
							THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), version != 1 && version != 2, "Unsupported mapped CHPE metadata version");
							const auto map = Read<uint32_t>(process, metadata + 4);
							const auto count = Read<uint32_t>(process, metadata + 8);
							THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !count || count > 4 * 1024 * 1024, "Invalid mapped CHPE CodeMap count");
							struct Range { uint32_t encoded; uint32_t size; };
							std::vector<Range> entries(count);
							Read(process, RemoteAddress(image, map, entries.size() * sizeof(Range)),
							     entries.data(), entries.size() * sizeof(Range));
							uint64_t end = 0;
							for (const auto& entry : entries)
							{
								const auto rva = entry.encoded & ~3u;
								const auto type = entry.encoded & 3u;
								THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), type > 2 || rva < end ||
								    uint64_t{rva} + entry.size > image.optional.SizeOfImage ||
								    (type != 2 && ((rva | entry.size) & 3)), "Malformed mapped CHPE code range");
								end = uint64_t{rva} + entry.size;
								if (entry.size)
									ranges.push_back({rva, entry.size,
									    type == 2 ? InstructionSet::Amd64 : InstructionSet::Arm64});
							}
						}
						THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), hybrid && ranges.empty(), "Mapped CHPE CodeMap contains no code ranges");
					}
				}
			}
			for (const auto& block : blocks)
			{
				if (ranges.empty())
				{
					const auto expected = image.file.Machine == 0x8664 ?
					    InstructionSet::Amd64 : InstructionSet::Arm64;
					THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), image.file.Machine == 0xa641 || block.instructionSet != expected, "Block ISA requires missing mapped CHPE metadata");
					continue;
				}
				auto range = std::upper_bound(
				    ranges.begin(), ranges.end(), block.rva,
				    [](uint32_t rva, const BasicBlock& value) { return rva < value.rva; });
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), range == ranges.begin(), "Block is outside the mapped CHPE CodeMap");
				--range;
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), block.instructionSet != range->instructionSet ||
				    uint64_t{block.rva} + block.size > uint64_t{range->rva} + range->size, "Block ISA differs from the mapped CHPE CodeMap");
			}
		}

		bool SameBlock(const BasicBlock& lhs, const BasicBlock& rhs)
		{
			return lhs.rva == rhs.rva && lhs.size == rhs.size &&
			       lhs.instructionSet == rhs.instructionSet;
		}

		DWORD ProcessId(HANDLE process)
		{
			const DWORD id = GetProcessId(process);
			THROW_LAST_ERROR_IF_MSG(!id, "Identifying debugged process");
			return id;
		}
	}

	struct RvaCoverageRunner::State
	{
		struct Breakpoint
		{
			enum class Status : uint8_t { Uninstalled, ApplicationTrap, Installed, Restored };
			std::array<uint8_t, 4> original{};
			Status status = Status::Uninstalled;
		};

		struct Module
		{
			size_t aggregate;
			uint32_t size;
			// Slots share the aggregate module's sorted block indices.
			std::vector<Breakpoint> breakpoints;
		};

		struct Process
		{
			struct Loader
			{
				uint32_t size;
				std::set<uint64_t> applicationBreakpoints;
			};

			wil::unique_handle handle;
			DWORD initialThread = 0;
			std::map<uint64_t, Module> modules;
			std::map<uint64_t, Loader> loaders;
			bool startupBreakpointHandled = false;

		};

		RvaCoverage coverage;
		std::unique_ptr<CoverageFilterManager> filter;
		ExceptionHandler exceptions;
		std::map<DWORD, std::unique_ptr<Process>> processes;

		void Terminate() noexcept
		{
			for (const auto& entry : processes)
			{
				if (TerminateProcess(entry.second->handle.get(), ERROR_PROCESS_ABORTED))
					DebugActiveProcessStop(entry.first);
			}
			processes.clear();
		}
	};

	RvaCoverageRunner::RvaCoverageRunner() = default;
	RvaCoverageRunner::~RvaCoverageRunner() = default;

	RvaCoverage RvaCoverageRunner::RunCoverage(const RunCoverageSettings& settings)
	{
		state_ = std::make_unique<State>();
		state_->filter = std::make_unique<CoverageFilterManager>(
		    settings.GetCoverageFilterSettings(), std::vector<UnifiedDiffSettings>{},
		    std::vector<std::wstring>{}, false);
		state_->coverage.name = settings.GetStartInfo().GetPath().filename().wstring();
		Debugger debugger{settings.GetCoverChildren(),
		                  settings.GetContinueAfterCppException(), settings.GetStopOnAssert()};
		try
		{
			state_->coverage.exitCode = debugger.Debug(settings.GetStartInfo(), *this);
		}
		catch (...)
		{
			state_->Terminate();
			throw;
		}
		return std::move(state_->coverage);
	}

	void RvaCoverageRunner::OnCreateProcess(const CREATE_PROCESS_DEBUG_INFO& info)
	{
		const DWORD id = ProcessId(info.hProcess);
		try
		{
			auto process = std::make_unique<State::Process>();
			THROW_LAST_ERROR_IF_MSG(!DuplicateHandle(GetCurrentProcess(), info.hProcess,
			                     GetCurrentProcess(), process->handle.put(), 0,
			                     FALSE, DUPLICATE_SAME_ACCESS), "Retaining debugged process handle");
			process->initialThread = GetThreadId(info.hThread);
			THROW_LAST_ERROR_IF_MSG(!process->initialThread, "Identifying initial debugged thread");
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !state_->processes.emplace(id, std::move(process)).second, "Duplicate live process identifier");
			const auto image = ReadImage(
			    info.hProcess, reinterpret_cast<uint64_t>(info.lpBaseOfImage));
			ArchitectureBreakpoint::ValidateTarget(info.hProcess, image.file.Machine);
			LoadModule(info.hProcess, info.hFile, info.lpBaseOfImage);
		}
		catch (...)
		{
			if (TerminateProcess(info.hProcess, ERROR_PROCESS_ABORTED))
				DebugActiveProcessStop(id);
			throw;
		}
	}

	void RvaCoverageRunner::OnExitProcess(
	    HANDLE process, HANDLE, const EXIT_PROCESS_DEBUG_INFO&)
	{
		state_->exceptions.OnExitProcess(process);
		state_->processes.erase(ProcessId(process));
	}

	void RvaCoverageRunner::OnLoadDll(
	    HANDLE process, HANDLE, const LOAD_DLL_DEBUG_INFO& info)
	{
		LoadModule(process, info.hFile, info.lpBaseOfDll);
	}

	void RvaCoverageRunner::OnUnloadDll(
	    HANDLE process, HANDLE, const UNLOAD_DLL_DEBUG_INFO& info)
	{
		auto& live = *state_->processes.at(ProcessId(process));
		const auto base = reinterpret_cast<uint64_t>(info.lpBaseOfDll);
		live.modules.erase(base);
		live.loaders.erase(base);
	}

	void RvaCoverageRunner::LoadModule(HANDLE process, HANDLE file, void* baseAddress)
	{
		if (!file || file == INVALID_HANDLE_VALUE)
		{
			LOG_WARNING << "Skipping a module without a file handle in RVA collection";
			return;
		}
		const std::filesystem::path path{HandleInformation{}.ComputeFilename(file)};
		auto& live = *state_->processes.at(ProcessId(process));
		const auto base = reinterpret_cast<uint64_t>(baseAddress);
		const bool loader = _wcsicmp(path.filename().c_str(), L"ntdll.dll") == 0;
		const bool selected = state_->filter->IsModuleSelected(path.wstring());
		if (!loader && !selected)
			return;
		const auto remote = ReadImage(process, base);
		if (loader)
			live.loaders.emplace(base, State::Process::Loader{
			    remote.optional.SizeOfImage, LoaderBreakpoints(process, remote)});
		if (!selected)
			return;

		const PhaseClock started;
		PeImage image{path};
		const auto& identity = image.Identity();
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), remote.file.Machine != identity.machine ||
		    remote.file.TimeDateStamp != identity.timeDateStamp ||
		    remote.optional.SizeOfImage != identity.sizeOfImage ||
		    remote.optional.CheckSum != identity.checksum,
			"Loaded module does not match its on-disk PE identity: %ls", path.c_str());
		for (const auto rva : image.FunctionOverrideRelocations())
			image.ApplyFunctionOverrideRelocation(
				rva, Read<uint32_t>(process, RemoteAddress(remote, rva, 4)));
		const PhaseClock parsed;
		auto blocks = BasicBlockDiscovery{}.Discover(image);
		std::sort(blocks.begin(), blocks.end(), [](const BasicBlock& lhs, const BasicBlock& rhs)
		{
			return lhs.rva < rhs.rva;
		});
		blocks.erase(std::unique(blocks.begin(), blocks.end(), SameBlock), blocks.end());
		const PhaseClock discovered;
		try
		{
			ValidateMappedInstructionSets(process, remote, blocks);
		}
		catch (const std::exception& error)
		{
			THROW_HR_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA),
				"Unsupported mapped ISA in %ls: %hs", path.c_str(), error.what());
		}
		uint64_t end = 0;
		std::vector<State::Breakpoint> breakpoints(blocks.size());
		std::vector<uint8_t> mapped;
		uint64_t mappedAddress = 0;
		for (size_t i = 0; i < blocks.size(); ++i)
		{
			const auto& block = blocks[i];
			const auto patch = ArchitectureBreakpoint::Encoding(block.instructionSet);
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), block.size < patch.size || block.rva < end ||
			    uint64_t{block.rva} + block.size > identity.sizeOfImage ||
			    (block.instructionSet == InstructionSet::Arm64 &&
			     ((block.rva | block.size) & 3)), "Invalid or overlapping discovered basic blocks");
			end = uint64_t{block.rva} + block.size;
			std::array<uint8_t, 4> prefix{};
			for (size_t offset = 0; offset < block.size;)
			{
				const auto address = base + block.rva + offset;
				if (address < mappedAddress || address - mappedAddress >= mapped.size())
					mappedAddress = ReadCodeRange(process, remote, address, mapped);
				const auto position = static_cast<size_t>(address - mappedAddress);
				const auto size = (std::min)(size_t{block.size} - offset, mapped.size() - position);
				if (!image.MatchesMappedCode(block.rva + static_cast<uint32_t>(offset),
				                            mapped.data() + position, size, base))
				{
					std::ostringstream message;
					message << "Unsupported mapped image view in " << path.u8string()
					        << " at RVA 0x" << std::hex << block.rva + offset
					        << ": code differs from the on-disk image after ASLR normalization"
					        << " (ARM64X dynamic relocations and runtime code changes are unsupported)";
					THROW_HR_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), "%hs", message.str().c_str());
				}
				if (offset < prefix.size())
					std::memcpy(prefix.data() + offset, mapped.data() + position,
					            (std::min)(size, prefix.size() - offset));
				offset += size;
			}
			auto& breakpoint = breakpoints[i];
			breakpoint.original = prefix;
			breakpoint.status = ArchitectureBreakpoint::IsApplicationTrap(
			        block.instructionSet, prefix.data(),
			        (std::min)(size_t{block.size}, prefix.size()))
			    ? State::Breakpoint::Status::ApplicationTrap : State::Breakpoint::Status::Installed;
		}
		const PhaseClock validated;
		size_t aggregate = 0;
		auto& modules = state_->coverage.modules;
		for (; aggregate < modules.size(); ++aggregate)
			if (SameIdentity(modules[aggregate].identity, identity))
				break;
		if (aggregate == modules.size())
		{
			RvaModule module;
			module.path = path;
			module.identity = identity;
			module.blocks.reserve(blocks.size());
			for (const auto& block : blocks)
				module.blocks.push_back({block, false});
			modules.push_back(std::move(module));
		}
		else
		{
			const auto& previous = modules[aggregate].blocks;
			THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), previous.size() != blocks.size(), "Identical PE identities have different block layouts");
			for (size_t i = 0; i < blocks.size(); ++i)
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !SameBlock(previous[i].block, blocks[i]), "Identical PE identities have different block layouts");
		}
		auto inserted = live.modules.emplace(
		    base, State::Module{aggregate, identity.sizeOfImage, std::move(breakpoints)});
		THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_INVALID_DATA), !inserted.second, "A module was reloaded without an unload notification");
		auto& installed = inserted.first->second.breakpoints;
		for (size_t i = 0; i < blocks.size(); ++i)
			if (modules[aggregate].blocks[i].executed)
				installed[i].status = State::Breakpoint::Status::Uninstalled;
		std::vector<ArchitectureBreakpoint> rangePatches;
		std::vector<ArchitectureBreakpoint*> patches;
		size_t installedCount = 0;
		for (size_t i = 0; i < blocks.size();)
		{
			if (installed[i].status != State::Breakpoint::Status::Installed)
			{
				++i;
				continue;
			}
			mappedAddress = ReadCodeRange(process, remote, base + blocks[i].rva, mapped);
			rangePatches.clear();
			const auto last = std::lower_bound(
			    blocks.begin() + i, blocks.end(), mappedAddress + mapped.size() - base,
			    [](const BasicBlock& block, uint64_t value) { return block.rva < value; });
			const auto lastIndex = static_cast<size_t>(last - blocks.begin());
			rangePatches.reserve(lastIndex - i);
			for (; i < lastIndex; ++i)
			{
				if (installed[i].status != State::Breakpoint::Status::Installed)
					continue;
				ArchitectureBreakpoint::Instruction original{
				    installed[i].original, ArchitectureBreakpoint::Encoding(blocks[i].instructionSet).size};
				rangePatches.emplace_back(process, base + blocks[i].rva,
				                          blocks[i].instructionSet, original);
				++installedCount;
			}
			patches.clear();
			patches.reserve(rangePatches.size());
			for (auto& patch : rangePatches)
				patches.push_back(&patch);
			ArchitectureBreakpoint::InstallRange(process, mappedAddress, mapped, patches);
		}
		const PhaseClock finished;
		LOG_DEBUG << "RVA preparation pid=" << ProcessId(process)
		          << " module=" << path.filename().wstring()
		          << " blocks=" << blocks.size() << " installed=" << installedCount
		          << " parse_wall_ms=" << parsed.WallMillisecondsSince(started)
		          << " parse_cpu_ms=" << parsed.CpuMillisecondsSince(started)
		          << " discovery_wall_ms=" << discovered.WallMillisecondsSince(parsed)
		          << " discovery_cpu_ms=" << discovered.CpuMillisecondsSince(parsed)
		          << " validation_wall_ms=" << validated.WallMillisecondsSince(discovered)
		          << " validation_cpu_ms=" << validated.CpuMillisecondsSince(discovered)
		          << " installation_wall_ms=" << finished.WallMillisecondsSince(validated)
		          << " installation_cpu_ms=" << finished.CpuMillisecondsSince(validated);
	}

	IDebugEventsHandler::ExceptionType RvaCoverageRunner::OnException(
	    HANDLE process, HANDLE thread, const EXCEPTION_DEBUG_INFO& info)
	{
		const auto& record = info.ExceptionRecord;
		auto& live = *state_->processes.at(ProcessId(process));
		const bool breakpoint = record.ExceptionCode == EXCEPTION_BREAKPOINT ||
		                        record.ExceptionCode == EmulatedBreakpoint;
		if (breakpoint && info.dwFirstChance)
		{
			const auto address = reinterpret_cast<uint64_t>(record.ExceptionAddress);
			auto module = live.modules.upper_bound(address);
			if (module != live.modules.begin())
			{
				--module;
				if (address - module->first < module->second.size)
				{
					auto& blocks = state_->coverage.modules[module->second.aggregate].blocks;
					const auto rva = static_cast<uint32_t>(address - module->first);
					const auto hit = std::lower_bound(
					    blocks.begin(), blocks.end(), rva,
					    [](const RvaBlock& block, uint32_t value) { return block.block.rva < value; });
					if (hit != blocks.end() && hit->block.rva == rva)
					{
						auto& site = module->second.breakpoints[static_cast<size_t>(hit - blocks.begin())];
						if (site.status == State::Breakpoint::Status::Installed ||
						    site.status == State::Breakpoint::Status::Restored)
						{
							ArchitectureBreakpoint::Instruction original{
							    site.original, ArchitectureBreakpoint::Encoding(hit->block.instructionSet).size};
							ArchitectureBreakpoint patch{
							    process, address, hit->block.instructionSet, original};
							if (site.status == State::Breakpoint::Status::Installed)
							{
								patch.Restore();
								site.status = State::Breakpoint::Status::Restored;
							}
							else
								patch.VerifyRestored();
							patch.ResumeThread(thread);
							hit->executed = true;
							return ExceptionType::BreakPoint;
						}
						if (site.status == State::Breakpoint::Status::ApplicationTrap)
							hit->executed = true;
					}
				}
			}
			if (GetThreadId(thread) == live.initialThread &&
			    !live.startupBreakpointHandled)
			{
				for (const auto& loader : live.loaders)
				{
					if (address < loader.first ||
					    address - loader.first >= loader.second.size)
						continue;
					bool applicationBreakpoint = false;
					for (const auto exported : loader.second.applicationBreakpoints)
						applicationBreakpoint |=
						    address >= exported && address - exported < 16;
					if (applicationBreakpoint)
						continue;
					MEMORY_BASIC_INFORMATION memory{};
					THROW_LAST_ERROR_IF_MSG(!VirtualQueryEx(process, reinterpret_cast<void*>(address),
					                    &memory, sizeof(memory)), "Identifying initial loader breakpoint");
					if (!(memory.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
					                       PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
						continue;
					const auto first = Read<uint8_t>(process, address);
					const bool nativeTrap = (address & 3) == 0 &&
					    address - loader.first + sizeof(uint32_t) <= loader.second.size &&
					    Read<uint32_t>(process, address) == 0xd43e0000;
					if (first == 0xcc || nativeTrap)
					{
						live.startupBreakpointHandled = true;
						return ExceptionType::BreakPoint;
					}
				}
			}
			return ExceptionType::InvalidBreakPoint;
		}
		std::wostringstream message;
		switch (state_->exceptions.HandleException(process, info, message))
		{
			case ExceptionHandlerStatus::CppError:
				LOG_ERROR << message.str();
				return ExceptionType::CppError;
			case ExceptionHandlerStatus::Error:
				LOG_ERROR << message.str();
				return ExceptionType::Error;
			default: return ExceptionType::NotHandled;
		}
	}
}
