#include "BasicBlockDiscovery.hpp"

#include <Windows.h>
#include <wil/result.h>

#include <capstone/capstone.h>

#if CS_API_MAJOR != 5
#error Basic-block discovery requires the Capstone 5 stable API.
#endif

#include <algorithm>
#include <deque>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>

namespace CppCoverage
{
	namespace
	{
		constexpr size_t MaxInstructions = 4u * 1024u * 1024u;

		class Decoder
		{
		public:
			explicit Decoder(InstructionSet instructionSet)
			{
				int major = 0;
				int minor = 0;
				cs_version(&major, &minor);
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED),
					major != 5, "Basic-block discovery requires Capstone runtime version 5");
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED),
					cs_support(CS_SUPPORT_DIET), "Basic-block discovery requires a non-diet Capstone build");
				const auto error = cs_open(instructionSet == InstructionSet::Amd64 ?
					CS_ARCH_X86 : CS_ARCH_ARM64,
					instructionSet == InstructionSet::Amd64 ? CS_MODE_64 : CS_MODE_ARM, &handle_);
				THROW_HR_IF_MSG(E_FAIL, error != CS_ERR_OK, "Cannot initialize Capstone decoder");
				if (cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
				{
					cs_close(&handle_);
					THROW_HR_MSG(HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED),
						"Capstone instruction details are unavailable");
				}
				instruction_ = cs_malloc(handle_);
				if (!instruction_)
				{
					cs_close(&handle_);
					THROW_HR_MSG(E_OUTOFMEMORY, "Cannot allocate Capstone instruction");
				}
			}

			~Decoder()
			{
				cs_free(instruction_, 1);
				cs_close(&handle_);
			}

			Decoder(const Decoder&) = delete;
			Decoder& operator=(const Decoder&) = delete;

			const cs_insn* Decode(PeCodeView code, uint32_t rva)
			{
				const auto* bytes = code.data;
				auto size = (std::min)(code.size,
					code.instructionSet == InstructionSet::Amd64 ? size_t{15} : size_t{4});
				uint64_t address = rva;
				if (!cs_disasm_iter(handle_, &bytes, &size, &address, instruction_) ||
					!instruction_->detail || !instruction_->size)
					return nullptr;
				return instruction_;
			}

		private:
			csh handle_ = 0;
			cs_insn* instruction_ = nullptr;
		};

		bool Group(const cs_insn& instruction, uint8_t group)
		{
			const auto& detail = *instruction.detail;
			return std::find(detail.groups, detail.groups + detail.groups_count, group) !=
				detail.groups + detail.groups_count;
		}

		bool Conditional(const cs_insn& instruction, InstructionSet instructionSet)
		{
			if (instructionSet == InstructionSet::Amd64)
				return instruction.id != X86_INS_JMP && instruction.id != X86_INS_LJMP;
			switch (instruction.id)
			{
			case ARM64_INS_CBZ:
			case ARM64_INS_CBNZ:
			case ARM64_INS_TBZ:
			case ARM64_INS_TBNZ:
				return true;
			case ARM64_INS_B:
			{
				const auto condition = instruction.detail->arm64.cc;
				return condition != ARM64_CC_INVALID && condition != ARM64_CC_AL &&
					condition != ARM64_CC_NV;
			}
			default:
				return false;
			}
		}

		bool Terminates(const cs_insn& instruction, InstructionSet instructionSet)
		{
			if (Group(instruction, CS_GRP_RET) || Group(instruction, CS_GRP_IRET) ||
				Group(instruction, CS_GRP_INT))
				return true;
			if (instructionSet == InstructionSet::Amd64)
				return instruction.id == X86_INS_HLT || instruction.id == X86_INS_UD0 ||
					instruction.id == X86_INS_UD1 || instruction.id == X86_INS_UD2 ||
					instruction.id == X86_INS_SYSRET || instruction.id == X86_INS_SYSRETQ ||
					instruction.id == X86_INS_SYSEXIT || instruction.id == X86_INS_SYSEXITQ ||
					instruction.id == X86_INS_XABORT;
			return instruction.id == ARM64_INS_BRK || instruction.id == ARM64_INS_HLT ||
				instruction.id == ARM64_INS_UDF || instruction.id == ARM64_INS_SVC ||
				instruction.id == ARM64_INS_HVC || instruction.id == ARM64_INS_SMC ||
				instruction.id == ARM64_INS_ERET || instruction.id == ARM64_INS_ERETAA ||
				instruction.id == ARM64_INS_ERETAB || instruction.id == ARM64_INS_DRPS ||
				instruction.id == ARM64_INS_DCPS1 || instruction.id == ARM64_INS_DCPS2 ||
				instruction.id == ARM64_INS_DCPS3;
		}

		bool DirectTarget(const cs_insn& instruction, InstructionSet instructionSet,
			uint32_t& rva)
		{
			int64_t target = -1;
			if (instructionSet == InstructionSet::Amd64)
			{
				const auto& detail = instruction.detail->x86;
				if (detail.op_count == 1 && detail.operands[0].type == X86_OP_IMM)
					target = detail.operands[0].imm;
			}
			else
			{
				const auto& detail = instruction.detail->arm64;
				for (size_t i = detail.op_count; i != 0; --i)
					if (detail.operands[i - 1].type == ARM64_OP_IMM)
					{
						target = detail.operands[i - 1].imm;
						break;
					}
			}
			if (target < 0 || static_cast<uint64_t>(target) >
				(std::numeric_limits<uint32_t>::max)())
				return false;
			rva = static_cast<uint32_t>(target);
			return true;
		}

		bool ImportReference(const PeImage& image, const cs_insn& instruction,
			uint32_t& target)
		{
			const auto& detail = instruction.detail->x86;
			if (detail.op_count != 1 || detail.operands[0].type != X86_OP_MEM)
				return false;
			const auto& memory = detail.operands[0].mem;
			if (memory.index != X86_REG_INVALID ||
				(memory.segment != X86_REG_INVALID && memory.segment != X86_REG_DS))
				return false;
			uint32_t slot = 0;
			if (memory.base == X86_REG_RIP)
			{
				const auto address = static_cast<int64_t>(instruction.address) +
					instruction.size + memory.disp;
				if (address < 0 || static_cast<uint64_t>(address) >
					(std::numeric_limits<uint32_t>::max)())
					return false;
				slot = static_cast<uint32_t>(address);
			}
			else if (memory.base != X86_REG_INVALID ||
				!image.VaToRva(static_cast<uint64_t>(memory.disp), slot))
				return false;
			return image.IsImportSlot(slot) && image.ImportTarget(slot, target);
		}

		struct DecodedInstruction
		{
			uint16_t size;
			InstructionSet instructionSet;
			bool endsBlock;
		};
	}

	std::vector<BasicBlock> BasicBlockDiscovery::Discover(const PeImage& image) const
	{
		std::unique_ptr<Decoder> amd64;
		std::unique_ptr<Decoder> arm64;
		std::map<uint32_t, DecodedInstruction> decoded;
		std::set<uint32_t> leaders;
		std::deque<uint32_t> pending;
		const auto enqueue = [&](uint32_t rva)
		{
			if (!image.GetCode(rva).data)
				return;
			auto next = decoded.upper_bound(rva);
			if (next != decoded.begin())
			{
				const auto previous = std::prev(next);
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), rva - previous->first < previous->second.size && rva != previous->first, "Control flow targets the middle of an instruction");
			}
			if (leaders.insert(rva).second)
			{
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), leaders.size() > MaxInstructions, "Basic-block discovery exceeds the instruction limit");
				pending.push_back(rva);
			}
		};
		for (const auto root : image.Roots())
			enqueue(root);

		while (!pending.empty())
		{
			auto rva = pending.front();
			pending.pop_front();
			while (decoded.find(rva) == decoded.end())
			{
				const auto code = image.GetCode(rva);
				if (!code.data)
					break;
				auto& decoder = code.instructionSet == InstructionSet::Amd64 ? amd64 : arm64;
				if (!decoder)
					decoder = std::make_unique<Decoder>(code.instructionSet);
				const auto* instruction = decoder->Decode(code, rva);
				if (!instruction || instruction->size > code.size ||
					(code.instructionSet == InstructionSet::Arm64 && instruction->size != 4))
					break;
				if (instruction->size > (std::numeric_limits<uint32_t>::max)() - rva)
					break;
				const auto nextRva = rva + instruction->size;
				const auto nextDecoded = decoded.lower_bound(rva);
				const auto nextLeader = leaders.upper_bound(rva);
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), (nextDecoded != decoded.end() && nextDecoded->first < nextRva) ||
					(nextLeader != leaders.end() && *nextLeader < nextRva), "Overlapping instruction decodes");

				const bool call = Group(*instruction, CS_GRP_CALL);
				const bool branch = Group(*instruction, CS_GRP_JUMP);
				const bool stop = Terminates(*instruction, code.instructionSet);
				const bool conditional = branch && Conditional(*instruction, code.instructionSet);
				THROW_HR_IF_MSG(HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT), decoded.size() >= MaxInstructions, "Basic-block discovery exceeds the instruction limit");
				decoded.emplace(rva, DecodedInstruction{instruction->size,
					code.instructionSet, call || branch || stop});
				if (call || branch)
				{
					uint32_t target = 0;
					if (DirectTarget(*instruction, code.instructionSet, target) ||
						(code.instructionSet == InstructionSet::Amd64 &&
							ImportReference(image, *instruction, target)))
						enqueue(target);
					if (call || conditional)
						enqueue(nextRva);
					break;
				}
				if (stop)
					break;
				const auto nextCode = image.GetCode(nextRva);
				if (!nextCode.data || nextCode.instructionSet != code.instructionSet)
					break;
				rva = nextRva;
			}
		}

		std::vector<BasicBlock> blocks;
		for (auto it = decoded.begin(); it != decoded.end();)
		{
			const auto first = it->first;
			const auto instructionSet = it->second.instructionSet;
			auto end = first;
			for (;;)
			{
				end = it->first + it->second.size;
				const auto endsBlock = it->second.endsBlock;
				++it;
				if (it == decoded.end() || endsBlock || it->first != end ||
					it->second.instructionSet != instructionSet || leaders.count(it->first))
					break;
			}
			blocks.push_back({first, end - first, instructionSet});
		}
		return blocks;
	}
}
