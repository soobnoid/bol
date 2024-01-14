#define WIN32_LEAN_AND_MEAN
#pragma once

#include <Windows.h>
#include <stdio.h>

#include "jmp.h"

#include <Zydis/Zydis.h>

class JmpOut
{
    public:
        #define NOP 0x90
    
        BYTE oldInsn [15] = {NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP, NOP}; // subject to change.
        BYTE setStack [4] = {0x48, 0x83, 0xec, 0x08};                     // sub rsp, 8
        BYTE mov1 [7] = {0xc7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00};       // mov [rsp], lower_half
        BYTE mov2 [8] = {0xc7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00}; // mov [rsp + 4], upper_half
        BYTE popRax [2] = {0x41, 0x5b};                                   // pop r11
        BYTE jmpRax [3] = {0x41, 0xff, 0xe3};                             // jmp r11

        JmpOut * branch;
        DWORD oldProtect;

        ZydisMnemonic insnMnemonic;

        void _init (uintptr_t addr)
        {
            UINT32 lodword = (UINT32) addr;
            UINT32 hidword = (UINT32)(addr >> 32);

            *((UINT32 *) &(mov1[3])) = lodword;
            *((UINT32 *) &(mov2[4])) = hidword; 

            // the shellcode is 39 bytes
            VirtualProtect((void *)(&oldInsn), 39, PAGE_EXECUTE_READ, &oldProtect);
        }

        enum branchingType {NO_BRANCH, STATIC_JMP, BRANCHING_JMP}; 

        JmpOut () {}

        JmpOut (uintptr_t disassAddr)
        {
            uintptr_t addr;
            ZydisDisassembledInstruction insn;

            bool res = ZYAN_SUCCESS(ZydisDisassembleIntel( 
                ZYDIS_MACHINE_MODE_LONG_64, 
                (ZyanU64) disassAddr, 
                (void *) disassAddr, 
                15, 
                &insn
            ));

            if(res)
            {
                branchingType branchInfo = NO_BRANCH;
                ZydisDecodedInstruction insnInfo = insn.info;
                insnMnemonic = insnInfo.mnemonic; 

                for(int i = 0; i < sizeof(branchingJmps); i++)
                {
                    if(insnMnemonic == branchingJmps[i]) 
                    {
                        branchInfo = BRANCHING_JMP; 
                        break;
                    }
                } 

                if (insnMnemonic == ZYDIS_MNEMONIC_JMP || insnMnemonic == ZYDIS_MNEMONIC_CALL)
                {
                    branchInfo = STATIC_JMP;
                }

                if(branchInfo == BRANCHING_JMP || branchInfo == STATIC_JMP)
                {
                    uintptr_t branch_addr;

                    for (int i = 0; i < insnInfo.operand_count; i++)
                    {
                        ZydisDecodedOperand op = insn.operands[i];
                        if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                        {
                            if(branchInfo == BRANCHING_JMP)
                            {
                                branch = new JmpOut();
                                branch->_init(disassAddr + op.imm.value.s);
                                addr = disassAddr + insnInfo.length;
                            }

                            else {addr = disassAddr + op.imm.value.s;}
                        }
                    }
                }

                else {addr = disassAddr + insnInfo.length;}
                _init(addr);
            }

            else {printf("dissasembly error\n");}
        }

        ~JmpOut () {VirtualProtect((void *)(&oldInsn), 39, oldProtect, &oldProtect);}

        #undef NOP
};