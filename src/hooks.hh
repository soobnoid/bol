#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN
#pragma once

#include <Windows.h>
#include <map>

#include "hwbp.h"
#include "jmp.h"
#include "trampoline.hh"

enum bptType
{
    HARDWARE_BREAKPOINT,
    INT3_BREAKPOINT
};

typedef void (*hookFunc)(PCONTEXT);

class BptInfo
{
    public:
        bptCond cond;
        bptType type;
        uintptr_t addr;

        BOOL enabled; 
        hookFunc hook;
        
        BOOL triggered;

        // for returning
        JmpOut* trampoline;

        // only for INT3 breakpoints
        BYTE orig;
        
        constexpr BptInfo (
                           bptCond Cond,
                           bptType Type,
                           uintptr_t Addr,
                           BOOL Enabled, 
                           hookFunc Hook
                          )
          : cond (Cond)
          , type (Type)
          , addr (Addr)
          , enabled (Enabled)
          , triggered (false)
          , hook (Hook)
          , trampoline (nullptr)
          , orig (NULL)
        {}
};

// global class that the veh handler can easily
// reference. Don't define another one.

typedef enum REMOVE_BREAKPOINT_COND
{
    SUCCESS,
    BREAKPOINT_DIDNT_EXIST,
    BREAKPOINT_EXISTS_REMOVAL_FAILED
};

class Debugger
{
    public:

        BOOL initialized;
        std::map<uintptr_t, BptInfo>* breakpoints;

        constexpr Debugger () 
          : breakpoints {nullptr}
          , initialized (false)
        {}     

        BptInfo* operator [] (uintptr_t addr)
        {
            if(breakpoints->find(addr) != breakpoints->end())
                return nullptr;
        
            return &breakpoints->at(addr);
        }

        BOOL init () 
        {
            breakpoints = new std::map<uintptr_t, BptInfo>;
            return breakpoints != nullptr;
        }   

        REMOVE_BREAKPOINT_COND removeBpt (uintptr_t addr)
        {
            if(breakpoints->find(addr) != breakpoints->end())
                return BREAKPOINT_DIDNT_EXIST;

            BptInfo* bpt = &breakpoints->at(addr);
            switch (bpt->type)
            {
                case (HARDWARE_BREAKPOINT):
                    if(unsetHWBps(addr))
                    {
                        delete bpt->trampoline;
                        breakpoints->erase(addr);
                        return SUCCESS;
                    }
                    else 
                        return BREAKPOINT_EXISTS_REMOVAL_FAILED;
                    break;

                case (INT3_BREAKPOINT):
                    DWORD oldProtect;
                    if(
                        VirtualProtect(
                            (LPVOID)addr,
                            1,
                            PAGE_READWRITE,
                            &oldProtect
                        )
                      )
                    {
                        *(BYTE *)addr = bpt->orig;

                        VirtualProtect(
                            (LPVOID)addr,
                            1,
                            oldProtect,
                            &oldProtect
                        );

                        delete bpt->trampoline;
                        breakpoints->erase(addr);
                    }
                    break;
            }
        }

        BOOL addBpt (BptInfo bpt)
        {
            if(breakpoints->find(bpt.addr) != breakpoints->end())
                return false;

            switch (bpt.type)
            {
                case (HARDWARE_BREAKPOINT):
                    if(setHWBps(bpt.addr, bpt.cond))
                    {
                        bpt.trampoline = new JmpOut(bpt.addr);
                        bpt.enabled = true;
                        breakpoints->insert({bpt.addr, bpt});
                        return true;
                    }
                    else
                        return false;
                    break;

                case (INT3_BREAKPOINT):
                    DWORD oldProtect;
                    if(
                        VirtualProtect(
                            (LPVOID)bpt.addr,
                            1,
                            PAGE_READWRITE,
                            &oldProtect
                        )
                      )
                    {
                        bpt.trampoline = new JmpOut(bpt.addr);
                        bpt.enabled = true;

                        bpt.orig = *(BYTE *)bpt.addr;
                        *(BYTE *) bpt.addr = 0xCC;

                        VirtualProtect(
                            (LPVOID)bpt.addr,
                            1,
                            oldProtect,
                            &oldProtect
                        );

                        breakpoints->insert({bpt.addr, bpt});
                        return true;
                    }
                    break;

            }
        }


        
};

typedef Debugger* pDebugger;
constexpr pDebugger debugger;


LONG CALLBACK veh_handler(PEXCEPTION_POINTERS ExceptionInfo)
{
    DWORD code = ExceptionInfo->ExceptionRecord->ExceptionCode;
    PCONTEXT ctx = ExceptionInfo->ContextRecord;

    //printContext(ctx);

    if (code == STATUS_BREAKPOINT) // software breakpoint
    {
        if ((*debugger)[ctx->Rip])
        {
            BptInfo * bpt = (*debugger)[(uintptr_t)ctx->Rip];
            
            bpt->triggered = true;
            if (bpt->enabled)
                bpt->hook(ctx);
            bpt->triggered = false;

            // account for hooking a possible
            // branching instruction.

            ctx->Rip = (DWORD64)bpt->trampoline;

            if(bpt->trampoline->branch)
            {
                if(jmpTaken(bpt->trampoline->insnMnemonic, ctx))
                {
                    ctx->Rip = (DWORD64)bpt->trampoline->branch;
                }
            }
                        
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}
