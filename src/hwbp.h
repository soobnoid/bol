#define VC_EXTRALEAN
#define WIN32_LEAN_AND_MEAN
#pragma once

#include <Windows.h>
#include <windows.h>
#include <tlhelp32.h>
#include <winnt.h>
#include <stdio.h>

enum bptCond
{
    exec      = 0b00,
    write     = 0b01,
    io        = 0b10,
    readWrite = 0b11,
};

enum bptLen
{
    oneByte    = 0b00,
    twoBytes   = 0b01,
    eightBytes = 0b10,
    fourBytes  = 0b11
};

bool unsetHWBpRegister (HANDLE thd, uintptr_t addr)
{
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; // only read debug
                                                // registers

    GetThreadContext(thd, &ctx);
    int dr = -1;
    for (int drIndex = 0; drIndex < 4; drIndex++)
    {
    if ((&ctx.Dr0)[drIndex] ==  addr)
        {
            dr = drIndex; 
            break;
        }
    }

    if(dr == -1) {return false;}

    (&ctx.Dr0)[dr] = NULL;

    ctx.Dr7 &= ~(0b11 << (16 + (4 * dr))); // RW[Dr]
    ctx.Dr7 &= ~(1 << (2 * dr));           // L[DR]

    SetThreadContext(thd, &ctx);
    return true;
}

bool unsetHWBps (uintptr_t addr) 
{
    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD pid = GetCurrentProcessId();

    if (h != INVALID_HANDLE_VALUE)
    {
        if(Thread32First(h, &te)) 
        {
            do {
                if(te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                   sizeof(te.th32OwnerProcessID) && te.th32OwnerProcessID == pid)
                    {
                        HANDLE thd = OpenThread(THREAD_ALL_ACCESS, false, te.th32ThreadID);
                        if (thd != INVALID_HANDLE_VALUE)
                        {
                            unsetHWBpRegister(thd, addr);
                        }                       
                    }
            } while (Thread32Next(h, &te));
        }
    }

    return true;
}

bool setHWBpRegister (
                      HANDLE thd, 
                      uintptr_t addr, 
                      bptCond cond
                     ) 
{
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS; // only read debug
                                                // registers

    GetThreadContext(thd, &ctx);

    int dr = -1;

    for (int drIndex = 0; drIndex < 4; drIndex++)
    {
        if(
            (&ctx.Dr0)[drIndex] == addr &&
            ((cond << (16 + (4 * drIndex))) & ctx.Dr7) == (cond << (16 + (4 * drIndex)))  
          )
            return true;
        
        if(
            (&ctx.Dr0)[drIndex] == addr &&
            ((cond << (16 + (4 * drIndex))) & ctx.Dr7) != (cond << (16 + (4 * drIndex)))  
          )
        {
            dr = drIndex; 
            break;
        }

        if ((ctx.Dr7 & (1 << (drIndex * 2))) == 0)
        {
            dr = drIndex; 
            break;
        }
    }

    if(dr == -1)
        return false;

    (&ctx.Dr0)[dr] = (DWORD64) addr;

    ctx.Dr7 &= ~(0b11 << (16 + (4 * dr)));
    ctx.Dr7 &= ~(0b11 << (18 + (4 * dr)));

    ctx.Dr7 |= (cond << (16 + (4 * dr))); 
    ctx.Dr7 |= 1 << (2 * dr);

    SetThreadContext(thd, &ctx);
    return true;
}

bool setHWBps (uintptr_t addr, bptCond cond) 
{
    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD pid = GetCurrentProcessId();

    if (h != INVALID_HANDLE_VALUE)
    {
        if(Thread32First(h, &te)) 
        {
            do {
                if(te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) +
                   sizeof(te.th32OwnerProcessID) && te.th32OwnerProcessID == pid)
                    {
                        HANDLE thd = OpenThread(THREAD_ALL_ACCESS, false, te.th32ThreadID);
                        if (thd != INVALID_HANDLE_VALUE)
                        {
                            if(!setHWBpRegister(thd, addr, cond))
                            {
                                return false;
                            }
                        }                       
                    }
            } while (Thread32Next(h, &te));
        }
    }

    return true;
}
