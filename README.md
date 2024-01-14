# Yet another windows hooking utility

*100% completely unrelated to any older project.*

Unlike other hooking libraries, this one generates trampolines dynamically using Zydis, meaning that the hardware/software breakpoint does not need to be removed. look at `trampoline.h` for more details. To ensure better reliability, for hardware breakpoints you can hook thread creation routines like in this repo https://github.com/rad9800/hwbp4mw, but I didn't need that for my purposes so I have not included it in this repo.

# dependancies
* Zydis
