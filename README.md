# Yet another windows hooking utility

*100% completely not a rewrite of a certain old project.*

Unlike other hooking libraries, this one generates trampolines dynamically using Zydis, meaning that the hardware/software breakpoint does not need to be removed. if the hooked function starts with a jmp instruction, the trampoline generator will generate a trampoline for the single branch, or both branches and evaluate which one is taken at runtime. look at `trampoline.h` for more details. To ensure better reliability, for hardware breakpoints you can hook thread creation routines like in this repo https://github.com/rad9800/hwbp4mw, but I didn't need that for my purposes so I have not included it in this repo.

# TODO 
* upload examples
* page guard hooks

# dependancies
* Zydis
