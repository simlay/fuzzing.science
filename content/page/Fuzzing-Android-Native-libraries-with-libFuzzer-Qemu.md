---
title: Fuzzing Android Native libraries with libFuzzer + QEMU
# subtitle: Fuzzing Android Native libraries with libFuzzer + QEMU
comments: false
draft: false
bigimg: [{src: "/img/exploitable.png", desc: "exploitable"}]
tags: [fuzzing, libfuzzer, qemu, sloth]
categories: [development, fuzzing]
date: 2021-06-19
---

# Fuzzing Android Native libraries with libFuzzer + QEMU 🦥

**TL;DR** In this blog post, I will go through the process of why and how I built a new framework called `Sloth` 🦥, using which, I was able to fuzz Android Native libraries with libFuzzer and QEMU. You will see me talking about QEMU internals, and showcasing my patches. Finally you will see the running demo of my `Sloth` framework to perform the fuzzing for `Skia` library.

## Introduction aka how it all started...

Initially, my goal was to build a tool to fuzz Android native libraries with libfuzzer and QEMU to perform binary-only code-coverage fuzzing. I checked if someone has already worked on this, but I couldn't find any such public implementations. So, to achieve this, I decided to patch QEMU and libFuzzer and dug deep into some internals of QEMU, QEMU TCG, ELF loaders, libFuzzer's custom coverage. In doing so, I built `Sloth`🦥 framework which I can use to fuzz Android Native libraries.

> I want to make use of QEMU’s user-mode emulation (`qemu-linux-user`. let's call this QUME 🤔) on `x86_64` host to emulate aarch64 Android libraries and I want my final harness to be look like this

```c
import <the target library here>

extern "C" int libQEMUFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
{
    targetFunction(Data, Size);
}
```

## QEMU Internals

I'm just gonna give a really basic introduction to QEMU internals and it's source code (PS: I'm no expert in QEMU 🧐). I'm sure there are other awesome resources related to QEMU internals (eg: [QEMU internals by airbus-seclab](https://airbus-seclab.github.io/qemu_blog/)). 

* Let's clone the source of latest QEMU (QEMU 5.1.0) from github using the following commands

```sh
➜  git clone --depth 1 --branch v5.1.0 https://github.com/qemu/qemu
➜  cd qemu/
➜  qemu > git submodule init
➜  qemu > git submodule update
```

> When we compile, QUME, the main folder that's resposible for loading ELF into memory, cpu execution loop and syscall handlers is `linux-user`. Folder looks something like this (stripped irrelevant directories from the output):

```sh
➜  > cd qemu/linux-user/
➜  linux-user > tree .
.
|____linuxload.c
|____uname.h
|____mmap.c
|____exit.c
|____fd-trans.h
|____elfload.c
|____syscall.c
|____trace.h
|____main.c                         
|____syscall_types.h
|____cpu_loop-common.h
|____syscall_defs.h
|____arm
| |____cpu_loop.c
| |____target_structs.h
| |____termbits.h
| |____target_elf.h
| |____syscallhdr.sh
| |____nwfpe
| | |____fpa11_cpdo.c
| | |____fpopcode.h
| | |____fpa11_cprt.c
| | |____double_cpdo.c
...
| |____target_syscall.h
| |____target_fcntl.h
| |____meson.build
| |____target_signal.h
| |____syscall.tbl
| |____sockbits.h
| |____signal.c
| |____target_cpu.h
|____aarch64
| |____cpu_loop.c
| |____target_structs.h
| |____termbits.h
| |____target_elf.h
| |____target_syscall.h
| |____target_fcntl.h
| |____target_signal.h
| |____sockbits.h
| |____signal.c
| |____syscall_nr.h
| |____target_cpu.h
|____socket.h
|____uaccess.c
|____ioctls.h
|____semihost.c
|____qemu.h
|____fd-trans.c
...
```

Here, `main.c` has the `main` function implementation for `linux-user`, `syscall.c` is responsible for syscall implementation, `elfload.c` is responsible for parsing and loading ELF into memory and `cpu_loop.c` inside `aarch64` folder is responsible for cpu_exec of `aarch64` architecture.

### QEMU Internals - The Tiny Code Generator (TCG)

The Tiny Code Generator (TCG) is responsible to transform target instructions (the processor being emulated, in our case `aarch64`) into host instructions (the processor executing QEMU itself, in our case `x86_64`). A TCG frontend lifts native target instructions into an architecture-independent intermediate representation (IR). A TCG backend then lowers the IR into native host instructions. The translation is done on-the-fly during emulation at the basic block level.

* The code for the TCG resides in `qemu/tcg/`

```sh
➜  cd qemu/tcg/
➜  tcg git:(609d759) ✗ tree .
.
|____tci
| |____tcg-target.c.inc
| |____tcg-target.h
| |____README
| |____tcg-target-con-set.h
| |____tcg-target-con-str.h
|____tcg-op-gvec.c
|____tcg-pool.c.inc
|____i386
| |____tcg-target.c.inc
| |____tcg-target.h
| |____tcg-target-con-set.h
| |____tcg-target-con-str.h
| |____tcg-target.opc.h
....
|____tcg.c
....
|____tci.c
|____README
....
|____tcg-op.c
|____optimize.c
|____tcg-common.c
|____tcg-op-vec.c
|____arm
| |____tcg-target.c.inc
| |____tcg-target.h
| |____tcg-target-con-set.h
| |____tcg-target-con-str.h
....
|____aarch64
| |____tcg-target.c.inc
| |____tcg-target.h
| |____tcg-target-con-set.h
| |____tcg-target-con-str.h
| |____tcg-target.opc.h
....
|____tcg-ldst.c.inc
```

> The code I patched in QEMU’s user-mode emulation recides inside `linux-user` folder. The execution of QUME starts from `main.c` (`int main(int argc, char **argv, char **envp)`) inside `qemu/linux-user/`. 

* High level execution flow of QUME:

![QEMU linux-user flow](../../img/qemu_linux-user_main.png)

* The interesting function to start with from the above flow is [`cpu_exec`](https://github.com/qemu/qemu/blob/v6.0.0/accel/tcg/cpu-exec.c#L715)

```c
int cpu_exec(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu);
    int ret;
    SyncClocks sc = { 0 };

    /* replay_interrupt may need current_cpu */
    current_cpu = cpu;

    ....

    /* if an exception is pending, we execute it here */
    while (!cpu_handle_exception(cpu, &ret)) {
        TranslationBlock *last_tb = NULL;
        int tb_exit = 0;

        while (!cpu_handle_interrupt(cpu, &last_tb)) {
            uint32_t cflags = cpu->cflags_next_tb;
            TranslationBlock *tb;

            ....

            tb = tb_find(cpu, last_tb, tb_exit, cflags);
            cpu_loop_exec_tb(cpu, tb, &last_tb, &tb_exit);

            ....
        }
    }

    cpu_exec_exit(cpu);    
```

> In `cpu_exec`, QEMU first tries to look for existing TBs inside TB Cache, by calling `tb_find`. If there's no entry for the current location, it generates a new one with [`tb_gen_code`](https://github.com/qemu/qemu/blob/v6.0.0/accel/tcg/translate-all.c#L1844). When a TB is found, QEMU runs it with `cpu_loop_exec_tb` which in short calls `cpu_tb_exec` and then `tcg_QEMU_tb_exec`. At this point our target code has been translated to host code, QEMU can run it directly on the host CPU.

## QEMU Patches

Perfect!

With this basic understanding of QUME, we know that instrumentation for code-coverage fuzzing can be achived by making use of TBs inside `tb_gen_code`.

<img src="../../img/cpu_exec.png" alt="TB-Code-Coverage" width="200"/>

I made use of the `afl_maybe_log` and `afl_gen_trace` code from [aflplusplus](https://github.com/AFLplusplus/QEMUafl/blob/master/accel/tcg/translate-all.c#L71). I did not add probabilistic instrumentation implemendted in aflplusplus for now.

Added the following code to `accel/tcg/translate-all.c` file, and call `afl_gen_trace` function inside `tb_gen_code` before `trace_translate_block` function call. (PS: QEMU provides trace-events to trace all the TB executions using `trace_translate_block`)

```c
#defined AFL_QEMU_NOT_ZERO

/* coverage bitmap */
extern unsigned char *afl_area_ptr;

/* NeverZero */

#if (defined(__x86_64__) || defined(__i386__)) && defined(AFL_QEMU_NOT_ZERO)
  #define INC_AFL_AREA(loc)           \
    asm volatile(                     \
        "addb $1, (%0, %1, 1)\n"      \
        "adcb $0, (%0, %1, 1)\n"      \
        : /* no out */                \
        : "r"(afl_area_ptr), "r"(loc) \
        : "memory", "eax")
#else
  #define INC_AFL_AREA(loc) afl_area_ptr[loc]++
#endif

void HELPER(afl_maybe_log)(target_ulong cur_loc) {

  register uintptr_t afl_idx = cur_loc ^ afl_prev_loc;

  INC_AFL_AREA(afl_idx);

  afl_prev_loc = cur_loc >> 1;

}

/* Generates TCG code for AFL's tracing instrumentation. */
static void afl_gen_trace(target_ulong cur_loc) {

  /* Looks like QEMU always maps to fixed locations, so ASLR is not a
     concern. Phew. But instruction addresses may be aligned. Let's mangle
     the value to get something quasi-uniform. */

  cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
  cur_loc &= MAP_SIZE - 1;

  TCGv cur_loc_v = tcg_const_tl(cur_loc);
  gen_helper_afl_maybe_log(cur_loc_v);
  tcg_temp_free(cur_loc_v);
}
```

* Add the following line to `accel/tcg/tcg-runtime.h`

```c
DEF_HELPER_FLAGS_1(afl_maybe_log, TCG_CALL_NO_RWG, void, tl)
```


Since libFuzzer is in-process, I would ideally want to launch QEMU only once per process and fuzz the target function from target library in-process. To make it work, I had to adjust the elf loader in QUME. In an ELF loader, when there's an interpreter, the Loader first jumps to the start of `interp_entry`. After loading all the dependent libraries, the execution is set to `elf_entry`. After finishing this execution, QUME exits.

To keep the fuzzing in-process, I patched few things:

- added a new variable `end_addr` to `struct CPUARMState` (`env` variable)
- patched `disas_a64_insn` function inside `target/arm/translate-a64.c` to exit cpu_loop when the `pc == end_addr`. (this is the same way Unicorn `uc_emu_start` `until` works)
- patch `loader_exec` and add a new function `run_linker`
- in `run_linker`, set `regs->pc` to `infop->interp_entry & ~0x3ULL;`
- set `env->end_addr` to `infop->entry`. This'll make sure the execution will stop after executing only the `interpreter`
- execute `cpu_loop`.
- reset TB Cache `tb_flush(cpu);` to get rid of the above `env->end_addr`
- set `env->addr_end` to 0.
- fetches pointer to `libQEMUFuzzerTestOneInput` from loaded target library

> By the time the execution reaches the last step in the above flow, all the dependent libraries of the ELF should be loaded in memory. Now I fetch the pointer to `libQEMUFuzzerTestOneInput` from the harness library by calling the `libQEMUDlsym` function and pass it to `libFuzzerStart`.

* Changes to `main.c` code:

```c
...
    env->addr_end = info->entry; // we execute linker, i.e. till elf_entry
    env->elf_entry = info->entry;
    env->interp_entry = info->interp_entry;

    cpu_loop(env);
    
    //reset cache
    cpu->halted = 0;
    tb_flush(cpu);
    env->addr_end = 0;

    target_addr = libQEMUDlsym("libQEMUFuzzerTestOneInput");

    // const uint8_t *h = NULL;
    argc = argc-1;
    argv[1] = argv[2];
    libFuzzerStart(argc, argv, LLVMFuzzerTestOneInput);
...
```

* And inside `LLVMFuzzerTestOneInput`, I just assign the required registers to point to Data and Size and call `libQEMUFuzzerTestOneInput`

```c
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) 
{
    previousLoc = 0;
    thread_cpu->halted = 0;

    regs->regs[0] = Data;
    regs->regs[1] = Size;
    regs->pc = target_addr & ~0x3ULL;

    target_cpu_copy_regs(env, regs);
    cpu_loop(env);    
    return 0;
}
```

* Final folder structure of Sloth

<img src="../../img/sloth_folder_structure.png" alt="Sloth-folder-structure" width="400"/>

* In `sloth.c`, i just call `libQEMUInit` from QUME to start execution

```c
int main(int argc, char* argv[], char* envp[])
{
    DBGLOGN("==== SLOTH ====");

    afl_area_ptr = (unsigned char *) malloc(sizeof(uint8_t)* MAP_SIZE);
    memset(afl_area_ptr, 0, sizeof(uint8_t)* MAP_SIZE);

    //start fuzzing
    libQEMUInit(argc, argv, envp);
    ...
}
```

## Sloth Demo - 🦥

> `Sloth` is a fuzzing framework I made to fuzz Android Native libraries with libFuzzer and QEMU 

* Build the Sloth docker image

```sh
export image="sloth:v1"
docker build -t $image .
docker run --rm -v `pwd`/:/home -v `pwd`/resources:/android -it $image bash
```

* I made a simple [library](https://gist.github.com/ant4g0nist/8d761d105f45033f3c704dfaea6e765a) to fuzz.

```sh
root@4558d8a05c92:/android/examples/Sample# ls
jni  seeds
root@4558d8a05c92:/android/examples/Sample# cd jni/
root@4558d8a05c92:/android/examples/Sample/jni# ls
Android.mk  Application.mk  Makefile  boo.cpp  lib

root@4558d8a05c92:/android/examples/Sample/jni# ls lib/
fuzz.cpp  fuzz.h  include
```

* Target library

```sh
root@4558d8a05c92:/android/examples/Sample/jni# cat lib/fuzz.cpp 
#define SK_BUILD_FOR_ANDROID

#include <stdio.h>
#include <stdint.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "fuzz.h"

extern "C" int libQEMUFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

	if (Size <5 && Size > 4096)
		return 0;

	if(Data[0] == 0x41)
	{
		if(Data[1] == 0x42)
		{
			if(Data[2] == 0x43)
			{
				if(Data[4] == 0x44)
				{
					if(Data[5] == 0x45)
					{
                        //crash here
						char * ptr = (char*) 0x61616161;
						ptr[0]=0;
					}
					
				}
				
			}
			
		}

	}

	return 0;
}
```

* Compile the target and copy libBooFuzz.so and boofuzz to `/android/rootfs/system/lib64/` and `/android/rootfs/` respectively

```sh
root@4558d8a05c92:/android/examples/Sample/jni# make
ndk-build
make[1]: Entering directory '/android/examples/Sample/jni'
Android NDK: APP_PLATFORM not set. Defaulting to minimum supported version android-16.    
Android NDK: WARNING:/android/examples/Sample/jni/Android.mk:BooFuzz: non-system libraries in linker flags: -lhwui    
Android NDK:     This is likely to result in incorrect builds. Try using LOCAL_STATIC_LIBRARIES    
Android NDK:     or LOCAL_SHARED_LIBRARIES instead to list the library dependencies of the    
Android NDK:     current module    
Android NDK: WARNING:/android/examples/Sample/jni/Android.mk:boofuzz: non-system libraries in linker flags: -landroidicu -lGLESOverlay -lBooFuzz -landroidicu -lhwui    
Android NDK:     This is likely to result in incorrect builds. Try using LOCAL_STATIC_LIBRARIES    
Android NDK:     or LOCAL_SHARED_LIBRARIES instead to list the library dependencies of the    
Android NDK:     current module    
make[1]: Leaving directory '/android/examples/Sample/jni'
make[1]: Entering directory '/android/examples/Sample/jni'
[arm64-v8a] Install        : libBooFuzz.so => libs/arm64-v8a/libBooFuzz.so
[arm64-v8a] Install        : boofuzz => libs/arm64-v8a/boofuzz
make[1]: Leaving directory '/android/examples/Sample/jni'

root@4558d8a05c92:/android/examples/Sample/jni# cp ../libs/arm64-v8a/boofuzz /android/rootfs/

root@4558d8a05c92:/android/examples/Sample/jni# cp ../libs/arm64-v8a/libBooFuzz.so /android/rootfs/system/lib64/
```

* Finally, I can fuzz

<img src="../../img/slot_boofuzz_example.png" alt="sloth sample boofuzz crash"/>

Yayyy, it works !!!! 🧐🧐🧐🧐🧐🕺🕺🕺🕺

## Skia fuzzer - Sloth

Bonus, I also tried to fuzz Skia Image parsing by porting the harness made by [j00ru](https://twitter.com/j00ru), [SKCodecFuzzer](https://github.com/googleprojectzero/SkCodecFuzzer), to the new `Sloth`. 

Final code for the port of `SKCodecFuzzer` to `Sloth`:

```c
//just a quick port of the SKCodecFuzzer harness by j00ru

#define SK_BUILD_FOR_ANDROID

#include <stdio.h>
#include <stdint.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "fuzz.h"
#include "include/codec/SkAndroidCodec.h"
#include "include/core/SkBitmap.h"
#include "include/codec/SkCodec.h"
#include "include/core/SkString.h"
#include "include/core/SkPngChunkReader.h"

extern "C" int libQemuFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

	if (Size <1 && Size > 4096)
		return 0;

	void * DataMa = malloc(Size);
	memcpy(DataMa, Data, Size);

	sk_sp<SkData> data = SkData::MakeFromMalloc(DataMa, Size);
	SkCodec::Result result;

	std::unique_ptr<SkAndroidCodec> codec = SkAndroidCodec::MakeFromData(std::move(data), nullptr);

	if (!codec) {
		return 0;
	}

	SkImageInfo info = codec->getInfo();
	const int width = info.width();
	const int height = info.height();

	SkColorType decodeColorType = kN32_SkColorType;
	SkBitmap::HeapAllocator defaultAllocator;
	SkBitmap::Allocator* decodeAllocator = &defaultAllocator;
	SkAlphaType alphaType = codec->computeOutputAlphaType(/*requireUnpremultiplied=*/false);
	const SkImageInfo decodeInfo =
		SkImageInfo::Make(width, height, decodeColorType, alphaType);

	SkImageInfo bitmapInfo = decodeInfo;
	SkBitmap decodingBitmap;
	if (!decodingBitmap.setInfo(bitmapInfo) ||
		!decodingBitmap.tryAllocPixels(decodeAllocator)) {
		return 1;
	}

	result = codec->getAndroidPixels(decodeInfo, decodingBitmap.getPixels(), decodingBitmap.rowBytes());

	return 0;
}
```

Coverage seems to be working fineeee 🕺🕺

<img src="../../img/skia_fuzz.png" alt="Skia SKCodecFuzzer"/>


#### PS

There might be big boo-boo I didn't think of. Please let me know if there's any improvements that need to be done or anything I missed out to handle on TB cache. 🙏🏻

## References

- https://andreafioraldi.github.io/articles/2019/07/20/aflpp-qemu-compcov.html
- https://abiondo.me/2018/09/21/improving-afl-qemu-mode/
- https://airbus-seclab.github.io/qemu_blog/
- http://people.redhat.com/pbonzini/qemu-test-doc/_build/html/topics/Translator-Internals.html
- https://googleprojectzero.blogspot.com/2020/07/mms-exploit-part-1-introduction-to-qmage.html

## To-Do

- [ ] Make sure coverage is working
- [ ] Check if it works with -fork
- [ ] Improve Code Coverage/Add extra instrumentation.
- [ ] Add CMP coverage
- [ ] Add ASAN
- [ ] Fuzzing support Android JNI libraries