## ActionScript3 IDA Pro

# [Hex-Rays IDA Pro Plug-In Contest 2018](https://www.hex-rays.com/contests/2018/index.shtml)

Author: [Boris Larin](https://twitter.com/oct0xor)

This repository contains the SWF Loader, ActionScript3 processor module, and a debugger assist plugin named KLFDB.

<div align="center">
    <img src ="/imgs/img0.png"/>
</div>

# Requirements

IDA Pro 7.1 (Tested with IDA Pro 7.1.180227)

# Installation

Copy files into the IDA Pro directory: 
* 'swf.py' to 'loaders' subfolder
* 'klfdb.py' to 'plugins' subfolder
* 'as3.py' to 'procs' subfolder

# Usage

Drag and drop the SWF file to IDA Pro and select the Shockwave Flash loader.

<div align="center">
    <img src ="/imgs/img1.png"/>
</div>

Use 'File' -> 'Produce file' -> 'Create MAP file...' to generate a map file for use with KLFDB.

<div align="center">
    <img src ="/imgs/img2.png"/>
</div>

KLFDB is written to work with 32-bit versions of Stand Alone Flash and with Flash for Browsers (Internet Explorer is currently supported). 

To debug the SWF file with Internet Explorer, load the Adobe Flash module (e.g. c:\Windows\System32\Macromed\Flash\Flash32_*_*_*_*.ocx) into IDA Pro.

Use 'Edit' -> 'Klfdb' -> 'Load new map file' to load the generated map file.

From this point, it is possible to use 'Edit' -> 'Klfdb' -> 'Set breakpoints on ...' to set breakpoints on methods.

<div align="center">
    <img src ="/imgs/img4.png"/>
</div>

After setting breakpoints, attach to the Internet Explorer process that is about to start the SWF file and use 'Edit' -> 'Klfdb' -> 'Run'. After that, allow the Flash file to execute.

<div align="center">
    <img src ="/imgs/img5.png"/>
</div>

The plugin will suspend execution of Adobe Flash after the breakpoint hit and will transparently fill just-in-time compiled native code with useful comments about the original bytecode.

<div align="center">
    <img src ="/imgs/img6.png"/>
</div>

# Acknowledgements
- [RABCDAsm](https://github.com/CyberShadow/RABCDAsm)
- [JPEXS Free Flash Decompiler](https://github.com/jindrapetrik/jpexs-decompiler/)
