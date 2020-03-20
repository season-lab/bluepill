# BluePill

**Update (Mar 4, 2020):** *An article on BluePill just got accepted at TIFS (see below). We are now extending the documentation! :-)*

**BluePill** is an open-source dynamic analysis framework for handling evasive malware. Its goal is to reconcile the transparency properties needed for automatic analyses with the fine-grained execution inspection and altering capabilities required for manual analysis. BluePill is an academic prototype under active development: as we share it as such, any feedback is greatly appreciated!

BluePill can counter many red pills targeting hypervisors, debuggers, third-party analysis tools (e.g. IDA Pro), and timing artifacts. It builds on dynamic binary instrumentation (DBI) to monitor adversarial queries that a sample can make on the environment looking for artifacts, and fix them when their results would give away the presence of an automated analysis or a human agent.

BluePill offers a GDB remote interface to analysts to debug a sample, complemented by a stealth patching mechanisms to hide code changes made in the debugger from self-checksumming schemes.

We tested BluePill on heterogeneous PE32 malware running on 32-bit Windows 7 SP1: as an example, we can run executables protected with recent versions of VMProtect and Themida, and highly evasive samples like Furtim.

To counter DBI evasions, BluePill uses a [library of mitigations](https://github.com/season-lab/sok-dbi-security/) that we wrote for Intel Pin as part of our paper *SoK: Using Dynamic Binary Instrumentation for Security (And How You May Get Caught Red-Handed)* from ASIACCS 2019. We extended the library with further mitigations for time overheads and red pills targeting the GDB remote debugging interface and exception handling.

BluePill has been presented in:
* ***Black Hat Europe 2019***. *BluePill: Neutralizing Anti-Analysis Behavior in Malware Dissection*. [[link]](https://www.blackhat.com/eu-19/briefings/schedule/index.html#bluepill-neutralizing-anti-analysis-behavior-in-malware-dissection-17685) [[slides]](https://i.blackhat.com/eu-19/Wednesday/eu-19-Delia-BluePill-Neutralizing-Anti-Analysis-Behavior-In-Malware-Dissection.pdf)
* ***TIFS 2020*** (IEEE Transactions on Information Forensics and Security). *On the Dissection of Evasive Malware*. [[paper]](https://ieeexplore.ieee.org/document/9018111)

*Before going public for BH Europe 2019, we made radical changes that broke the handling of 64-bit code and partially of the WoW64 subsystem: please consider these scenarios experimental as we complete the regression testing.*

### Quick start

BluePill builds on Intel Pin and requires Visual Studio 2015 for its compilation.

Extract a recent release of Pin to your disk drive and change the path-related property value in the Visual Studio project when needed: by default we assume Pin v3.11 installed in `C:\Pin311`. Once compilation ends, you will find a `bluepill32.dll` library in `C:\Pin311`. To run an executable under BluePill use:

```
C:\Pin311\pin.exe -t bluepill32.dll [options] -- <file.exe>
```

BluePill supports the following command-line options:

Option | Meaning
--- | --- 
`-evasions` | Detect and handle the majority of evasions supported (see below for DBI)
`-debugger` | Enable debugger mode via GDB remote interface
`-leak` | DBI evasions: fix leaks of real EIP (e.g. FPU instructions)
`-nx` | DBI evasions: check that code pages are executable
`-rw` | DBI evasions: hide pages that belong to the DBI engine

For instance, to run an evasive program named `sample.exe` in a sandbox-like automatic mode try:

```
C:\Pin311\pin.exe -t bluepill32.dll -evasions -leak  -- sample.exe
```

Enabling the `-leak` mitigation has minimal performance impact, while `-nx` and ultimately `-rw` can help with complex packers that attempt conformance checking on the address space of the program.

BluePill will create a file named `evasions.log` under Pin's folder `C:\Pin311` (modify the `LOGPATH` variable inside `pintool\src\logging.h` to change it) that logs possible evasion attempts intercepted during the execution.  

### Debugging via GDB remote interface

BluePill supports the use of a debugger to control the execution and carry out malware dissection. We rely on the GDB remote interface of Pin: BluePill can thus be used as a remote backend from your debugger tool if it supports the GDB protocol. In the following we provide instructions to set up a debugging session with IDA Pro.

To enable the debugger interface, you need to provide additional command-line options to both Pin (`-appdebug -appdebug_server_port <port>`) and BluePill (`-debugger`) as follows:

```
C:\Pin311\pin.exe -appdebug —appdebug_server_port 10000 -t bluepill32.dll -debugger [other options] -- <file.exe>
```

We will use `10000` as port number in this guide. The application will stay paused until you connect a debugger to the socket: however, if you try *attaching* a local debugger to the process, you will end up debugging the whole Pin engine instead of just the application. The expected output on screen will be something like:

![Pin waiting for a debugger to connect](docs/pin-debugger-port.png)

#### Setting up IDA Pro
You can now open the executable in IDA and select the *Remote GDB debugger* backend from `Debugger->Switch debugger`. Check that the options (e.g. port number) are correct using `Debugger->Process options` like in the screenshot below:

![IDA debugger settings](docs/ida-debugger-settings.png)

At this point it helps to insert a breakpoint on some address in the main executable section, for instance on the entrypoint. Then you can start your debugging session with `Debugger->Start process`. IDA will notify you that *"There is already a process being debugged by remote. Do you want to attach to it?"*. Just click *Yes* and the debugging session will start, with EIP being somewhere inside in ntdll.dll.

Since memory mapping information is not available by default over the GDB remote protocol, we added a custom debugger command `vmmap` that instructs BluePill to build such a map. We automated this process with a script `addSegments.py` available in the `scripts/` folder: just load it in IDA with `File->Script file`. The script will populate the *Segments* subview of IDA with the memory layout information (i.e. sections and their permissions) for each code module. *Note: we will soon add code to update the Module subview, which currently stays stale.*

You can now debug your sample as BluePill shields you from a whole lot of evasions :-)

Please note that exception handling requires a workaround for the current GDB server implementation. When you need to pass an exception to the application just send a `wait` command right after you receive the exception message, then disconnect and reconnect IDA to BluePill, which meanwhile will put the execution on hold in response to the command.

#### Making stealth code edits
*We will shortly populate this part explaining the custom GDB commands we introduced to make edits to the code that would stay invisible to self-checksumming schemes. Please be patient with us for a little bit longer :-)*


### Authors
* Daniele Cono D'Elia ([@dcdelia](https://github.com/dcdelia)) - design
* Federico Palmaro ([@nik94](https://github.com/nik94)) - main developer
