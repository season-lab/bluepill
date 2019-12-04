# BluePill

BluePill is an open-source dynamic analysis framework for neutralizing evasive behavior in malware.
It aims at reconciling transparency requirements typical of automatic malware analysis with manipulation capabilities required for dissection.

The repository contains a polished snapshot of code under active development, and for the time being we share it with the community as such: BluePill is a research prototype and any feedback would be **greatly** appreciated. 

BluePill build on dynamic binary instrumentation to observe, check, and replace outputs in adversarial queries that a sample can make on the environment, when their results would give away the presence of an analysis system and/or a human agent behind it.

It builds on Intel Pin 3.5 and requires Visual Studio 2010 for its compilation. Make sure you extract the working tree (temporarily hosted [here](https://drive.google.com/file/d/1fKTRcpYbH-cbqfGQwPV5evx9KMrAkBIE/view?usp=sharing)) of Pin to `C:\Pin35` or change the related property value in the Visual Studio project we provide.

BluePill has been tested on 32-bit malware running on Windows 7 SP1, mainly on a 32-bit install and to a good extent under WoW64. We will be porting BluePill to newer Pin and VS releases soon, after proper testing. 64-bit support does not require changes to the design and we will hopefully be releasing to production soon, along with richer documentation for using BluePill.

To cope with DBI artifacts, BluePill builds on a library of mitigations for Intel Pin devised as part of the [code](https://github.com/season-lab/sok-dbi-security/) from our ACM ASIACCS 2019 paper *SoK: Using Dynamic Binary Instrumentation for Security (And How You May Get Caught Red-Handed)*. We have extended the work with additional mitigations for DBI overheads and other red pills targeting debugging and exceptions.

Once you compile BluePill, you will find a `bluepill32.dll` library in `C:\Pin35`. To run a program under BluePill use:

```
C:\Pin35\pin.exe -t bluepill32.dll -- <file.exe>
```

Change the defaults in `config.h` to control the mitigations used by default or to enable command-line knobs for them.


P.S. Apologies for the incompleteness/minimalism in the documentation: we will extend it real soon :-)
