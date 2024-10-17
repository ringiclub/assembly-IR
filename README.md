# Introduction
As part of my work-study program as a reverse engineer, I'm in charge of analyzing the various obfuscation techniques used by Tigress and OLLVM. 
The aim is to analyze the evolution of these techniques over time and to propose a final rendering in the form of a graphical interface for three types of decompilers, such as IDA Pro, Ghidra and Binary Ninja, to enable real-time code clean-up with a native C/Python/Java plugin or an external Python script (which I'll have to justify with benchmarks).

Being an important part of decompilation, the decompiler's microcode is something I need to know, so, as with [obfuscation](https://github.com/ringiclub/obfuscation) I'll be doing an open source analysis of it to better understand/learn but also share this new knowledge. This time with notebooks and not C scripts and markdown files.

## Microcode overview

The microcode, also called IR (Intermediate Representation), is the first stage of IDA decompilation process. <br>
In this case, microcode is the IR of assembly instruction, think of them like LLVM'S IR.