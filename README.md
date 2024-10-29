# Introduction
As part of my work-study program as a reverse engineer, I'm in charge of analyzing the various obfuscation techniques used by Tigress and OLLVM. The aim is to analyze the evolution of these techniques over time and to propose a final rendering in the form of a graphical interface for three types of decompilers, such as IDA Pro, Ghidra and Binary Ninja, to enable real-time code clean-up with a native  plugin or an external Python script (which I'll have to justify with benchmarks).

Being an important part of decompilation, the decompiler's itermediate representation for assembly instructions is something I need to know, so, as with [obfuscation](https://github.com/ringiclub/obfuscation) I'll be doing an open source analysis of it to better understand/learn but also share this new knowledge. This time with notebooks and not C scripts and markdown files.

> [!NOTE]
> All the work is store in notebooks folder...

## IR explorer plugins

- [Lucid for IDA](https://github.com/Fireboyd78/lucid)
- No plugin for BinaryNinja, already have a mulitple native integrations of BNIL explorer
- [... for Ghidra]()

## Quote us
```tex
@misc{reverse_engineering_analysis,
  author       = {Alexis Daugé (aldauge)},
  title        = {Analyses of Various Decompiler Microcode},
  year         = {2024},
  howpublished = {Work-Study Program Report},
  url          = {https://github.com/ringiclub/microcode},
}
```
