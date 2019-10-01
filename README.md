# devi - DEvirtualize VIrtual calls

Devi is a simple tool that uses runtime information to devirtualize virtual calls in c++ binaries. 

## Usage

Devi consits of two components, one for dynamic analysis (DBI)  and one for static analysis (disassembler). 

### Running the Frida Tracer

#### Minimal Command Line

Spawn process:

```
python devi_frida.py -m <module_name> -o <JSON_output> -- <software_to_trace> <arguments for binary>
```

Attach to process:

```
python devi_frida.py -m <module_name> -s <sysmbol_to_hook> -o <JSON_output> -p <pid_of_target>
```

### Disassembler Plugin:

For Binary Ninja see https://github.com/murx-/devi_binja for IDA follow along here. 

Copy devi\_ida.py to your IDA plugin folder or load the script via File -> Script file... and load devi\_ida.py.

Once devi is loaded you can load the JSON file containing the virtual calls via File -> Load File -> Load Virtual Calls. 

## Minimal Example

```bash
python devi_frida.py -m main -o virtual_calls.json -- tests/HelloWorld myArgs
```

Load JSON file into IDA Pro. 

### Disassembly

Before:

![Disassembly before devi](https://github.com/murx-/devi/blob/master/images/cpp-test-assembly-wo-devi.png)


After:

![Disassembly with devi](https://github.com/murx-/devi/blob/master/images/cpp-test-assembly-w-devi.PNG)

### Xrefs

Before:

![Xrefs before devi](https://github.com/murx-/devi/blob/master/images/cpp-test-xrefs-wo-devi.PNG)

After:

![Xrefs after devi](https://github.com/murx-/devi/blob/master/images/cpp-test-xrefs-w-devi.PNG)

### Xref Graph

Before:

![Xrefs graph before devi](https://github.com/murx-/devi/blob/master/images/cpp-test-xrefs-graphs-wo-devi2.PNG)

After:

![Xrefs graph after devi](https://github.com/murx-/devi/blob/master/images/cpp-test-xrefs-graphs-w-devi.PNG)

## Supported Frameworks

Supported DBIs:

- Frida

Supported Disassemblers:

- IDA
- [Binary Ninja](https://github.com/murx-/devi_binja)

## Misc

This tool is heavily inspired by [Ablation](https://github.com/cylance/Ablation). 
