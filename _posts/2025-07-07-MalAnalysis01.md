---
layout: post
title: Malware Analysis 01 - Structural Analysis
category : [MalwareAnalysis]
tags: reverse
---

## PE (Portable Executable) Analysis

### PE File Structure Overview

PE files are the standard executable format for Windows systems. Understanding their structure is crucial for malware analysis as most Windows malware uses this format.

#### Key PE Components

**DOS Header (64 bytes)**
- Contains the "MZ" signature (0x4D5A) at offset 0x00
- `e_lfanew` field at offset 0x3C points to PE header location
- Legacy compatibility with DOS systems
- `e_cblp` (0x02): Bytes on last page of file
- `e_cp` (0x04): Pages in file
- `e_cparhdr` (0x08): Size of header in paragraphs
- `e_minalloc` (0x0A): Minimum extra paragraphs needed
- `e_maxalloc` (0x0C): Maximum extra paragraphs needed
- `e_ss` (0x0E): Initial (relative) SS value
- `e_sp` (0x10): Initial SP value
- `e_csum` (0x12): Checksum
- `e_ip` (0x14): Initial IP value
- `e_cs` (0x16): Initial (relative) CS value
- `e_lfarlc` (0x18): File address of relocation table
- `e_ovno` (0x1A): Overlay number

**PE Header**
- Contains the "PE" signature (0x50450000) at offset 0x00
- **File Header (20 bytes):**
  - `Machine` (0x04): Target machine type (0x014C for x86, 0x8664 for x64)
  - `NumberOfSections` (0x06): Number of sections
  - `TimeDateStamp` (0x08): Time and date the file was created
  - `PointerToSymbolTable` (0x0C): File offset of COFF symbol table
  - `NumberOfSymbols` (0x10): Number of symbols in symbol table
  - `SizeOfOptionalHeader` (0x14): Size of optional header
  - `Characteristics` (0x16): File attributes (executable, DLL, etc.)
- **Optional Header:**
  - `Magic` (0x00): Magic number (0x010B for PE32, 0x020B for PE32+)
  - `AddressOfEntryPoint` (0x10): RVA of entry point
  - `ImageBase` (0x1C): Preferred load address
  - `SectionAlignment` (0x20): Section alignment in memory
  - `FileAlignment` (0x24): Section alignment in file
  - `SizeOfImage` (0x38): Size of image in memory
  - `SizeOfHeaders` (0x3C): Size of headers
  - `Subsystem` (0x44): Required subsystem (1=Native, 2=GUI, 3=Console)
  - `DllCharacteristics` (0x46): DLL characteristics (ASLR, DEP, etc.)

**Section Headers**
- `.text` - Contains executable code
- `.data` - Contains initialized data
- `.rdata` - Contains read-only data
- `.idata` - Contains import information
- `.edata` - Contains export information
- `.reloc` - Contains relocation information
- `.rsrc` - Contains resources
- `.pdata` - Contains exception handling data
- `.debug` - Contains debug information

### Tools for PE Analysis

#### PE Explorer
- GUI-based PE file analyzer
- Shows headers, sections, imports, exports
- Displays strings and resources

#### PEiD
- PE file identifier
- Detects packers, cryptors, and compilers
- Signature-based detection

#### CFF Explorer
- Comprehensive PE analysis tool
- Can modify PE files
- Shows detailed header information

#### FLOSS (FireEye Labs Obfuscated String Solver)
- Extracts obfuscated strings from malware
- Handles XOR, ROT, and other encoding schemes
- Can extract stack strings and function arguments
- Useful for finding hidden URLs, commands, and configuration data

#### CAPA (Capability and Attack Pattern Analyzer)
- Identifies capabilities and attack patterns in malware
- Uses rule-based detection for common malware behaviors
- Can detect persistence, evasion, execution, and communication patterns
- Provides detailed analysis reports with confidence scores

### Practical PE Analysis Example

Let's analyze a suspicious PE file using command-line tools:

```bash
# Basic file information
file suspicious.exe

# PE header analysis
pefile suspicious.exe

# Strings extraction
strings suspicious.exe | grep -i "http\|cmd\|powershell"

# Import analysis
objdump -p suspicious.exe | grep -i "kernel32\|user32\|advapi32"
```

#### Advanced String Analysis with FLOSS

FLOSS is particularly useful for finding obfuscated strings that regular `strings` command might miss:

```bash
# Extract all strings (including obfuscated ones)
floss suspicious.exe

# Extract only stack strings
floss suspicious.exe --only-stack-strings

# Extract only decoded strings
floss suspicious.exe --only-decoded

# Extract function arguments
floss suspicious.exe --only-arguments

# Save output to file
floss suspicious.exe -o strings_output.txt
```

#### Capability Analysis with CAPA

CAPA helps identify malware capabilities and attack patterns:

```bash
# Basic capability analysis
capa suspicious.exe

# Verbose output with detailed explanations
capa suspicious.exe -v

# Save results to JSON
capa suspicious.exe -j > capa_results.json

# Analyze with specific rule sets
capa suspicious.exe --rules /path/to/custom/rules

# Show only high-confidence matches
capa suspicious.exe --confidence high
```

#### Packing Detection: UPX and Other Packers

Packed malware uses compression and obfuscation to hide its true nature. UPX is one of the most common packers, but many others exist.

##### UPX Detection and Analysis

UPX (Ultimate Packer for eXecutables) is a popular open-source packer often used by malware authors:

```bash
# Check if file is UPX packed
upx -t suspicious.exe

# Attempt to unpack UPX
upx -d suspicious.exe -o suspicious_unpacked.exe

# List UPX information without unpacking
upx -l suspicious.exe

# Force unpack (may not work if modified)
upx -d suspicious.exe --force

# Check UPX version used
upx -V suspicious.exe
```

**UPX Indicators:**
- Section names: `.UPX0`, `.UPX1`, `.UPX2`
- High compression ratio (file size vs memory size)
- UPX stub in the executable
- Characteristic UPX strings: "UPX!", "UPX0", "UPX1"

##### Other Common Packers and Detection

**ASPack:**
```bash
# Look for ASPack indicators
strings suspicious.exe | grep -i "aspack"
# Common strings: "ASPack", "aPLib", "ASPack v"

# Check for ASPack sections
objdump -h suspicious.exe | grep -i "aspack"
```

**VMProtect:**
```bash
# VMProtect detection
strings suspicious.exe | grep -i "vmprotect"
# Look for: "VMProtect", "Virtual Machine"

# Check for VMProtect sections
objdump -h suspicious.exe | grep -i "\.vmp"
```

**Themida/WinLicense:**
```bash
# Themida indicators
strings suspicious.exe | grep -i "themida\|winlicense"
# Common strings: "Themida", "WinLicense", "Oreans"
```

##### Generic Packing Detection Techniques

```bash
# Entropy analysis (high entropy may indicates packing)
binwalk -E suspicious.exe

# Using pefile for size analysis
python3 -c "
import pefile
pe = pefile.PE('suspicious.exe')
file_size = pe.OPTIONAL_HEADER.SizeOfHeaders + sum(section.SizeOfRawData for section in pe.sections)
mem_size = pe.OPTIONAL_HEADER.SizeOfImage
ratio = mem_size / file_size
print(f'File size: {file_size}')
print(f'Memory size: {mem_size}')
print(f'Size ratio: {ratio:.2f}')
print('Likely packed' if ratio > 1.5 else 'Probably not packed')
"

# Section analysis
objdump -h suspicious.exe | grep -E "\.text|\.data|\.rdata"

# Check for unusual section names
objdump -h suspicious.exe | grep -v "\.text\|\.data\|\.rdata\|\.bss\|\.idata\|\.edata\|\.reloc\|\.rsrc"
```

**Common Packing Indicators:**
- **Size Discrepancies:** Large difference between file and memory size
- **Unusual Section Names:** `.packed`, `.upx`, `.aspack`, `.vmp`, `.themida`
- **High Entropy:** Entropy > 7.0 in code sections
- **Small Code Sections:** Tiny `.text` section with large memory allocation
- **Packer Strings:** Signatures of known packers in strings
- **Import Obfuscation:** Few or no visible imports (may be resolved at runtime)
- **Anti-Debugging:** Packer stubs often include anti-analysis code

##### Automated Packing Detection Tools

```bash
# PEiD for packer detection
peid suspicious.exe

# Detect It Easy (DIE)
die suspicious.exe

# Exeinfo PE
exeinfope suspicious.exe

# Using YARA for packer detection
yara -r rules/packers.yar suspicious.exe
```

**Example YARA rule for UPX detection:**
```yara
rule UPX_Packed {
    strings:
        $upx1 = "UPX!"
        $upx2 = "UPX0"
        $upx3 = "UPX1"
        $upx4 = "UPX2"
    
    condition:
        any of them
}
```

#### Common Malware Indicators in PE Files

1. **Suspicious Imports**
   - `CreateRemoteThread` - Process injection
   - `VirtualAlloc` + `WriteProcessMemory` - Code injection
   - `RegCreateKey` + `RegSetValue` - Registry manipulation
   - `URLDownloadToFile` - File download

2. **Packed/Encrypted Sections**
   - High entropy in sections
   - Unusual section names
   - Large `.text` section with low entropy

3. **Suspicious Resources**
   - Embedded executables
   - Encrypted data
   - Unusual file types

## ELF (Executable and Linkable Format) Analysis

### ELF File Structure Overview

ELF is the standard binary format for Linux and Unix-like systems. Linux malware analysis requires understanding this format.

#### Key ELF Components

**ELF Header (64 bytes)**
- Contains the ELF magic number (0x7F454C46)
- Identifies file type (executable, shared object, relocatable)
- Specifies target architecture and endianness

**Program Headers**
- Define memory segments
- Specify load addresses and permissions
- Include dynamic linking information

**Section Headers**
- `.text` - Executable code
- `.data` - Initialized data
- `.bss` - Uninitialized data
- `.rodata` - Read-only data
- `.dynamic` - Dynamic linking information
- `.got` - Global Offset Table
- `.plt` - Procedure Linkage Table

### Tools for ELF Analysis

#### readelf
- Command-line ELF analysis tool
- Shows headers, sections, symbols
- Displays dynamic linking information

#### objdump
- Object file analysis tool
- Shows disassembly, symbols, relocations
- Can extract sections

#### ldd
- Shows shared library dependencies
- Identifies missing libraries
- Useful for understanding dependencies

### Practical ELF Analysis Example

```bash
# Basic file information
file suspicious_elf

# ELF header analysis
readelf -h suspicious_elf

# Section headers
readelf -S suspicious_elf

# Program headers
readelf -l suspicious_elf

# Dynamic symbols
readelf -d suspicious_elf

# Strings analysis
strings suspicious_elf | grep -i "http\|bash\|nc\|ssh"

# Dependencies
ldd suspicious_elf
```

#### Common Malware Indicators in ELF Files

1. **Suspicious Imports**
   - `system()` - Command execution
   - `popen()` - Command execution with output capture
   - `dlopen()` + `dlsym()` - Dynamic library loading
   - `ptrace()` - Process manipulation

2. **Anti-Analysis Techniques**
   - Encrypted strings
   - Anti-debugging code
   - VM detection

3. **Network Indicators**
   - Hardcoded IP addresses
   - Port numbers
   - Protocol strings

## Malicious Document (Maldoc) Analysis

### Maldoc Types and Formats

Malicious documents are a common malware delivery mechanism, especially in targeted attacks.

#### Microsoft Office Documents
- **Word (.doc/.docx)** - Macros, embedded objects, OLE
- **Excel (.xls/.xlsx)** - Macros, formulas, embedded objects
- **PowerPoint (.ppt/.pptx)** - Macros, embedded objects

#### PDF Documents
- JavaScript execution
- Embedded executables
- Exploit code
- Social engineering

### Tools for Maldoc Analysis

#### Office Documents
- **Oletools** - Python library for OLE/Office file analysis
- **Oledump** - Command-line OLE file analyzer for VBA/macro extraction
- **OfficeParser** - Command-line Office file analyzer
- **VBA-Run** - VBA macro analyzer
- **MacroRaptor** - Advanced macro analysis tool

#### PDF Documents
- **pdfid** - PDF structure analyzer
- **pdf-parser** - Detailed PDF analysis
- **peepdf** - Interactive PDF analysis

### Practical Maldoc Analysis Example

#### Office Document Analysis: Detecting Macros and Scripts in Word and Excel

Malicious macros and embedded scripts are common in both Word and Excel files. Detecting and analyzing them is crucial in static maldoc analysis. Here's how to do it with modern tools:

##### 1. Oledump for Macro Detection and Extraction

Oledump is a powerful tool for inspecting OLE files (used by older Office formats like .doc, .xls, and some .docm/.xlsm). It can list, extract, and analyze VBA macro streams.

```bash
# List all streams in the document (look for streams with 'M' indicating macros)
oledump.py suspicious_word.doc

oledump.py suspicious_excel.xls

oledump.py suspicious_macro.docm

# Extract and view macro code from a specific stream (e.g., stream 8)
oledump.py suspicious_word.doc -s 8 -v

# Extract all macro streams
oledump.py suspicious_word.doc --vba

# Deobfuscate macro code (if obfuscated)
oledump.py suspicious_word.doc -s 8 -v --deobfuscate
```

##### 2. Oletools for Macro and OLE Object Analysis

Oletools provides additional utilities for Office file analysis:

```bash
# Scan for OLE objects and macros
oleid suspicious_word.docx

# Extract and analyze VBA macros
olevba suspicious_word.docx
olevba suspicious_excel.xlsm

# List embedded objects
oleobj suspicious_word.docx
```

##### 3. What to Look For
- Streams marked with 'M' in oledump output (indicates VBA macro code)
- Suspicious keywords in macro code: Shell, CreateObject, WScript, PowerShell, AutoOpen, Workbook_Open
- Obfuscated or encoded strings
- Auto-executing macro functions (e.g., AutoOpen, Document_Open, Workbook_Open)
- URLs, file downloaders, or command execution patterns

##### 4. Example: Detecting a Malicious Macro in Excel

```bash
# List streams
oledump.py suspicious.xlsm

# Extract macro from stream 10
oledump.py suspicious.xlsm -s 10 -v

# Look for suspicious code (e.g., powershell, cmd, download)
```

##### 5. YARA Scanning for Macro Malware

```bash
yara -r rules/macro_malware.yar suspicious_word.docm
```

These steps help you quickly identify and extract malicious macros and scripts in both Word and Excel files, which are common initial infection vectors in targeted attacks.

#### PDF Document Analysis

```bash
# Basic file information
file suspicious_document.pdf

# PDF structure analysis
pdfid suspicious_document.pdf

# Detailed analysis
pdf-parser suspicious_document.pdf

# JavaScript extraction
pdf-parser suspicious_document.pdf | grep -A 10 -B 10 "JavaScript"

# Embedded objects
pdf-parser suspicious_document.pdf | grep -i "embedded\|object"
```

### Common Malware Indicators in Maldocs

#### Office Documents
1. **Suspicious Macros**
   - Auto-executing macros
   - PowerShell execution
   - File download functions
   - Registry manipulation

2. **Embedded Objects**
   - Executable files
   - Script files
   - Encrypted data

3. **Social Engineering**
   - Urgent language
   - Authority references
   - Suspicious links

#### PDF Documents
1. **JavaScript Code**
   - Shell command execution
   - File operations
   - Network connections
   - Exploit code

2. **Embedded Files**
   - Executables
   - Scripts
   - Encrypted payloads

3. **Exploit Attempts**
   - Buffer overflow attempts
   - Memory corruption
   - Privilege escalation

## Advanced Static Analysis Techniques

### Entropy Analysis

Entropy analysis helps identify packed or encrypted content:

```bash
# Using binwalk for entropy analysis
binwalk -E suspicious_file

# Using ent for detailed entropy
ent suspicious_file
```

### String Analysis

String analysis reveals functionality and indicators:

```bash
# Extract strings
strings suspicious_file

# Filter for specific patterns
strings suspicious_file | grep -i "http\|cmd\|powershell\|nc\|ssh"

# Unicode strings
strings -el suspicious_file

# Wide strings
strings -ew suspicious_file
```
