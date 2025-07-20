# 🧠 PE-Parser

A lightweight **PE (Portable Executable)** file parser written in **C**.

This tool analyzes the internal structure of Windows executable files (**EXE/DLL**) including headers, sections, and data directories.  
Ideal for:

- 📚 Learning Windows internals  
- 🐞 Malware analysis  
- 🧪 Binary research  

---

## ⚙️ How to Use

Run the executable from the command line by passing the path to a PE file (EXE or DLL):

```bash
PE-Parser.exe <path_to_exe_or_dll>
📌 Example

PE-Parser.exe C:\Windows\System32\notepad.exe
🧾 What It Parses
The tool will extract and display detailed information about the file structure, including:

✅ DOS Header

✅ NT Headers

✅ Optional Header

✅ Section Headers

✅ Raw data of each section

✅ Import Table (if available)

📂 Output Example

Machine: 0x8664 (x64)
Number of Sections: 5
TimeDateStamp: 0x5DBA4A2F
Characteristics: Executable | 32bitMachine

Section[0]: .text | VA: 0x1000 | RAW: 0x400 | Size: 0x6C00
Section[1]: .rdata | VA: 0x8000 | RAW: 0x7400 | Size: 0x2C00
...

Import Table:
KERNEL32.dll
    - GetProcAddress
    - LoadLibraryA
USER32.dll
    - MessageBoxA
🛠️ Requirements
🪟 Windows OS

💻 C Compiler (e.g., Visual Studio, MinGW)

🔧 To Compile with GCC (MinGW)

gcc PE-Parser.c -o PE-Parser.exe
📁 Project Structure

📦 PE-Parser
 ┣ 📄 PE-Parser.c          # Main source code
 ┣ 📄 PE-Parser.exe        # Compiled executable (optional)
 ┗ 📄 README.md            # Documentation file
🔐 License
This project is open-source and intended for educational and research purposes only.
No warranty. Use at your own risk.

👤 Author
Yousef Salah
