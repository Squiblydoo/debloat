![debloat](https://user-images.githubusercontent.com/77356206/215351855-9f89c298-36b4-4234-89b5-dc3f26d1f8b0.png)

# Debloat
Debloat is a GUI tool to remove excess garbage from bloated executables.

Being built with Python, the code and logic is easily accessible for others to take the concepts and apply the concepts to their own tools. The program can be compiled for Windows, MacOS, Linux. The GUI removes any need for remembering commandline options and reading through CLI manuals: it is intended to be as simple as possible. The logic within the program handles the different use cases automatically.

## How to use?
Debloat is a GUI and intends to be as intuitive as possible.
When launched, you can drag and drop bloated file onto the text bar and press the "Process file" button.
Some technical information will be printed to the scrolling textbox and the file without bloat will be written to the directory the file was pulled from.
Sound easy? It is!

<img width="602" alt="Screenshot 2023-01-29 at 2 52 13 PM" src="https://user-images.githubusercontent.com/77356206/215352245-b37091ce-4d58-415c-a7ba-44a9c45bd6f1.png">

## Why?
There appear to be a limited number of tools to easily process bloated executables. The two tools I have seen the most are “foremost” which is intended for recovering binaries from a disk image and “pecheck”.

Foremost works best in instances where the junk bytes are null (0x00) and it struggles when the binary has a fake or real signature.

Pecheck has been developed over 14+ years and has some confusing commandline options. The option to remove bloated content is not the primary function of the script. Pecheck has to be combined with another tool in order to handle signed executables. In my experience, there are other times where pecheck can get confused and return an executable twice the size of the original bloated executable.

## How to build? 
Follow the build commands appropriate to your platform. The main difference between build commands is the format of the icon.
<br>
MacOS<br>
`pyinstaller --onefile --noconsole --additional-hooks-dir=./hook --icon=debloat.icns debloat.py`

Windows<br>
`pyinstaller --onefile  --noconsole  --additional-hooks-dir=./hook --icon=debloat.ico debloat.py`

Linux<br> 
`~/.local/bin/pyinstaller --onefile --noconsole --icon=debloat.ico --additional-hooks-dir=./hook --add-binary "/home/redacted/.local/lib/python3.10/site-packages/:." debloat.py`
- I'm not sure why the same hook didn't work on Linux and pointing to the site-packages directory is not preferred. For some unknown reason, it would not find the binary if I pointed to the specific tkinterdnd2 or tkdnd directories.
