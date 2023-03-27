![debloat](https://user-images.githubusercontent.com/77356206/215351855-9f89c298-36b4-4234-89b5-dc3f26d1f8b0.png)

# Debloat
Debloat is a GUI and CLI tool to remove excess garbage from bloated executables.

By excess garbage, I mean 300 - 800MB of junk bytes added to a binary to keep it from going into a sandbox.

Being built with Python, the code and logic is easily accessible for others to take the concepts and apply them to their own tools. The program can be compiled for Windows, MacOS, Linux. The GUI removes any need for remembering commandline options and reading through CLI manuals: it is intended to be as simple as possible. The logic within the program handles the different use cases automatically.

Compiled binaries have already been included in the [Releases](https://github.com/Squiblydoo/debloat/releases/).

The CLI version can be installed using `pip install debloat`. 

For advanced users, Debloat can also be imported into other scripts and the processing functions can be called individually.

## How to use the GUI?
The GUI of Debloat intends to be as intuitive as possible.
When launched, you can drag and drop bloated file onto the text bar and press the "Process file" button.
Some technical information will be printed to the scrolling textbox and the file without bloat will be written to the directory the file was pulled from.
Sound easy? It is!

Running the program should debloat the binary in 30-40 second on average; as long as 120 seconds for more complicated obfuscation methods.

<img width="602" alt="Screenshot 2023-01-29 at 2 52 13 PM" src="https://user-images.githubusercontent.com/77356206/215352245-b37091ce-4d58-415c-a7ba-44a9c45bd6f1.png">

## How to use the CLI?
After installing using `pip install debloat` use the command `debloat`.<br>
`debloat` can take two arguments. The first argument is required: the file to debloat. The second argument is optional: the output location. When no output is provided, it will be written to the same directory as the original file.

The gui can also be launched from the CLI using the command `debloat-gui`.

## Does it always work?
Not yet.
My unscientific guess is that it should work for every 5 of 6 binaries. There are specific usecases I know where it does not work and I am working to implement solutions for those usecases. In situations where it does not work, it may remove too much content from the binary and the binary will return malformed.

## Use Cases (Images from [Malcat](https://malcat.fr/))
### Full support
- [x] Bloat appended to the end of a Signed PE.<br>
In the image below, the bloat has been appended to the end of the executable. <br>
![Screenshot 2023-02-11 at 3 32 36 PM](https://user-images.githubusercontent.com/77356206/218279963-00780b59-8227-47dd-a0af-41096f6ae17b.png)

- [X] Signed executable packed with UPX.<br>
In the image below, the bloat has been appended to the executable after packing. <br>
![Screenshot 2023-02-11 at 3 44 10 PM](https://user-images.githubusercontent.com/77356206/218280433-6dbcf51a-68c8-48e1-a89a-ad0b818a0afc.png)

- [X] Signed executable includes bloat in the .rsrc section of the PE.<br>
In the image below, the bloat is identified as in the .rsrc section and is removed from the PE.<br>
![Screenshot 2023-02-11 at 3 35 21 PM](https://user-images.githubusercontent.com/77356206/218280086-7cd548f8-e16b-4290-9283-a8a848de1419.png)

### Partial Support
- [ ] Some cases where bloat is added inside a PE Section.<br>
In the image below, the bloat has been included in a PE section named [0]. <br>
![Screenshot 2023-02-11 at 3 26 52 PM](https://user-images.githubusercontent.com/77356206/218279753-ed2c9102-482a-4639-aeb1-df8efc9c4e2e.png)

- [ ] Some packer detection

### Other use cases
There are use cases where the tool does not work. However, I plan to solve for them before publishing too much about them.

## Why?
There appear to be a limited number of tools to easily process bloated executables. The two tools I have seen the most are “foremost” which is intended for recovering binaries from a disk image and “pecheck”.

[Foremost](https://www.kali.org/tools/foremost/) works best in instances where the junk bytes are null (0x00) and it struggles when the binary has a fake or real signature. Its use in removing bloat from files is not its original purpose.

[Pecheck](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pecheck.py) has been developed over 14+ years and has some confusing commandline options. The option to remove bloated content is not the primary function of the script. Pecheck has to be combined with another tool ([disitool](https://blog.didierstevens.com/programs/disitool/)) in order to handle signed executables. In my experience, there are other times where pecheck can get confused and return an executable twice the size of the original bloated executable. All these factors seem OK if you are handling a small number of binaries, but as the number of binaries and methods increase, a tool specific to removing bloat is needed.

There are good solid manual methods to remove bloat from binaries, but these methods can be tedious and not all analysts have the skills to do this. This tool removes the burden of needing to know how to manually remove bloat. Additionally, it allows for better scale. The principles used in the script allow allow for better scale if automation is desired.\*

\* Note: If automation is desired, I recommend re-writing these concepts in C/C++ and not Python.

## How to build? 
Follow the build commands appropriate to your platform. The main difference between build commands is the format of the icon.
<br>
MacOS<br>
`pyinstaller --onefile --noconsole --additional-hooks-dir=./hook --icon=debloat.icns gui.py`

Windows<br>
`pyinstaller --onefile  --noconsole  --additional-hooks-dir=./hook --icon=debloat.ico gui.py`

Linux<br> 
`~/.local/bin/pyinstaller --onefile --noconsole --icon=debloat.ico --additional-hooks-dir=./hook --add-binary "/home/redacted/.local/lib/python3.10/site-packages/:." gui.py`
- I'm not sure why the same hook didn't work on Linux and pointing to the site-packages directory is not preferred. For some unknown reason, it would not find the binary if I pointed to the specific tkinterdnd2 or tkdnd directories.

## Where is this project going next?
Batch processing: process all files in a directory and produce a report.

Better support for using processing methods outside of debloat.
