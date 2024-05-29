![debloat](https://user-images.githubusercontent.com/77356206/215351855-9f89c298-36b4-4234-89b5-dc3f26d1f8b0.png)

# Debloat
Debloat is a GUI and CLI tool to remove excess garbage from bloated executables.

By excess garbage, I mean 100 - 800 MB of junk bytes added to a binary to keep it from going into a sandbox. This method of adding junk is called "inflating" or "pumping" a binary. Debloat currently handles the 10 most common inflation tactics.

Being built with Python, the application can easily be leveraged in other workflows. Currently, debloat is used by [CCCS's AssemblyLine](https://www.cyber.gc.ca/en/tools-services/assemblyline) and [CERT Polska's MWDB](https://github.com/CERT-Polska/karton-archive-extractor).

 The program can be compiled for Windows, MacOS, Linux. The GUI and CLI have minimal options: it is intended to be as simple as possible and the logic within the program handles the different use cases automatically.

Compiled binaries have already been included in the [Releases](https://github.com/Squiblydoo/debloat/releases/).

The debloat can installed using `pip install debloat`. Use `debloat` to launch the CLI and `debloat-gui` to launch the GUI.

For advanced users, Debloat can also be imported into other scripts and the processing functions can be called individually.

## How to use the GUI?
The GUI of Debloat intends to be as intuitive as possible.
When launched, you can drag and drop bloated file onto the text bar and press the "Process file" button.
Some technical information will be printed to the scrolling textbox and the file without bloat will be written to the directory the file was pulled from.
Sound easy? It is!

Processing files will take a few seconds.<br>
![image](https://github.com/Squiblydoo/debloat/assets/77356206/3d2756cd-bc83-44e8-b223-edd8ed464369)


## How to use the CLI?
After installing using `pip install debloat` use the command `debloat`.<br>
`debloat` can take two arguments. The first argument is required: the file to debloat. The second argument is optional: the output location. When no output is provided, it will be written to the same directory as the original file.

The gui can also be launched from the CLI using the command `debloat-gui`.

## Does it always work?
Not yet.
Based on my recent analysis, debloat is able to [remove junk from bloated files 97.8% of the time](https://x.com/SquiblydooBlog/status/1795419380991291424).

In previous versions, `debloat` could accidentally remove too much of the binary. That is no longer the case unless you use the "--last-ditch" switch. If you ever need this switch, consider sharing the sample for additional analysis. This option has now been added to the GUI. Functionally, what the function does is it will remove the whole overlay, if there is one. In some cases this is necessary as no pattern for the junk was found---this is most commonly the case in samples that do not compress well.

## Use Cases (Images from [Malcat](https://malcat.fr/))
### Full support
- [x] Bloat appended to the end of a Signed PE.<br>
In the image below, the bloat has been appended to the end of the executable. <br>
![Screenshot 2023-02-11 at 3 32 36 PM](https://user-images.githubusercontent.com/77356206/218279963-00780b59-8227-47dd-a0af-41096f6ae17b.png)

- [X] Signed or Unsigned Packed executable.<br>
In the image below, the bloat has been appended to the executable after packing. <br>
![Screenshot 2023-02-11 at 3 44 10 PM](https://user-images.githubusercontent.com/77356206/218280433-6dbcf51a-68c8-48e1-a89a-ad0b818a0afc.png)

- [X] Signed executable includes bloat in the .rsrc section of the PE.<br>
In the image below, the bloat is identified as in the .rsrc section and is removed from the PE.<br>
![Screenshot 2023-02-11 at 3 35 21 PM](https://user-images.githubusercontent.com/77356206/218280086-7cd548f8-e16b-4290-9283-a8a848de1419.png)

- [X] Cases where bloat is added inside a PE Section.<br>
In the image below, the bloat has been included in a PE section named [0]. <br>
![Screenshot 2023-02-11 at 3 26 52 PM](https://user-images.githubusercontent.com/77356206/218279753-ed2c9102-482a-4639-aeb1-df8efc9c4e2e.png)

- [X] Cases where the executable is a Nullsoft Scriptable Installer System executable (NSIS aka Nullsoft)
These exe are installers that may contain one or more files. The files contained may or may not be malicious. (Sometimes actors will add files simply for increasing the file size.) All files within the installer are extracted to a new directory. The directory also contains the script for the installer which can be consulted to determine which files may be malicious.
In the image below, Malcat has identified the executable as a NSIS installer.
![image](https://github.com/Squiblydoo/debloat/assets/77356206/86780abc-da4b-4808-bccb-733d97fa80d8)

# Partial Support

- [X] Cases where the junk is too random and the entropy is too high. In these cases, a switch/option called "--last-ditch" 

### Other use cases
There are use cases where the tool does not work. However, I plan to solve for them before publishing too much about them.

## Why?
There appear to be a limited number of tools to easily process bloated executables. The two tools I have seen the most are “foremost” which is intended for recovering binaries from a disk image and “pecheck”.

[Foremost](https://www.kali.org/tools/foremost/) works best in instances where the junk bytes are null (0x00) and it struggles when the binary has a fake or real signature. Its use in removing bloat from files is not its original purpose.

[Pecheck](https://github.com/DidierStevens/DidierStevensSuite/blob/master/pecheck.py) has been developed over 14+ years and has some confusing commandline options. The option to remove bloated content is not the primary function of the script. Pecheck has to be combined with another tool ([disitool](https://blog.didierstevens.com/programs/disitool/)) in order to handle signed executables. In my experience, there are other times where pecheck can get confused and return an executable twice the size of the original bloated executable. All these factors seem OK if you are handling a small number of binaries, but as the number of binaries and methods increase, a tool specific to removing bloat is needed.

[Binary Refinery](https://github.com/binref/refinery) is an amazing tool. It was written with the intention of being a [CyberChef](https://github.com/gchq/CyberChef) of the commandline. While both tools are amazing, they both have a shortcoming that requires the user to know what formulas should be applied. 

There are good solid manual methods to remove bloat from binaries, but these methods can be tedious and not all analysts have the skills to do this. This tool removes the burden of needing to know how to manually remove bloat. Additionally, it allows for better scale. The principles used in the script allow allow for better scale if automation is desired.


## How to build? 
Follow the build commands appropriate to your platform. The main difference between build commands is the format of the icon.
<br>
MacOS<br>
`pyinstaller --onefile --noconsole --additional-hooks-dir=./hook --icon=debloat.icns gui.py`

Windows<br>
`pyinstaller --onefile  --noconsole  --additional-hooks-dir=./hook --icon=debloat.ico gui.py`

Linux<br> 
`pyinstaller --onefile --noconsole --icon=debloat.ico --collect-all tkinterdnd2 gui.py`

## Want to discuss?
Consider joining the [debloat Discord](discord.gg/dvGXKaY5qr).

## Credits
Big shoutout to Jesko Hüttenhain creator of [Binary Refinery](https://github.com/binref/refinery). The NSIS extraction is based on his reverse engineering of the NSIS file format. Check out Binary Refinery if you have not.

## Where is this project going next?
Batch processing: process all files in a directory and produce a report.

Better support for using processing methods outside of debloat.

Support for debloating without unzipping.
