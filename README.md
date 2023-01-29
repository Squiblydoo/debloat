![debloat](https://user-images.githubusercontent.com/77356206/215351855-9f89c298-36b4-4234-89b5-dc3f26d1f8b0.png)

# Debloat
Debloat is a GUI tool to remove excess garbage from bloated executables.

Being built with Python, the code and logic is easily accessible for others to take the concepts and apply the concepts to their own tools. The program can be compiled for Windows, MacOS, Linux. The GUI removes any need for remembering commandline options and reading through CLI manuals: it is intended to be as simple as possible. The logic within the program handles the different use cases automatically.


## Why?
There appear to be a limited number of tools to easily process bloated executables. The two tools I have seen the most are “foremost” which is intended for recovering binaries from a disk image and “pecheck”.

Foremost works best in instances where the junk bytes are null (0x00) and it struggles when the binary has a fake or real signature.

Pecheck has been developed over 14+ years and has some confusing commandline options. The option to remove bloated content is not the primary function of the script. Pecheck has to be combined with another tool in order to handle signed executables. In my experience, there are other times where pecheck can get confused and return an executable twice the size of the original bloated executable.

