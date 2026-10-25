"""pyinstaller hook file.

You need to use this hook-file if you are packaging a project using tkinterdnd2.
Just put hook-tkinterdnd2.py in the same directory where you call pyinstaller and type:

    pyinstaller myproject/myproject.py --additional-hooks-dir=.
"""

import os
import platform
import tkinter
from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs


# tkinterdnd2 ships the tkdnd library for every OS and CPU, one folder each:
#   tkinterdnd2/tkdnd/win-x64/        (for Tcl/Tk 8)
#   tkinterdnd2/tkdnd/win-x64-tcl9/   (for Tcl/Tk 9, not every platform has one)
# The built app only runs on the OS, CPU and Tcl/Tk of the Python doing the build,
# so we bundle just the one folder it will load.
PLATFORM_FOLDERS = {
    ('Darwin', 'arm64'): 'osx-arm64',
    ('Darwin', 'x86_64'): 'osx-x64',
    ('Linux', 'aarch64'): 'linux-arm64',
    ('Linux', 'x86_64'): 'linux-x64',
    ('Windows', 'ARM64'): 'win-arm64',
    ('Windows', 'AMD64'): 'win-x64',
    ('Windows', 'x86'): 'win-x86',
}

# Each platform folder also contains the Tcl scripts for the other OSes; skip those.
UNUSED_SCRIPTS = {
    'Windows': {'tkdnd_unix.tcl', 'tkdnd_macosx.tcl'},
    'Linux': {'tkdnd_windows.tcl', 'tkdnd_macosx.tcl'},
    'Darwin': {'tkdnd_windows.tcl', 'tkdnd_unix.tcl'},
}

system = platform.system()
# Same CPU detection as tkinterdnd2: on Windows, PROCESSOR_ARCHITECTURE gives the
# architecture of the running Python (e.g. AMD64 for x64 Python on an ARM64 PC).
if system == 'Windows':
    machine = os.environ.get('PROCESSOR_ARCHITECTURE', platform.machine())
else:
    machine = platform.machine()

if (system, machine) not in PLATFORM_FOLDERS:
    raise RuntimeError(f'TkinterDnD2 is not supported on platform "{system} {machine}".')

all_files = collect_data_files('tkinterdnd2') + collect_dynamic_libs('tkinterdnd2')
available_folders = {os.path.basename(dest) for src, dest in all_files}

# Like tkinterdnd2 itself, use the Tcl 9 folder when building with Tcl 9,
# falling back to the Tcl 8 folder if there is no Tcl 9 build for this platform.
folder_to_bundle = PLATFORM_FOLDERS[(system, machine)]
uses_tcl9 = int(str(tkinter.TclVersion).split('.')[0]) >= 9
if uses_tcl9 and folder_to_bundle + '-tcl9' in available_folders:
    folder_to_bundle += '-tcl9'


def is_needed(source_path, dest_dir):
    folder = os.path.basename(dest_dir)
    filename = os.path.basename(source_path)
    return folder == folder_to_bundle and filename not in UNUSED_SCRIPTS[system]


datas = {(src, dest) for src, dest in all_files if is_needed(src, dest)}
