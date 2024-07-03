#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Most of this code was repurposed from Binary Refinery (https://github.com/binref/refinery), used under the 3-Clause BSD License

from collections import namedtuple
import struct

import enum

import itertools
import re
import io
import dataclasses

import zlib
import lzma

from datetime import datetime

import logging
from debloat.utilities.readers import StructReader, Struct, StreamDetour, MemoryFile
from debloat.utilities.pyflate import BZip2File
from typing import (
    BinaryIO, 
    NamedTuple, 
    Iterable, 
    Iterator, 
    Callable, 
    Union, 
    ByteString, 
    Optional, 
    List, 
    Dict,
    Type)

logging.basicConfig(level=logging.WARN)

class UnpackResult:

    def get_data(self) -> ByteString:
        if Callable(self.data):
            self.data = self.data()
        return self.data

    def __init__(self, _br__path: str, _br__data: Union[ByteString, Callable[[], ByteString]], **_br__meta):
        self.path = _br__path
        self.data = _br__data
        self.meta = _br__meta
        for key in [key for key, value in _br__meta.items() if value is None]:
            del _br__meta[key]   

class ArchiveUnit:
    def __init__(self, *paths, 
                 list=False, join_path=False, 
                 drop_path=False, fuzzy=0, exact=False, 
                 regex=False, 
                 date=b'date', 
                 path=b'path', **kwargs):
        self.paths = paths
        self.list = list
        self.join_path = join_path
        self.drop_path = drop_path
        self.fuzzy = fuzzy
        self.exact = exact
        self.regex = regex
        self.path = path
        self.date = date,
        self.kwargs = kwargs

    def _pack(
        self,
        path: str,
        date: Optional[Union[datetime, str]],
        data: Union[ByteString, Callable[[], ByteString]],
        **meta
    ) -> UnpackResult:
        if isinstance(date, datetime):
            date = date.isoformat(' ', 'seconds')
        if isinstance(date, str):
            meta[self.args.date.decode(self.codec)] = date
        return UnpackResult(path, data, **meta)

class DeflateFile(io.RawIOBase):

    data: MemoryFile
    dc: zlib.decompress

    def __new__(cls, data: MemoryFile):
        self = super().__new__(cls)
        self.data = data
        self.dc = zlib.decompressobj(-15)
        return io.BufferedReader(self)

    def readall(self) -> bytes:
        return self.read()

    def readinto(self, __buffer):
        data = self.read(len(__buffer))
        size = len(data)
        __buffer[:size] = data
        return size

    def read(self, size=-1):
        buffer = self.dc.unconsumed_tail or self.data.read(size)
        kwargs = {}
        if size > 0:
            kwargs.update(max_length=size)
        return self.dc.decompress(buffer, **kwargs)

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def writable(self) -> bool:
        return False

    def write(self, __b):
        raise NotImplementedError

class LZMAOptions(NamedTuple):
    filter_flag: bool
    dictionary_size: int

class NSBlockHeaderOffset(Struct):
    def __init__(self, reader: StructReader, is64bit: bool):
        self.offset = reader.u64() if is64bit else reader.u32()
        self.size = reader.u32()

class NSMethod(str, enum.Enum):
    Copy = 'COPY'
    LZMA = 'LZMA'
    BZip2 = 'BZIP2'
    Deflate = 'DEFLATE'

class Op(enum.IntEnum):
    INVALID_OPCODE     = 0              # noqa
    RET                = enum.auto()    # noqa; Return
    NOP                = enum.auto()    # noqa; Nop, Goto
    ABORT              = enum.auto()    # noqa; Abort
    QUIT               = enum.auto()    # noqa; Quit
    CALL               = enum.auto()    # noqa; Call, InitPluginsDir
    UPDATETEXT         = enum.auto()    # noqa; DetailPrint
    SLEEP              = enum.auto()    # noqa; Sleep
    BRINGTOFRONT       = enum.auto()    # noqa; BringToFront
    CHDETAILSVIEW      = enum.auto()    # noqa; SetDetailsView
    SETFILEATTRIBUTES  = enum.auto()    # noqa; SetFileAttributes
    CREATEDIR          = enum.auto()    # noqa; CreateDirectory, SetOutPath
    IFFILEEXISTS       = enum.auto()    # noqa; IfFileExists
    SETFLAG            = enum.auto()    # noqa; SetRebootFlag, ...
    IFFLAG             = enum.auto()    # noqa; IfAbort, IfSilent, IfErrors, IfRebootFlag
    GETFLAG            = enum.auto()    # noqa; GetInstDirError, GetErrorLevel
    RENAME             = enum.auto()    # noqa; Rename
    GETFULLPATHNAME    = enum.auto()    # noqa; GetFullPathName
    SEARCHPATH         = enum.auto()    # noqa; SearchPath
    GETTEMPFILENAME    = enum.auto()    # noqa; GetTempFileName
    EXTRACTFILE        = enum.auto()    # noqa; File
    DELETEFILE         = enum.auto()    # noqa; Delete
    MESSAGEBOX         = enum.auto()    # noqa; MessageBox
    RMDIR              = enum.auto()    # noqa; RMDir
    STRLEN             = enum.auto()    # noqa; StrLen
    ASSIGNVAR          = enum.auto()    # noqa; StrCpy
    STRCMP             = enum.auto()    # noqa; StrCmp
    READENVSTR         = enum.auto()    # noqa; ReadEnvStr, ExpandEnvStrings
    INTCMP             = enum.auto()    # noqa; IntCmp, IntCmpU
    INTOP              = enum.auto()    # noqa; IntOp
    INTFMT             = enum.auto()    # noqa; IntFmt/Int64Fmt
    PUSHPOP            = enum.auto()    # noqa; Push/Pop/Exchange
    FINDWINDOW         = enum.auto()    # noqa; FindWindow
    SENDMESSAGE        = enum.auto()    # noqa; SendMessage
    ISWINDOW           = enum.auto()    # noqa; IsWindow
    GETDLGITEM         = enum.auto()    # noqa; GetDlgItem
    SETCTLCOLORS       = enum.auto()    # noqa; SetCtlColors
    SETBRANDINGIMAGE   = enum.auto()    # noqa; SetBrandingImage / LoadAndSetImage
    CREATEFONT         = enum.auto()    # noqa; CreateFont
    SHOWWINDOW         = enum.auto()    # noqa; ShowWindow, EnableWindow, HideWindow
    SHELLEXEC          = enum.auto()    # noqa; ExecShell
    EXECUTE            = enum.auto()    # noqa; Exec, ExecWait
    GETFILETIME        = enum.auto()    # noqa; GetFileTime
    GETDLLVERSION      = enum.auto()    # noqa; GetDLLVersion
#   GETFONTVERSION     = enum.auto()    # noqa; Park : 2.46.2
#   GETFONTNAME        = enum.auto()    # noqa; Park : 2.46.3
    REGISTERDLL        = enum.auto()    # noqa; RegDLL, UnRegDLL, CallInstDLL
    CREATESHORTCUT     = enum.auto()    # noqa; CreateShortCut
    COPYFILES          = enum.auto()    # noqa; CopyFiles
    REBOOT             = enum.auto()    # noqa; Reboot
    WRITEINI           = enum.auto()    # noqa; WriteINIStr, DeleteINISec, DeleteINIStr, FlushINI
    READINISTR         = enum.auto()    # noqa; ReadINIStr
    DELREG             = enum.auto()    # noqa; DeleteRegValue, DeleteRegKey
    WRITEREG           = enum.auto()    # noqa; WriteRegStr, WriteRegExpandStr, WriteRegBin, WriteRegDWORD
    READREGSTR         = enum.auto()    # noqa; ReadRegStr, ReadRegDWORD
    REGENUM            = enum.auto()    # noqa; EnumRegKey, EnumRegValue
    FCLOSE             = enum.auto()    # noqa; FileClose
    FOPEN              = enum.auto()    # noqa; FileOpen
    FPUTS              = enum.auto()    # noqa; FileWrite, FileWriteByte
    FGETS              = enum.auto()    # noqa; FileRead, FileReadByte
#   Park:
#   FPUTWS             = enum.auto()    # noqa; FileWriteUTF16LE, FileWriteWord
#   FGETWS             = enum.auto()    # noqa; FileReadUTF16LE, FileReadWord
    FSEEK              = enum.auto()    # noqa; FileSeek
    FINDCLOSE          = enum.auto()    # noqa; FindClose
    FINDNEXT           = enum.auto()    # noqa; FindNext
    FINDFIRST          = enum.auto()    # noqa; FindFirst
    WRITEUNINSTALLER   = enum.auto()    # noqa; WriteUninstaller
#   Park : since 2.46.3 the log is enabled in main Park version
#   LOG                = enum.auto()    # noqa; LogSet, LogText
    SECTIONSET         = enum.auto()    # noqa; Get*, Set*
    INSTTYPESET        = enum.auto()    # noqa; InstTypeSetText, InstTypeGetText, SetCurInstType, GetCurInstType
#   Before NSIS v3.06: Instructions not actually implemented in exehead, but used in compiler.
#   GETLABELADDR       = enum.auto()    # noqa; both of these get converted to ASSIGNVAR
#   GETFUNCTIONADDR    = enum.auto()    # noqa
#   In NSIS v3.06 and later it was changed to:
    GETOSINFO          = enum.auto()    # noqa
    RESERVEDOPCODE     = enum.auto()    # noqa
    LOCKWINDOW         = enum.auto()    # noqa; LockWindow
#   Two unicode commands available only in Unicode archive:
    FPUTWS             = enum.auto()    # noqa; FileWriteUTF16LE, FileWriteWord
    FGETWS             = enum.auto()    # noqa; FileReadUTF16LE, FileReadWord
#   Since NSIS v3.06 the fllowing IDs codes was moved here:
#   Opcodes listed here are not actually used in exehead.
#   No exehead opcodes should be present after these!
#   GETLABELADDR       = enum.auto()    # noqa; ASSIGNVAR
#   GETFUNCTIONADDR    = enum.auto()    # noqa; ASSIGNVAR
#   The following IDs are not IDs in real order.
#   We just need some IDs to translate eny extended layout to main layout:
    LOG                = enum.auto()    # noqa; LogSet, LogText
#   Park
    FINDPROC           = enum.auto()    # noqa; FindProc
    GETFONTVERSION     = enum.auto()    # noqa; GetFontVersion
    GETFONTNAME        = enum.auto()    # noqa; GetFontName

    @classmethod
    def from_int(cls, value: int) -> 'Op':
        try:
            return cls(value)
        except ValueError:
            return cls.INVALID_OPCODE
_Op_PARAMETER_COUNT = {
    Op.INVALID_OPCODE   : 0,
    Op.RET              : 0,
    Op.NOP              : 1,
    Op.ABORT            : 1,
    Op.QUIT             : 0,
    Op.CALL             : 2,
    Op.UPDATETEXT       : 6,
    Op.SLEEP            : 1,
    Op.BRINGTOFRONT     : 0,
    Op.CHDETAILSVIEW    : 2,
    Op.SETFILEATTRIBUTES: 2,
    Op.CREATEDIR        : 3,
    Op.IFFILEEXISTS     : 3,
    Op.SETFLAG          : 3,
    Op.IFFLAG           : 4,
    Op.GETFLAG          : 2,
    Op.RENAME           : 4,
    Op.GETFULLPATHNAME  : 3,
    Op.SEARCHPATH       : 2,
    Op.GETTEMPFILENAME  : 2,
    Op.EXTRACTFILE      : 6,
    Op.DELETEFILE       : 2,
    Op.MESSAGEBOX       : 6,
    Op.RMDIR            : 2,
    Op.STRLEN           : 2,
    Op.ASSIGNVAR        : 4,
    Op.STRCMP           : 5,
    Op.READENVSTR       : 3,
    Op.INTCMP           : 6,
    Op.INTOP            : 4,
    Op.INTFMT           : 4,
    Op.PUSHPOP          : 6,
    Op.FINDWINDOW       : 5,
    Op.SENDMESSAGE      : 6,
    Op.ISWINDOW         : 3,
    Op.GETDLGITEM       : 3,
    Op.SETCTLCOLORS     : 2,
    Op.SETBRANDINGIMAGE : 4,
    Op.CREATEFONT       : 5,
    Op.SHOWWINDOW       : 4,
    Op.SHELLEXEC        : 6,
    Op.EXECUTE          : 3,
    Op.GETFILETIME      : 3,
    Op.GETDLLVERSION    : 4,
    Op.REGISTERDLL      : 6,
    Op.CREATESHORTCUT   : 6,
    Op.COPYFILES        : 4,
    Op.REBOOT           : 1,
    Op.WRITEINI         : 5,
    Op.READINISTR       : 4,
    Op.DELREG           : 5,
    Op.WRITEREG         : 6,
    Op.READREGSTR       : 5,
    Op.REGENUM          : 5,
    Op.FCLOSE           : 1,
    Op.FOPEN            : 4,
    Op.FPUTS            : 3,
    Op.FGETS            : 4,
    Op.FSEEK            : 4,
    Op.FINDCLOSE        : 1,
    Op.FINDNEXT         : 2,
    Op.FINDFIRST        : 3,
    Op.WRITEUNINSTALLER : 4,
    Op.SECTIONSET       : 5,
    Op.INSTTYPESET      : 4,
    Op.GETOSINFO        : 6,
    Op.RESERVEDOPCODE   : 2,
    Op.LOCKWINDOW       : 1,
    Op.FPUTWS           : 4,
    Op.FGETWS           : 4,
    Op.LOG              : 2,
    Op.FINDPROC         : 2,
    Op.GETFONTVERSION   : 2,
    Op.GETFONTNAME      : 2,
}

NS_SHELL_STRINGS = {
    0x00: 'DESKTOP',
    0x01: 'INTERNET',
    0x02: 'SMPROGRAMS',
    0x03: 'CONTROLS',
    0x04: 'PRINTERS',
    0x05: 'DOCUMENTS',
    0x06: 'FAVORITES',
    0x07: 'SMSTARTUP',
    0x08: 'RECENT',
    0x09: 'SENDTO',
    0x0A: 'BITBUCKET',
    0x0B: 'STARTMENU',
    0x0D: 'MUSIC',
    0x0E: 'VIDEOS',
    0x10: 'DESKTOP',
    0x11: 'DRIVES',
    0x12: 'NETWORK',
    0x13: 'NETHOOD',
    0x14: 'FONTS',
    0x15: 'TEMPLATES',
    0x16: 'STARTMENU',
    0x17: 'SMPROGRAMS',
    0x18: 'SMSTARTUP',
    0x19: 'DESKTOP',
    0x1A: 'APPDATA',
    0x1B: 'PRINTHOOD',
    0x1C: 'LOCALAPPDATA',
    0x1D: 'ALTSTARTUP',
    0x1E: 'ALTSTARTUP',
    0x1F: 'FAVORITES',
    0x20: 'INTERNET_CACHE',
    0x21: 'COOKIES',
    0x22: 'HISTORY',
    0x23: 'APPDATA',
    0x24: 'WINDIR',
    0x25: 'SYSDIR',
    0x26: 'PROGRAM_FILES',
    0x27: 'PICTURES',
    0x28: 'PROFILE',
    0x29: 'SYSTEMX86',
    0x2A: 'PROGRAM_FILESX86',
    0x2B: 'PROGRAM_FILES_COMMON',
    0x2C: 'PROGRAM_FILES_COMMONX8',
    0x2D: 'TEMPLATES',
    0x2E: 'DOCUMENTS',
    0x2F: 'ADMINTOOLS',
    0x30: 'ADMINTOOLS',
    0x31: 'CONNECTIONS',
    0x35: 'MUSIC',
    0x36: 'PICTURES',
    0x37: 'VIDEOS',
    0x38: 'RESOURCES',
    0x39: 'RESOURCES_LOCALIZED',
    0x3A: 'COMMON_OEM_LINKS',
    0x3B: 'CDBURN_AREA',
    0x3D: 'COMPUTERSNEARME',
}

NS_VARIABLE_STRINGS = (
    "CMDLINE",
    "INSTDIR",
    "OUTDIR",
    "EXEDIR",
    "LANGUAGE",
    "TEMP",
    "PLUGINSDIR",
    "EXEPATH",  # NSIS 2.26+
    "EXEFILE",  # NSIS 2.26+
    "HWNDPARENT",
    "CLICK",    # set from page->clicknext
    "OUTDIR",   # NSIS 2.04+
)

class NSHeaderFlags(enum.IntFlag):
    Undefined = 0
    Uninstall = 1
    Silent = 2
    NoCrc = 4
    ForceCrc = 8
    LongOffset = 16
    ExternalFileSupport = 32
    ExternalFile = 64
    IsStubInstaller = 128



class NSType(enum.IntEnum):
    Nsis2 = 0
    Nsis3 = enum.auto()
    Park1 = enum.auto()
    Park2 = enum.auto()
    Park3 = enum.auto()

class NSScriptInstruction(Struct):
    def __init__(self, reader: StructReader):
        self.opcode = reader.u32()
        self.arguments = [reader.u32() for _ in range(6)]

class NSCharCode(enum.IntEnum):
    NONE = 0
    CHAR = enum.auto()
    SKIP = enum.auto()
    SHELL = enum.auto()
    VAR = enum.auto()
    LANG = enum.auto()

    @property
    def special(self):
        return self > NSCharCode.CHAR
    
@dataclasses.dataclass(eq=True)
class NSItem:
    offset: int
    name: Optional[str] = None
    mtime: Optional[datetime] = None
    is_compressed: bool = True
    is_uninstaller: bool = False
    attributes: Optional[int] = None
    size: Optional[int] = None
    compressed_size: Optional[int] = None
    estimated_size: Optional[int] = None
    dictionary_size: int = 1
    patch_size: int = 0
    prefix: Optional[str] = None

    @property
    def path(self) -> str:
        path = self.name
        if self.prefix:
            path = F'{self.prefix}\\{path}'
        return path
    
    def __str__(self) -> str:
        return self.name

    def __eq__(self, other) -> bool:
        if not other or not isinstance(other, self.__class__):
            return False
        return (
            self.offset == other.offset
            and self.mtime == other.mtime
            and self.is_compressed == other.is_compressed
            and self.is_uninstaller == other.is_uninstaller
            and self.attributes == other.attributes
            and self.size == other.size
            and self.compressed_size == other.compressed_size
            and self.estimated_size == other.estimated_size
            and self.dictionary_size == other.dictionary_size
            and self.patch_size == other.patch_size
            and self.path == other.path
        )


class NSHeader(Struct):
    BACKSLASH           = ord('\\')  # noqa
    NS_CMDLINE          = 20         # noqa
    NS_INSTDIR          = 21         # noqa
    NS_OUTDIR           = 22         # noqa
    NS_EXEDIR           = 23         # noqa
    NS_LANGUAGE         = 24         # noqa
    NS_TEMP             = 25         # noqa
    NS_PLUGINSDIR       = 26         # noqa
    NS_EXEPATH          = 27         # noqa NSIS 2.26+
    NS_EXEFILE          = 28         # noqa NSIS 2.26+
    NS_HWNDPARENT_225   = 27         # noqa
    NS_HWNDPARENT_226   = 29         # noqa
    NS_CLICK            = 30         # noqa
    NS_OUTDIR_225       = 29         # noqa NSIS 2.04 - 2.25
    NS_OUTDIR_226       = 31         # noqa NSIS 2.26+

    def _string_args_to_single_arg(self, arg1: int, 
                                   arg2: Optional[int] = None) -> int:
        if self.type >= NSType.Park1:
            return arg1 & 0x7FFF
        else:
            if arg2 is None:
                arg2 = arg1 >> 8
            arg1 &= 0x7F
            arg2 &= 0x7F
            return arg1 | arg2 << 7

    def _get_char_code(self, char: int) -> NSCharCode:
        if self.type >= NSType.Park1:
            if char < 0x80:
                return NSCharCode.CHAR
            lookup = {
                0xE000: NSCharCode.SKIP,
                0xE001: NSCharCode.VAR,
                0xE002: NSCharCode.SHELL,
                0xE003: NSCharCode.LANG,
            }
        elif self.type is NSType.Nsis3:
            if char > 4:
                return NSCharCode.CHAR
            lookup = {
                0x0002: NSCharCode.SHELL,
                0x0003: NSCharCode.VAR,
                0x0004: NSCharCode.SKIP,
            }
        elif self.type is NSType.Nsis2:
            lookup = {
                0x00FC: NSCharCode.SKIP,
                0x00FD: NSCharCode.VAR,
                0x00FE: NSCharCode.SHELL,
            }
        else:
            raise ValueError(F'Unknown NSIS type {self.type}.')
        return lookup.get(char, NSCharCode.NONE)

    def _string_code_shell(self, index1: int, 
                           index2: Optional[int] = None) -> str:
        if index2 is None:
            index2 = index1 >> 8
            index1 &= 0xFF
        if index1 & 0x80 != 0:
            offset = index1 & 0x3F
            with StreamDetour(self.strings, offset):
                if self.strings.tell() != offset:
                    raise ValueError(F'Failed to detour to offset 0x{offset:02X}.')
                path = self._read_current_string()
                if path.startswith('ProgramFilesDir'):
                    return '$PROGRAMFILES'
                if path.startswith('CommonFilesDir'):
                    return '$COMMONFILES'
                suffix = 32 * (index1 >> 5 & 2)
                return F'$REG{suffix}({path})'
        for index in (index1, index2):
            shell = NS_SHELL_STRINGS.get(index)
            if shell is not None:
                return F'$SHELL:{shell}'
        else:
            return F'Error:$SHELL:{index1:02X}{index2:02X}'

    def _string_code_variable(self, index: int) -> str:
        varcount = 20 + len(NS_VARIABLE_STRINGS)
        if self._is_nsis200:
            varcount -= 3
        elif self._is_nsis225:
            varcount -= 2
        if index < 20:
            if index >= 10:
                return F'$R{index - 10}'
            return F'$V{index}'
        else:
            if index < varcount:
                if self._is_nsis225 and index >= self.NS_EXEPATH:
                    index += 2
                try:
                    variable = NS_VARIABLE_STRINGS[index - 20]
                except IndexError:
                    return F'Error:$V:{index}'
                else:
                    return F'${variable}'
            return F'Error:$V:{index}'
        
    def _string_code_language(self, index: int) -> str:
        return F'$LANGUAGE:{index}'

    @property
    def _read_char(self) -> str:
        return self.strings.u16 if self.unicode else self.strings.u8
    
    def _seek_to_string(self, position: int) -> bool:
        pos = position * self.charsize
        return self.strings.seek(pos) == pos
    
    def _read_string(self, position: int) -> Optional[str]:
        if position < 0:
            return self._string_code_language(-(position + 1))
        if not self._seek_to_string(position):
            return None
        return self._read_current_string()

    def _read_string_raw(self, position: int) -> Optional[str]:
        if not self._seek_to_string(position):
            return None
        if self.unicode:
            return self.strings.read_w_string()
        else:
            return self.strings.read_c_string()
        
    def _is_var_absolute_path(self, position: int) -> bool:
        var = self._get_var_index(position)
        if var is None:
            return False
        return var in (
            self.NS_INSTDIR,
            self.NS_EXEDIR,
            self.NS_TEMP,
            self.NS_PLUGINSDIR,
        )
    
    def _is_good_string(self, position: int) -> bool:
        if position == 0:
            return False
        if not self._seek_to_string(position - 1):
            return False
        prefix = self._read_char()
        return prefix == 0 or prefix == self.BACKSLASH

    def _is_var_str(self, position: int, index: int) -> bool:
        if index > 0x7FFF:
            return False
        var_index = self._get_var_index(position)
        if var_index is None:
            return False
        if self._get_resource_finished(position, 0) is None:
            return False
        return var_index == index

    def _get_var_index(self, position: int) -> Optional[int]:
        if not self._seek_to_string(position):
            raise LookupError(F'Failed to seek to string at position 0x{position:08X}.')
        try:
            code = self._read_char()
            if self._get_char_code(code) is not NSCharCode.VAR:
                return None
            arg1 = self._read_char()
            if arg1 == 0:
                return None
            if self.unicode:
                args = arg1,
            else:
                arg2 = self._read_char()
                if arg2 == 0:
                    return None
                args = arg1, arg2
            return self._string_args_to_single_arg(*args)
        except EOFError:
            return None
        
    def _get_resource(self, position: int) -> Optional[int]:
        if self.unicode:
            if len(self.strings) - position >= 4:
                return 2
        else:
            if len(self.strings) - position >= 3:
                return 3
        return None

    def _get_resource_finished(self, position: int, 
                          terminator: int) -> Optional[int]:
        if not self._seek_to_string(position):
            return None
        self.strings.seek_relative(3)
        if self.unicode:
            self.strings.seek_relative(1)
        if self.strings.remaining_bytes < self.charsize:
            return None
        if self._read_char() != terminator:
            return None
        return 3 if self.unicode else 4


    @property
    def charsize(self) -> int:
        return 2 if self.unicode else 1

    def _read_current_string(self) -> str:
        string = io.StringIO()
        chars = iter(self._read_char, 0)
        for letter in chars:
            code = self._get_char_code(letter)
            if code is NSCharCode.CHAR:
                string.write(chr(letter))
                continue
            if code.special:
                try:
                    var1 = next(chars)
                except StopIteration:
                    break
                if var1 == 0:
                    break
                if code is NSCharCode.SKIP:
                    letter = var1
                else:
                    if not self.unicode:
                        try:
                            var2 = next(chars)
                        except StopIteration:
                                break
                        if var2 == 0:
                            break
                        vars = var1, var2
                    else:
                        vars = var1,
                    if code is NSCharCode.SHELL:
                        string.write(self._string_code_shell(*vars))
                        continue
                    else:
                        var = self._string_args_to_single_arg(*vars)
                        if code is NSCharCode.VAR:
                            string.write(self._string_code_variable(var))
                        if code is NSCharCode.LANG:
                            string.write(self._string_code_language(var))
                        continue
            string.write(chr(letter))
        return string.getvalue()

    def opcode(self, cmd: NSScriptInstruction) -> Op:
        code = cmd.opcode
        if self.type < NSType.Park1:
            if self._log_cmd_is_enabled:
                return Op.from_int(code)
            if code < Op.SECTIONSET:
                return Op.from_int(code)
            if code is Op.SECTIONSET:
                return Op.LOG
            return Op.from_int(code - 1)
        if code < Op.REGISTERDLL:
            return Op.from_int(code)
        if self.type >= NSType.Park2:
            if code == Op.REGISTERDLL:
                return Op.GETFONTVERSION
            code -= 1
        if self.type >= NSType.Park3:
            if code == Op.REGISTERDLL:
                return Op.GETFONTNAME
            code -= 1
        if code >= Op.FSEEK:
            if self.unicode:
                if code == Op.FSEEK:
                    return Op.FPUTWS
                if code == Op.FSEEK + 1:
                    return Op.FGETWS
                code -= 2
            if code >= Op.SECTIONSET and self._log_cmd_is_enabled:
                if code == Op.SECTIONSET:
                    return Op.LOG
                return Op.from_int(code - 1)
            if code == Op.FPUTWS:
                return Op.FINDPROC
        return Op.from_int(code)

    def _find_bad_cmd(self) -> None:
        self._bad_cmd = -1
        for instruction in self.instructions:
            cmd = self.opcode(instruction)
            arg = instruction.arguments
            if cmd is Op.INVALID_OPCODE:
                continue
            if cmd >= self._bad_cmd >= 0:
                continue
            if self.type is NSType.Nsis3:
                if cmd == Op.RESERVEDOPCODE:
                    self._bad_cmd = cmd
                    continue
            else:
                if cmd == Op.RESERVEDOPCODE or cmd == Op.GETOSINFO:
                    self._bad_cmd = cmd
                    continue
            last_non_empty_index = max((k for k, a in enumerate(arg, 1) if a), default=0)
            if cmd == Op.FINDPROC and last_non_empty_index == 0:
                continue
            if _Op_PARAMETER_COUNT[cmd] < last_non_empty_index:
                self._bad_cmd = cmd

    def _guess_nsis_version(self):
        self.strong_nsis = False
        self.strong_park = False
        char_mask = 0x8080 if self.unicode else 0x80
        self.strings.seek(0)
        while not self.strings.is_eof:
            string = self._read_current_string()
            if string is None:
                continue
            if len(string) < 2:
                continue
            if ord(string[0]) != 3:
                continue
            if ord(string[1]) & char_mask == char_mask:
                self.type = NSType.Nsis3
                self.strong_nsis = True
                break
        if self.unicode:
            if not self.strong_nsis:
                self.type = NSType.Park1
                self.strong_park = True
        elif self.type is NSType.Nsis2:
            for instruction in self.instructions:
                cmd = self.opcode(instruction)
                arg = instruction.arguments
                if cmd is Op.GETDLGITEM:
                    if self._is_var_str(arg[1], self.NS_HWNDPARENT_225):
                        self._is_nsis225 = True
                        if arg[0] == self.NS_OUTDIR_225:
                            self._is_nsis200 = True
                            break
                if cmd is Op.ASSIGNVAR:
                    if arg[0] == self.NS_OUTDIR_225 and arg[2] == 0 and arg[3] == 0:
                        self._is_nsis225 = self._is_var_str(arg[1], self.NS_OUTDIR)
        got_park_version = False
        mask = 0
        IN = 4 if self.unicode else 2
        if not self.strong_nsis and not self._is_nsis225 and not self._is_nsis200:
            for instruction in self.instructions:
                cmd = instruction.opcode
                arg = instruction.arguments
                alt = arg[3]
                if cmd < Op.WRITEUNINSTALLER or cmd > Op.WRITEUNINSTALLER + IN:
                    continue
                if arg[4] != 0 or arg[5] != 0 or arg[0] <= 1 or alt <= 1:
                    continue
                if not self._is_good_string(arg[0]) or not self._is_good_string(alt):
                    continue
                index = self._get_var_index(alt)
                if index is None:
                    continue
                additional = self._get_resource_finished(alt, self.BACKSLASH)
                if index != self.NS_INSTDIR:
                    continue
                if self._read_string_raw(alt + additional) == self._read_string_raw(arg[0]):
                    inserts = cmd - Op.WRITEUNINSTALLER.value
                    mask |= 1 << inserts
            if mask == 1:
                got_park_version = True
            elif mask:
                shift = 0
                nt = self.type
                if self.unicode:
                    shift = 2
                if mask == 1 << (shift + 1):
                    nt = NSType.Park2
                if mask == 1 << (shift + 2):
                    nt = NSType.Park3
                if nt != self.type:
                    self.type = nt
                    got_park_version = True
        self._find_bad_cmd()
        if self._bad_cmd < Op.REGISTERDLL:
            return
        if self.strong_park and not got_park_version:
            if self._bad_cmd < Op.SECTIONSET:
                self.type = NSType.Park3
                self._log_cmd_is_enabled = True
                self._find_bad_cmd()
                if self._bad_cmd in range(Op.SECTIONSET):
                    self.type = NSType.Park2
                    self._log_cmd_is_enabled = False
                    self._find_bad_cmd()
                    if self._bad_cmd in range(Op.SECTIONSET):
                        self.type = NSType.Park1
                        self._find_bad_cmd()
        if self._bad_cmd >= Op.SECTIONSET:
            self._log_cmd_is_enabled = not self._log_cmd_is_enabled
            self._find_bad_cmd()
            if self._bad_cmd >= Op.SECTIONSET and self._log_cmd_is_enabled:
                self._log_cmd_is_enabled = False
                self._find_bad_cmd()   

    def _read_items(self) -> List[NSItem]:
        prefixes = ['$INSTDIR']
        out_dir = ''
        out_dir_index = (
            self.NS_OUTDIR_225
        ) if self._is_nsis225 else (
            self.NS_OUTDIR_226
        )
        items: List[NSItem] = []

        for cmd_index, instruction in enumerate(self.instructions):
            def set_path(index:int) -> None:
                item.prefix = None
                item.name = self._read_string(index)
                if not self._is_var_absolute_path(index):
                    item.prefix = prefixes[-1]
            
            cmd = self.opcode(instruction)
            arg = instruction.arguments

            if cmd is Op.INVALID_OPCODE:
                continue
            elif cmd is Op.CREATEDIR:
                if not arg[1]:
                    continue
                _path = arg[0]
                index = self._get_var_index(_path)
                if index in (out_dir_index, self.NS_OUTDIR):
                    _path += self._get_resource(_path)
                path = self._read_string(_path)
                if index == out_dir_index:
                    path = out_dir + path
                elif index == self.NS_OUTDIR:
                    path = prefixes[-1] + path
                prefixes.append(path)
            elif cmd is Op.ASSIGNVAR:
                if arg[0] != out_dir_index:
                    continue
                if self._is_var_str(arg[1], self.NS_OUTDIR) and arg[2] == 0 and arg[3] == 0:
                    out_dir = prefixes[-1]
            elif cmd is Op.EXTRACTFILE:
                try:
                    time = datetime.fromtimestamp(arg[4] << 32 | arg[3])
                except Exception:
                    time = None
                item = NSItem(arg[2], mtime=time)
                set_path(arg[1])
                items.append(item)
                if not self._is_var_str(arg[1], 10):
                    continue
                cmd_back_offset = 28
                if cmd_index > 1:
                    previous = self.instructions[cmd_index - 1]
                    if self.opcode(previous) is Op.NOP:
                        cmd_back_offset -= 2
                if cmd_index <= cmd_back_offset:
                    continue
                previous = self.instructions[cmd_index - cmd_back_offset]
                if self.opcode(previous) is Op.ASSIGNVAR:
                    previous_arguments = previous.arguments
                    if previous_arguments[0] == 14 and previous_arguments[2] == 0 and previous_arguments[3] == 0:
                        set_path(previous_arguments[1])
            elif cmd is Op.SETFILEATTRIBUTES:
                if cmd_index > 0:
                    previous = self.instructions[cmd_index - 1]
                    previous_arguments = previous.arguments
                    if self.opcode(previous) is Op.EXTRACTFILE and arg[0] == previous_arguments[1]:
                        item = items[-1]
                        item.attributes = arg[1]
            elif cmd is Op.WRITEUNINSTALLER:
                if arg[4] or arg[5] or arg[0] <=1 or arg[3] <= 1:
                    continue
                if not self._is_good_string(arg[0]):
                    continue
                if self._bad_cmd in range(Op.WRITEUNINSTALLER):
                    continue
                item = NSItem(arg[1])
                set_path(arg[0])
                item.patch_size = arg[2]
                item.is_uninstaller = True
                items.append(item)
        return items
                
    @property
    def script(self):
        script = io.StringIO()
        name_width = max(len(op.name) for op in Op)
        addr_width = len(F'{len(self.instructions):X}')
        for k, instruction in enumerate(self.instructions):
            if k > 0:
                script.write('\n')
            opcode = self.opcode(instruction)
            script.write(F'{k:0{addr_width}X} {opcode.name:{name_width}}')
            for j, arg in enumerate(instruction.arguments[:_Op_PARAMETER_COUNT.get(opcode, 6)]):
                if j > 0:
                    script.write(', ')
                if arg > 20 and self._is_good_string(arg):
                    script.write(repr(self._read_string(arg)))
                elif arg < 0x100:
                    script.write(str(arg))
                elif arg < 0x10000:
                    script.write(F'${arg:04X}')
                else:
                    script.write(F'${arg:08X}')
        return script.getvalue()

    def _string_code_language(self, index: int) -> str:
        return F'$LANGUAGE:{index:04X}'


    def __init__(self, reader: StructReader[bytearray], size: int):
        self.is64bit = size >= 100 and not any(
            struct.unpack('8xI' * 8, reader.peek(12 * 8)))
        block_header_offset_size = 12 if self.is64bit else 8
        required_size = block_header_offset_size * 8 + 4
        if size < required_size:
            raise ValueError(F'Header size 0x{size:08X} is too small. Minimum required size is 0x{required_size:08X}.')
        # TODO: Confirm role of unknown value. Copilot believes it to be
        # a signature indicating the end of the NSIS installer header.
        self.unknown_value = reader.u32()
        self.block_header_offsets = [NSBlockHeaderOffset(
            reader.read(block_header_offset_size), 
            is64bit=self.is64bit) for _ in range(8)]
        self.block_header_entries = self.block_header_offsets[2]
        self.block_header_strings = self.block_header_offsets[3]
        self.block_header_langtables = self.block_header_offsets[4]
        
        for key, offset in enumerate(self.block_header_offsets):
            width = 0x10 if self.is64bit else 8
            table = {2: 'entries', 3: 'strings', 4: 'langtables'}.get(key)
            message = F'Block {key}: offset=0x{offset.offset:0{width}X}, size=0x{offset.size:0{width}X}'
            if table is not None:
                message += F'{message} ({table})'
            logging.debug(message)

        self.type = NSType.Nsis2 # Default to NSIS 2
        
        reader.seek_set(self.block_header_entries.offset)
        self.instructions: List[NSScriptInstruction] = [NSScriptInstruction(reader) for _ in range(self.block_header_entries.size)]

        if self.block_header_entries.offset > size:
            raise ValueError(F'Header indicates {self.block_header_entries.size} entries, but only {size} bytes remain.')
        if self.block_header_strings.offset > size:
            raise ValueError(F'Header indicates {self.block_header_strings.size} strings, but only {size} bytes remain.')
        if self.block_header_langtables.offset > size:
            raise ValueError(F'Header indicates {self.block_header_langtables.size} langtables, but only {size} bytes remain.')
        if self.block_header_langtables.offset < self.block_header_strings.offset:
            raise ValueError(F'Langtables block is before strings block.')
        string_table_size = self.block_header_langtables.offset - self.block_header_strings.offset
        if string_table_size < 2:
            raise ValueError(F'String table size is too small.')
        reader.seek_set(self.block_header_strings.offset)
        strings = reader.read(string_table_size)
        self.unicode = strings[:2] == B'\0\0'
        if strings[-1] != 0 or (self.unicode and strings[-2] != 0):
            raise ValueError(F'String table is not null-terminated.')
        if self.unicode and string_table_size % 2 != 0:
            raise ValueError(F'String table is not even-sized.')

        self.strings = StructReader(strings)
        if self.block_header_entries.size > (1 << 25):
            raise ValueError(F'Header indicates {self.block_header_entries.size} entries, which is too large.')
        
        self._log_cmd_is_enabled = False
        self._is_nsis225 = False
        self._is_nsis200 = False
        self_bad_cmd = -1

        self._guess_nsis_version()

        items: Dict[(str, int), NSItem] = {}
        for item in self._read_items():
            if items.setdefault((item.path, item.offset), item) != item:
                raise ValueError(F'Duplicate item: {item.path} at 0x{item.offset:08X}')
        
        self.items = [items[t] for t in sorted(items.keys())]
        


class NSArchive(Struct):
    MAGICS = [
        # https://nsis.sourceforge.io/Can_I_decompile_an_existing_installer
        B'\xEF\xBE\xAD\xDE' B'Null' B'soft' B'Inst',   # v1.6
        B'\xEF\xBE\xAD\xDE' B'Null' B'Soft' B'Inst',   # v1.3
        B'\xED\xBE\xAD\xDE' B'Null' B'Soft' B'Inst',   # v1.1
        B'\xEF\xBE\xAD\xDE' B'nsis' B'inst' B'all\0',  # v1.0
    ]

    @dataclasses.dataclass
    class Entry:
        offset: int
        data: bytearray
        compressed_size: int
        decompression_failed: bool = False


    def __init__(self, reader: StructReader[bytearray]):
        self.flags = NSHeaderFlags(reader.u32())
        self.signature = reader.read(0x10)
        header_data = None
        header_size = reader.u32()
        header_data_length = None
        archive_size = reader.u32()
        self.archive_offset = reader.tell()
        body_size = archive_size - self.archive_offset
        if body_size < 0:
            raise ValueError("Invalid archive size")
        if header_size < self.archive_offset:
            raise ValueError("Invalid header size")
        if reader.remaining_bytes < body_size:
            raise ValueError(
                F'Header indicates archive size 0x{archive_size:08X}, '
                F'but only 0x{reader.remaining_bytes:08X} bytes remain.')
    
        # Prepare to check compression format. This takes
        # a few bytes and checks the header to determine the format
        preview_bytes = bytes(reader.peek(4))
        preview_value = int.from_bytes(preview_bytes, byteorder='little')
        
        # The default "solid" value is True and default method is deflate.
        # Regarding Solid:
        # "If /SOLID is used, all of the installer data is compressed in one block. This results in greater compression ratios."
        # We determine if the compression is solid or not by checking the headers.
        # https://nsis.sourceforge.io/Docs/Chapter4.html#
        
        self.solid = True
        self.lzma_options: Optional[LZMAOptions] = None
        self.method = NSMethod.Deflate

        # Header Matching Logic:
        #  X is the header size as given by the first header
        #  T is a value less than 0xE
        #  Y is a value different from 0x80
        # XX XX XX XX __ __ __ __ __ __ __  non-solid, uncompressed
        # 5D 00 00 DD DD 00 __ __ __ __ __  solid LZMA
        # 00 5D 00 00 DD DD 00 __ __ __ __  solid LZMA, empty filter
        # 01 5D 00 00 DD DD 00 __ __ __ __  solid LZMA, BCJ filter
         # __ __ __ 80 5D 00 00 DD DD 00 __  non-solid LZMA
        # __ __ __ 80 00 5D 00 00 DD DD 00  non-solid LZMA, empty filter
        # __ __ __ 80 01 5D 00 00 DD DD 00  non-solid LZMA, BCJ filter
        # __ __ __ 80 01 0T __ __ __ __ __  non-solid BZip
        # __ __ __ 80 __ __ __ __ __ __ __  non-solid deflate
        # 01 0T __ YY __ __ __ __ __ __ __  solid BZip
        # __ __ __ YY __ __ __ __ __ __ __  solid Deflate
        
        def lzmacheck(preview):
            if B'\x5D\0\0' not in preview:
                return False
            filter_flag = preview_bytes[0] <= 1
            reader.seek_relative(3 + int(filter_flag))
            self.lzma_options = LZMAOptions(filter_flag, reader.u32())
            return True
        
        def bzipcheck(preview):
            return preview[0] == 0x31 and preview[1] < 14
        
        if preview_value == header_size:
            self.solid = False
            header_data_length = header_size
            reader.seek_relative(4)
            header_data = reader.read_exactly(header_size)
            self.method = NSMethod.Copy
        elif lzmacheck(preview_bytes):
            self.method = NSMethod.LZMA
        elif preview_bytes[3] == 0x80:
            self.solid = False
            reader.seek_relative(4)
            second_preview = bytes(reader.peek(4))
            if lzmacheck(second_preview):
                self.method = NSMethod.LZMA
            elif bzipcheck(second_preview):
                self.method = NSMethod.BZip2
        elif bzipcheck(preview_bytes):
            self.method = NSMethod.BZip2

        reader.seek_set(self.archive_offset)
        self.entries: Dict[int, bytearray] = {}
        self.entry_offset_delta = 0
        self._solid_iter = None

        if header_data is None:
            item = self._decompress_items(reader)
            try:
                header_entry = next(item)
            except zlib.error as ZLERR:
                raise NotImplementedError(
                    'This archive seems to use an NSIS-specific deflate '
                    'algorithm which has not been implemented yet.'
                ) from ZLERR
            if self.solid:
                self._solid_iter = item 
            self.entry_offset_delta = 4 + header_entry.compressed_size
            header_data = header_entry.data
        else:
            self.entry_offset_delta = 4 + len(header_data)

        if not header_data:
            raise ValueError("Empty header")
        logging.debug(F'Header size: 0x{header_size:08X}')

        self.header = NSHeader(header_data, size=header_size)
        self.reader = reader
        
    @property
    def script(self):
        return self.header.script
    
    @property
    def offset_items(self):
        return self.archive_offset + self.entry_offset_delta
    
    def _extract_item_data(self, item: NSItem) -> Entry:
        if self.solid:
            while True:
                try:
                    entry = self.entries[item.offset]
                except KeyError:
                    try:
                        entry = next(self._solid_iter)
                    except StopIteration:
                        raise LookupError(F'Failed to find item at offset 0x{item.offset:08X}.')
                    self.entries[entry.offset - self.entry_offset_delta] = entry.data
                else: 
                    return entry
        else:
            self.reader.seek(self.offset_items + item.offset)
            decompressed = self._decompress_items(self.reader)
            entry = next(decompressed).data
            return entry

    class SolidReader(Iterable[Entry]):
        def __init__(self, src: BinaryIO):
            self.src = src
            self.pos = 0

        def __iter__(self):
            return self
        
        def __next__(self):
            offset = self.pos
            size = self.src.read(4)
            if len(size) != 4:
                raise StopIteration
            size = int.from_bytes(size, byteorder='little')
            read = size & 0x7FFFFFFF
            data = self.src.read(read)
            if len(data) != read:
                raise EOFError('Unexpected end of stream while decompressing archive entries.')
            self.pos = offset + size + 4
            return NSArchive.Entry(offset, data, size)

    class PartsReader(SolidReader):
        def __init__(self, src: BinaryIO, decompressor: Optional[Type[BinaryIO]]):
            super().__init__(src)
            self._dc = decompressor

        def __next__(self):
            item = super().__next__()
            is_compressed = bool(item.compressed_size & 0x80000000)
            item.compressed_size &= 0x7FFFFFFF
            if is_compressed:
                try:
                    dc = self._dc(MemoryFile(item.data))
                    item.data = dc.read()
                except Exception:
                    item.decompression_failed = True
            return item              
        
    class LZMAFix:
        ''' Creates a wrapper to compensate for how NSIS handles LZMA'''
        def __init__(self, src: MemoryFile):
            self._src = src
            self._fix = MemoryFile(bytes(src.read(5)) + B'\xFF' * 8)

        def __getattr__(self, key):
            return getattr(self._src, key)
        
        def read(self, size: int = -1):
            src = self._src
            fix = self._fix
            if not fix.remaining_bytes:
                return src.read(size)
            if size < 0:
                size = fix.remaining_bytes + src.remaining_bytes
            data = bytearray(size)
            wrapper = fix.read(size)
            data[:len(wrapper)] = wrapper
            data[len(wrapper):] = src.read(size - len(wrapper))
            return data
    


    def _decompress_items(self, reader: StructReader[bytearray]) -> Iterator[Entry]:
        """ Decompresses the items in the archive. """
        def NSISLZMAFile(d):
            return lzma.LZMAFile(self.LZMAFix(d))
        decompressor: Type[BinaryIO]= {
            NSMethod.Copy    : None,
            NSMethod.Deflate : DeflateFile,
            NSMethod.LZMA    : NSISLZMAFile,
            NSMethod.BZip2   : BZip2File,
        }[self.method]
        if self.solid:
            return self.SolidReader(decompressor(reader))
        return self.PartsReader(reader, decompressor)
        

class extractNSIS(ArchiveUnit):
    """
    A class to extract an NSIS file.
    """
    @classmethod
    def _find_archive_offset(cls, data: memoryview, before: int = -1, flaw_max=2) -> int:
        def signatures(*magics):
            for changes in range(flaw_max + 1):
                for magic in magics:
                    if not changes:
                        yield 0, magic
                        continue
                    for positions in itertools.permutations(range(len(magic)), r=changes):
                        signature = bytearray(magic)
                        for position in positions:
                            signature[position] = 0x2E
                        yield changes, bytes(signature)
        best_guess = None
        search_space = memoryview(data)
        for flaws, sig in signatures(*NSArchive.MAGICS):
            if flaws > 1:
                search_space = search_space[:0x20_000]
            matches = [m.start() - 4 for m in re.finditer(sig, 
                                                          search_space, 
                                                          flags=re.DOTALL)]
            if before >= 0:
                matches = [match for match in matches if match < before]
            matches.reverse()
            archive = None
            for match in matches:
                if match % 0x200 == 0:
                    archive = match
                    break
            if not archive:
                if matches and not best_guess:
                    best_guess = matches[-1]
            else:
                message = F'Archive signature was found at offset 0x{archive:08X}.'
                if flaws > 0:
                    message += F' the signature has {flaws} flaws and was likely modified.'
                logging.debug(message)
                return archive
        if best_guess:
            message = F'Archive signature was found at offset 0x{best_guess:08X}, but it has too many flaws to be reliable.'
            logging.debug(message)
        return best_guess

    def unpack(self, data: memoryview):
        memory = memoryview(data)
        before = -1
        _error = None
        while True:
            offset = self._find_archive_offset(data, before)
            if offset is None:
                _error = _error or ValueError("Unable to find NSIS archive marker")
                raise _error
            try:
                archive = NSArchive(memory[offset:])
            except Exception as e:
                _error = e
                before = offset
            else:
                break

        def info():
            yield F'{archive.header.type.name} archive'
            yield F'{archive.method.name.lower()} compression'
            yield F'Mystery value 0x{archive.header.unknown_value:X}'
            yield 'solid archive' if archive.solid else 'non-solid archive'
            yield '64-bit archive' if archive.header.is64bit else '32-bit archive'
            yield 'unicode' if archive.header.unicode else 'ansi'
        
        logging.info(', '.join(info()))
        unpacked_items = []
        for item in archive.header.items:
            unpacked_items.append(self._pack(item.path, item.mtime, archive._extract_item_data(item)))
            #data = archive._extract_item_data(item)
            logging.info(F'{item.path} at 0x{item.offset:08X}, {len(data)} bytes')
        unpacked_items.append(self._pack('setup.nsis', None, archive.script.encode('utf-8'))) 
        return unpacked_items



