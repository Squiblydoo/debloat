#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Most of this code was repurposed from Binary Refinery (https://github.com/binref/refinery), used under the 3-Clause BSD License

from __future__ import annotations
import io
import itertools
import enum
import struct
import re
import functools
from types import TracebackType
from typing import List, Union, Tuple, Optional, Iterable, TypeVar, Generic, Any

T = TypeVar('T', bound=Union[bytearray, bytes, memoryview])
UnpackType = Union[int, bool, float, bytes]

def signed(k: int, bits: int):
    M = 1 << bits
    k = k & (M - 1)
    return k - M if k >> (bits - 1) else k

def exception_to_string(exception: BaseException, default=None) -> str:
    """
    Attempts to convert a given exception to a good description that can be exposed to the user.
    """
    if not exception.args:
        return exception.__class__.__name__
    it = (a for a in exception.args if isinstance(a, str))
    if default is None:
        default = str(exception)
    return max(it, key=len, default=default).strip()

class StreamDetour:
    def __init__(self, stream: io.IOBase, 
                 offset=None, whence=io.SEEK_SET) -> None:
        self.stream = stream
        self.offset = offset
        self.whence = whence

    def __enter__(self) -> io.IOBase:
        self.cursor = self.stream.tell()
        if self.offset is not None:
            self.stream.seek(self.offset, self.whence)
        return self.stream
    
    def __exit__(self, *args) -> None:
        self.stream.seek(self.cursor, io.SEEK_SET)

class MemoryFile(Generic[T], io.IOBase):

    closed: bool
    read_as_bytes: bool

    _data: T
    _cursor: int   # Defines where in the file we are currently reading from
    _closed: bool

    class SEEK(int, enum.Enum):
        CUR = io.SEEK_CUR
        END = io.SEEK_END
        SET = io.SEEK_SET

    def __init__(self, data: T, read_as_bytes: bool = False, 
                 file_number: Optional[int] = None) -> None:
        self._data = data
        self._cursor = 0
        self._closed = False
        self.read_as_bytes = read_as_bytes
        self.file_number = file_number

    def close(self) -> None:
        self._closed = True

    @property
    def closed(self) -> bool:
        return self._closed
    
    # Enter and exit methods for context manager
    def __enter__(self) -> 'MemoryFile':
        return self
    
    def __exit__(self, exc_type: type[BaseException] | None, exc_val: BaseException | None, exc_tb: TracebackType | None) -> None:
        return super().__exit__(exc_type, exc_val, exc_tb)
    
    def flush(self) -> None:
        return super().flush()
    
    def isatty(self) -> bool:
        return super().isatty()

    def __iter__(self) -> Iterable[bytes]:
        return self
    
    def __len__(self) -> int:
        return len(self._data)
    
    def __next__(self) -> bytes:
        if self._cursor >= len(self._data):
            raise StopIteration
        else:
            return self.readline()
        
    def file_number(self) -> Optional[int]:
        if self.file_number is None:
            return None
        return self.file_number
    
    def readable(self) -> bool:
        return super().readable()
    
    def seekable(self) -> bool:
        return super().seekable()
    
    @property
    def is_eof(self) -> bool:
        return self._closed or self._cursor >= len(self._data)
    
    @property
    def remaining_bytes(self) -> int:
        return len(self._data) - self.tell()
    
    def writable(self) -> bool:
        if self._closed:
            return False
        # Readonly for memoryview?
        return isinstance(self._data, bytearray)

    def read(self, size: int = -1, peek: bool = False) -> T:
        beginning = self._cursor
        if size is None or size < 0:
            end = len(self._data)
        else:
            end = min(self._cursor + size, len(self._data))
        result = self._data[beginning:end]
        if self.read_as_bytes and not isinstance(result, bytes):
            result = bytes(result)
        if not peek:
            self._cursor = end
        return result
    
    def peek(self, size: int = -1) -> memoryview:
        cursor = self._cursor
        mv = memoryview(self._data)
        if size is None or size < 0:
            return mv[cursor:]
        return mv[cursor:cursor + size]
    
    def read1(self, size: int = -1, peek: bool = False) -> T:
        return self.read(size, peek)
    
    def _find_linebreak(self, beginning: int, end: int) -> int:
        if not isinstance(self._data, memoryview):
            return self._data.find(b'\n', beginning, end)
        for k in range(beginning, end):
            if self._data[k] == 0xA: return k
        return -1
    
    def readline(self, size: int = -1) -> T:
        beginning, end = self._cursor, len(self._data)
        if size is not None and size >= 0:
            end = beginning + size
        p = self._find_linebreak(beginning, end)
        self._cursor = end if p < 0 else p + 1
        result = self._data[beginning:self._cursor]
        if self.read_as_bytes and not isinstance(result, bytes):
            result = bytes(result)
        return result
    
    def readlines(self, size: int = -1) -> Iterable[T]:
        if size is None or size < 0:
            yield from self
        else:
            total = 0
            while total < size:
                line = next(self)
                total += len(line)
                yield line
    
    def readinto1(self, buffer: Any) -> int:
        data = self.read(len(buffer))
        size = len(data)
        buffer[:size] = data
        return size
    
    def readinto(self, buffer: Any) -> int: 
        return self.readinto1(buffer)

    def tell(self) -> int:
        return self._cursor
    
    def seek_relative(self, offset: int) -> int:
        return self.seek(self._cursor + offset)
        
    def seek_set(self, offset: int) -> int:
        if offset < 0:
            return self.seek(offset, self.SEEK.END)
        else:
            return self.seek(offset, self.SEEK.SET)
        
    def get_buffer(self) -> T:
        return self._data
    
    def get_value(self) -> T:
        return self._data
    
    def seek(self, offset: int, whence=io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            if offset < 0:
                raise ValueError('Negative seek position {}'.format(offset))    
            self._cursor = offset
        elif whence == io.SEEK_CUR:
            self._cursor += offset
        elif whence == io.SEEK_END:
            self._cursor = len(self._data) + offset
        self._cursor = max(0, min(self._cursor, len(self._data)))
        return self._cursor
    
    def write_lines(self, lines: Iterable[Union[bytes, bytearray, memoryview]]) -> None:
        for line in lines:
            self.append(line)

    def truncate(self, size=None) -> None:
        if size is not None:
            if not (0 <= size <= len(self._data)):
                raise ValueError('Invalid size {}'.format(size))
            self._cursor = size
        del self._data[self._cursor:]

    def append_byte(self, byte: int) -> None:
        try:
            cursor = self._cursor
            if cursor < len(self._data):
                self._data[cursor] = byte
            else:
                self._data.append(byte)
        except Exception as T:
            raise io.UnsupportedOperation('append_byte') from T
        else:
            self._cursor += 1

    def append(self, data: Iterable[int]) -> int:
        output_data = self._data
        end = len(output_data)
        beginning = self._cursor
        if beginning == end:
            output_data.extend(data)
            self._cursor = end = len(output_data)
            return end - beginning
        try:
            size = len(data)
        except Exception as T:
            it = iter(data)
            for cursor, byte in enumerate(it, end - beginning):
                output_data[cursor] = byte
                if cursor >= end - 1:
                    break
            else:
                cursor += 1
                self._cursor = cursor
                return cursor - beginning
            output_data.extend(it)
        else:
            self._cursor += size
            try:
                self._data[beginning:self._cursor] = data
            except Exception as T:
                self._cursor = beginning
                raise io.UnsupportedOperation('append') from T
            return size
        self._cursor = end = len(output_data)
        return end - beginning

    def __getitem__(self, slice: Any) -> T:
        result = self._data[slice]
        if isinstance(result, bytes) and not self.read_as_bytes:
            result = bytes(result)
        return result

    def replay(self, offset: int, length: int) -> None:
        if offset not in range(self._cursor + 1):
            raise ValueError('Invalid offset {}'.format(offset))
        rep, r = divmod(length, offset)
        offset = -offset - len(self) + self._cursor
        replay = self._data[offset:offset + r]
        if rep > 0:
            replay = bytes(self._data[offset:self._cursor]) * rep + replay
        self.append(replay)


class order(str, enum.Enum):
    big = 'big'
    little = 'little'

class StructReader(MemoryFile[T]):

    class Unaligned(RuntimeError):
        pass

    def __init__(self, data: T, bigendian: bool = False):
        super().__init__(data)
        self._number_of_bits = 0
        self._buffer_bits = 0
        self._bigendian = bigendian
    
    def __enter__(self) -> 'StructReader':
        return self
    
    def __exit__(self) -> None:
        return super().__exit__()

    @property
    def bigendian(self):
        self.bigendian = True
        try:
            yield self
        finally:
            self.bigendian = False
    
    @property
    def byteorder_format(self) -> str:
        return '>' if self.bigendian else '<'
    
    @property
    def byteorder_name(self) -> str:
        return 'big' if self._bigendian else 'little'

    def readinto(self, buffer: Any) -> int:
        return super().readinto(buffer)
    
    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        return super().seek(offset, whence)
    
    def read_exactly(self, size: Optional[int] = None,
                      peek: bool = False) -> T:
        if not self.byte_aligned:
            raise StructReader.Unaligned('Buffer is not byte aligned')
        data = self.read1(size, peek)
        if size and len(data) < size:
            raise EOF(data)
        return data
        
    @property
    def byte_aligned(self) -> bool:
        return not self._number_of_bits
    
    def byte_align(self, blocksize: int = 1) -> Tuple[int, int]:
        if self.byte_aligned:
            return 0, 0
        number_of_bits = self._number_of_bits
        buffer_bits = self._buffer_bits
        self._number_of_bits = 0
        self._buffer_bits = 0
        mod = self._cursor % blocksize
        self.seek_relative(mod and blocksize - mod)
        return number_of_bits, buffer_bits
    
    # TODO: Review Read Integer if needed
    def read_integer(self, length: int, peek: bool = False) -> int:
        """
        Read `length` many bits from the underlying stream as an integer.
        """
        if length < self._number_of_bits:
            new_count = self._number_of_bits - length
            if self.bigendian:
                result = self._buffer_bist >> new_count
                if not peek:
                    self._buffer_bist ^= result << new_count
            else:
                result = self._buffer_bist & 2 ** length - 1
                if not peek:
                    self._buffer_bist >>= length
            if not peek:
                self._number_of_bits = new_count
            return result


        number_of_bits, buffer_bits = self.byte_align()
        number_of_missing_bits = length - number_of_bits
        bytecount, rest = divmod(number_of_missing_bits, 8)
        if rest:
            bytecount += 1
            rest = 8 - rest
        if bytecount == 1:
            result, = self.read_exactly(1, peek)
        else:
            result = int.from_bytes(self.read_exactly(bytecount, peek), self.byteorder_name)
        if not number_of_bits and not rest:
            return result
        if self.bigendian:
            rbmask   = 2 ** rest - 1       # noqa
            excess   = result & rbmask     # noqa
            result >>= rest                # noqa
            result  ^= buffer_bits << number_of_missing_bits   # noqa
        else:
            excess   = result >> number_of_missing_bits  # noqa
            result  ^= excess << number_of_missing_bits  # noqa
            result <<= number_of_bits               # noqa
            result  |= buffer_bits               # noqa
        assert excess.bit_length() <= rest
        if not peek:
            self._number_of_bits = rest
            self._buffer_bist = excess
        return result
        
    def read_bytes(self, size: int, peek: bool = False) -> bytes:
        if self.byte_aligned:
            data = self.read_exactly(size, peek)
            if not isinstance(data, bytes):
                data = bytes(data)
            return data
        else:
            return self.read_bits(size * 8, peek).tobytes()
        
    def read_bit(self) -> int:
        return self.read_integer(1)
    
    def read_bits(self, number_of_bits: int) -> Iterable[int]:
        chunk = self.read_integrer(number_of_bits) 
        for k in range(number_of_bits -1, -1, -1):
            yield chunk >> k & 1

    def read_flags(self, number_of_bits: int, reverse=False) -> Iterable[bool]:
        bits = list(self.read_bits(number_of_bits))
        if reverse:
            bits.reverse()
        for bit in bits:
            yield bool(bit)

    def read_struct(self, spec: str, unwrap=False, 
                    peek=False) -> Union[List[UnpackType], UnpackType]:
        if not spec:
            raise ValueError('No format specified')
        byte_order = spec[:1]
        if byte_order in '<!=@>':
            spec = spec[1:]
        else:
            byte_order = self.byteorder_format
        data = []
        current_cursor = self.tell()

        for k, part in enumerate(re.split('(\\d*[auwE])', spec)):
            if k % 2 == 1:
                count = 1 if len(part) == 1 else int(part[:~0])
                part = part[~0]
                for _ in range(count):
                    if part == 'a':
                        size = self.read_integer(8)
                        data.append(self.read_bytes(size))
                    elif part == 'u':
                        data.append(self.read_integer(8))
                    elif part == 'w':
                        data.append(self.read_integer(16))
                    elif part == 'E':
                        data.append(self.read_integer(32))
                    else:
                        raise ValueError('Invalid format {}'.format(part))
                continue
            else:
                part = F'{byte_order}{part}'
                data.extend(struct.unpack(part, self.read_exactly(struct.calcsize(part))))
        if unwrap and len(data) == 1:
            return data[0]
        if peek:
            self.seek_set(current_cursor)
        return data

    def read_nibble(self, peek: bool = False) -> int:
        return self.read_integer(4, peek)


    def u8(self, peek: bool = False) -> int: 
        return self.read_integer(8, peek)
    def i8(self, peek: bool = False) -> int: 
        return signed(self.read_integer(8, peek), 8)
    def u16(self, peek: bool = False) -> int: 
        return self.read_integer(16, peek)
    def u32(self, peek: bool = False) -> int: 
        return self.read_integer(32, peek)
    def u64(self, peek: bool = False) -> int: 
        return self.read_integer(64, peek)
    def i16(self, peek: bool = False) -> int: 
        return signed(self.read_integer(16, peek), 16)
    def i32(self, peek: bool = False) -> int: 
        return signed(self.read_integer(32, peek), 32)
    def i64(self, peek: bool = False) -> int: 
        return signed(self.read_integer(64, peek), 64)
    def f32(self, peek: bool = False) -> float: 
        return self.read_struct('f', unwrap=True, peek=peek)
    def f64(self, peek: bool = False) -> float: 
        return self.read_struct('d', unwrap=True, peek=peek)
    def read_byte(self, peek: bool = False) -> int: 
        return self.read_integer(8, peek)
    def read_char(self, peek: bool = False) -> int:
        return signed(self.read_integer(8, peek), 8)

    def read_terminated_array(self, terminator: bytes, 
                              alignment: int = 1) -> bytearray:
        pos = self.tell()
        buffer = self.get_buffer()
        try:
            end = pos - 1
            while True:
                end = buffer.find(terminator, end + 1)
                if end < 0 or not (end - pos) % alignment:
                    break
        except AttributeError:
            result = bytearray()
            while not self.is_eof:
                result.extend(self.read_bytes(alignment))
                if result.endswith(terminator):
                    return result[:-len(terminator)]
            self.seek(pos)
            raise EOF
        else:
            data = self.read_exactly(end - pos)
            self.seek_relative(len(terminator))
            return bytearray(data)
    
    def read_c_string(self, encoding=None) -> Union[str, bytearray]:
        data = self.read_terminated_array(b'\0')
        if encoding is not None:
            data = data.decode(encoding)
        return data
    
    def read_w_string(self, encoding=None) -> Union[str, bytearray]:
        data = self.read_terminated_array(b'\0\0', 2)
        if encoding is not None:
            data = data.decode(encoding)
        return data
    
    def read_length_prefixed(self, 
                             prefix_size: int = 32, 
                             encoding: Optional[str] = None,
                             block_size: int = 1) -> Union[T, str]:
        prefix = self.read_integer(prefix_size) * block_size
        data = self.read(prefix)
        if encoding is not None:
            data = data.decode(encoding)
        return data

    def read_length_prefixed_ascii(self, 
                                   prefix_size: int = 32) -> Union[T, str]:
        return self.read_length_prefixed(prefix_size, 'ascii')
    
    def read_length_prefixed_utf8(self, 
                                  prefix_size: int = 32) -> Union[T, str]:
        return self.read_length_prefixed(prefix_size, 'utf-8')
    
    def read_length_prefixed_utf16(self, 
                                   prefix_size: int = 32,
                                   bytecount: bool = False) -> Union[T, str]:
        block_size = 1 if bytecount else 2
        return self.read_length_prefixed(prefix_size, 'utf-16le', block_size)
    
    # TODO: Review function if needed
    def read_7bit_encoded_int(self, max_bits: int = 0) -> int:
        result = 0
        for k in itertools.count():
            if k == max_bits:
                raise ValueError('Invalid 7-bit encoded integer')
            byte = self.read_byte()
            result |= (byte & 0x7F) << (7 * k)
            if not byte & 0x80:
                break
        return result

class StructMeta(type):
    def __new__(mcls, name, bases, nmspc, parser=StructReader):
        return type.__new__(mcls, name, bases, nmspc)
    
    def __init__(cls, name, bases, nmspc, parser=StructReader):
        super(StructMeta, cls).__init__(name, bases, nmspc)
        original__init__ = cls.__init__

        @functools.wraps(original__init__)
        def wrapped__init__(self: Struct, reader, *args, **kwargs):
            if not isinstance(reader, parser):
                if issubclass(parser, reader.__class__):
                    raise ValueError(
                        F'A reader of type {reader.__class__.__name__} was passed to {cls.__name__}, '
                        F'but a {parser.__name__} is required.')
                reader = parser(reader)
            start = reader.tell()
            view = memoryview(reader.get_buffer())
            original__init__(self, reader, *args, **kwargs)
            self.__data = view[start:reader.tell()]

        cls.__init__ = wrapped__init__

class Struct(metaclass=StructMeta):

    _data: Union[memoryview, bytearray]

    def __len__(self):
        return len(self._data)
    
    def __bytes__(self):
        return bytes(self._data)   
    
    def get_data(self, decouple=False):
        if decouple and isinstance(self._data, memoryview):
            self._data = bytearray(self._data)
        return self._data
    
    def __init__(self, reader: StructReader):
        pass

    


class EOF(EOFError):
    def __init__(self, rest: Union[bytes, bytearray, memoryview] = b''):
        super().__init__('End of File')
        self.rest = rest