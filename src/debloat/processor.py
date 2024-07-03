"""
This file handles the processing of binaries and helper methods.

Three methods rely heavily on parts of Binary Refinery
https://github.com/binref/refinery
Copyright 2019 Jesko Hüttenhain under the 3-Clause BSD License
The methods are:
refinery_strip()
adjust_offsets()
refinery_trim_resources()
The RSRC Class is also from refinery.
"""
from pathlib import Path
import re
from typing import Tuple, Optional, Any, Callable, List
import pefile
import binascii
import zlib
from pefile import Structure, SectionStructure, DIRECTORY_ENTRY
from typing import Generator, Iterable, Optional

import debloat.utilities.nsisParser as nsisParser
import debloat.utilities.rsrc as rsrc

DEBLOAT_VERSION = "1.5.6.6"

RESULT_CODES = {
    0: "No Solution found.",
    1: "Junk after signature.",
    2: "Single repeated byte in overlay.",
    3: "Pattern in overlay.",
    4: "Sets of repeated bytes in overlay.",
    5: "NSIS Installer.",
    6: "Bloat in PE resources",
    7: "Bloat in PE section",
    8: "Bloat in .NET resource",
    9: "Non-essential, high entropy overlay",
    10: "High compression with bytes at end.",
    11: ".NET Single File with junk",
    12: "Packed file with bloated section",
    13: "Random overlay with high compression",
    14: "Junk interspersed with data",
    15: "VMProtected junk",
}


_KB = 1000
_MB = _KB * _KB

def readable_size(value: int) -> str:
    '''Return bytes in human readable format.'''
    if value <= 1024:
        return '%s bytes' % value
    elif value < 1024 * 1024:
        return '%.1f KB' % (float(value) / 1024.0)
    elif value < 1024 * 1024 * 1024:
        return '%.1f MB' % (float(value) / 1024.0 / 1024.0)
    else:
        return '%.1f GB' % (float(value) / 1024.0 / 1024.0 / 1024.0)

def write_multiple_files(out_path: str,
                         files: list, log_message: Callable[[str], None]) -> None:
    '''
    Writes multiple files to disk when applicable.
    '''
    log_message("Installer unpacked!\n")
    log_message(f"The files are being written to {out_path}")
    for file in files:
        out_file_path = Path(out_path) / Path(file.path.replace("\\", "/"))
        out_dir_path = out_file_path.parent
        out_dir_path.mkdir(parents=True, exist_ok=True)
        with open(out_file_path, "wb") as f:
            f.write(file.data)
            log_message("File: " + str(Path(file.path.replace("\\", "/"))))
    log_message("")
    log_message("The user will need to determine which file is malicious if any.")
    log_message("If a file is bloated: resubmit it through the tool to debloat it.")
    log_message(f"Consider reviewing the 'setup.nsis' from the installer to determine how the files were meant to be used.")
    return 


def write_patched_file(out_path: str,
                        pe: pefile.PE) -> Tuple[int, str]:
    '''Writes the patched file to disk.

    Keyword Arguments:
    out_path -- the path and file name to write
    pe -- the pefile that is being processed
    end_of_real_data -- an int indicating the size of bytes to write'''
    with open(out_path, 'wb') as writer:
        writer.write(pe.write())
        final_filesize = len(pe.write())
        return final_filesize, out_path

def handle_signature_abnormality(signature_address: int,
                                signature_size: int,
                                beginning_file_size: int) -> bool:
    '''Remove all bytes after a PE signature'''
    # If the signature_address is 0, there was no original signature.
    # We are setting the signature address to the filesize in order to
    # skip the next check.
    if signature_address == 0:
        signature_address = beginning_file_size
    # Check to see if there is data after the signature; if so, it is
    #  junk data
    if beginning_file_size > (signature_address + signature_size):
        return True
    return False

def check_and_extract_NSIS(possible_header: bytearray, pe: pefile.PE) -> list:
    '''Check if the PE is an NSIS installer.'''
    extractor = nsisParser.extractNSIS()
    confirm_if_nsis = extractor._find_archive_offset(memoryview(possible_header))
    if confirm_if_nsis is None:
        return
    extracted_files = extractor.unpack(memoryview(pe.__data__))
    return extracted_files


def find_last_section(pe: pefile.PE) -> Optional[pefile.SectionStructure]:
    '''Iterate through PE sections to identify the last one.'''
    last_section = None
    for section in pe.sections:
        if last_section is None \
                        or section.PointerToRawData > last_section.PointerToRawData:
            last_section = section
    return last_section

def get_signature_info(pe: pefile.PE, cert_preservation) -> Tuple[int, int]:
    '''Remove PE signature and update header.'''
    signature_address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    signature_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = 0
    # If the cert is to be preservered, we do not need to modify the size in the header. 
    if cert_preservation == False:
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = 0

    return signature_address, signature_size


def adjust_offsets(pe: pefile.PE, gap_offset: int, gap_size: int):
    base = pe.OPTIONAL_HEADER.ImageBase
    alignment = pe.OPTIONAL_HEADER.FileAlignment
    rva_offset = pe.get_rva_from_offset(gap_offset)
    tva_offset = rva_offset + base

    section = pe.get_section_by_offset(gap_offset)
    new_section_size = section.SizeOfRawData - gap_size
    if new_section_size % alignment != 0:
        raise RuntimeError(
            F'trimming 0x{gap_size:X} bytes from section {(section.Name)} of size 0x{section.SizeOfRawData:X} '
            F'violates required section alignment of 0x{alignment:X} bytes')
    inside_section_offset = gap_offset - section.PointerToRawData
    if inside_section_offset > new_section_size:
        overlap = inside_section_offset - new_section_size
        raise RuntimeError(F'trimming from section {(section.Name)}; data extends {overlap} beyond section')

    rva_lbound = section.VirtualAddress
    rva_ubound = section.VirtualAddress + section.Misc_VirtualSize - 1
    tva_lbound = rva_lbound + base
    tva_ubound = rva_ubound + base

    def adjust_attributes_of_structure(
        structure: Structure,
        threshold: int,
        valid_values_lower_bound: Optional[int],
        valid_values_upper_bound: Optional[int],
        attributes: Iterable[str]
    ):
        for attribute in attributes:
            old_value = getattr(structure, attribute, 0)
            if old_value <= gap_offset:
                continue
            if valid_values_lower_bound is not None and old_value < valid_values_lower_bound:
                continue
            if valid_values_upper_bound is not None and old_value > valid_values_upper_bound:
                continue
            new_value = old_value - gap_size
            if new_value < gap_offset:
                raise RuntimeError(F'adjusting attribute {attribute} of {structure.name} would result in negative value: {new_value}')
            setattr(structure, attribute, new_value)

    it: Iterable[Structure] = iter(pe.__structures__)
    remove = []

    for index, structure in enumerate(it):
        old_offset = structure.get_file_offset()
        new_offset = old_offset - gap_offset

        if old_offset > gap_offset:
            if old_offset < gap_offset + gap_size:
                remove.append(index)
                continue
            if isinstance(structure, SectionStructure) and new_offset % alignment != 0:
                raise RuntimeError(
                    F'section {(structure.Name)} would be moved to offset 0x{new_offset:X}, '
                    F'violating section alignment value 0x{alignment:X}.')
            structure.set_file_offset(new_offset)

        try:
            adjust_attributes_of_structure(structure, rva_offset, rva_lbound, rva_ubound, (
                'OffsetToData',
                'AddressOfData',
                'VirtualAddress',
                'AddressOfNames',
                'AddressOfNameOrdinals',
                'AddressOfFunctions',
                'AddressOfEntryPoint',
                'AddressOfRawData',
                'BaseOfCode',
                'BaseOfData',
            ))
            adjust_attributes_of_structure(structure, tva_offset, tva_lbound, tva_ubound, (
                'StartAddressOfRawData',
                'EndAddressOfRawData',
                'AddressOfIndex',
                'AddressOfCallBacks',
            ))
            adjust_attributes_of_structure(structure, gap_offset, None, None, (
                'OffsetModuleName',
                'PointerToRawData',
            ))
        except Exception as e:
            remove.append(index)
            continue

        for attribute in (
            'CvHeaderOffset',
            'OffsetIn2Qwords',
            'OffsetInQwords',
            'Offset',
            'OffsetLow',
            'OffsetHigh'
        ):
            if not hasattr(structure, attribute):
                continue
    
    while remove:
        index = remove.pop()
        pe.__structures__[index:index + 1] = []

    section.SizeOfRawData = new_section_size
    return pe


def refinery_strip(data: memoryview, alignment=1, block_size=_MB) -> int:
    if not data:
        return 0
    threshold = 0.15
    data_overhang = len(data) % alignment
    result = data_overhang

    if 0 < threshold < 1:
        def compression_ratio(offset: int):
            ratio = len(zlib.compress(data[:offset], level=1)) / offset
            return ratio
        upper = len(data)
        lower = result

        if compression_ratio(upper) <= threshold:
            while block_size < upper - lower:
                pivot = (lower + upper) // 2
                ratio = compression_ratio(pivot)
                if ratio > threshold:
                    lower = pivot + 1
                    continue
                upper = pivot
                if abs(ratio - threshold) < 1e-10:
                    break
        result = upper
    while result > 1 and data[result - 2] == data[result -1]:
        result -= 1

    result = max(result, data_overhang)

    result = result + (data_overhang - result) % alignment

    if result > len(data):
        excess = result - len(data)
        excess = excess + (-excess % alignment)
        result = result - excess

    return result


def refinery_trim_resources(pe: pefile.PE, data_to_delete: List) -> int:
    size_limit = 10000
    size_removed = 0

    def find_bloated_resources(pe: pefile.PE, directory, level: int = 0, *path) -> Generator[Structure, None, None]:
        for entry in directory.entries:
            name = getattr(entry, 'name')
            numeric_id = getattr(entry, 'id')
            if not name:
                if level == 0 and numeric_id in iter(rsrc.RSRC):
                    name = rsrc.RSRC(entry.id)
                elif numeric_id is not None:
                    name = str(numeric_id)
            name = name and str(name) or '?'
            if entry.struct.DataIsDirectory:
                yield from find_bloated_resources(pe, entry.directory, level + 1, *path, name)
                continue
            struct: Structure = entry.data.struct
            name = '/'.join((*path, name))
            if struct.Size <= size_limit:
                continue
            yield name, struct

    RSRC_INDEX = DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']
    pe.parse_data_directories(directories=[RSRC_INDEX])

    try:
        resources = pe.DIRECTORY_ENTRY_RESOURCE
    except AttributeError:
        return 0
    for name, resource in find_bloated_resources(pe, resources):
        offset = pe.get_offset_from_rva(resource.OffsetToData)
        # Offset may be modified from debloating a previous resource
        original_offset = offset
        for slice_start, slice_end in data_to_delete:
            if slice_start <= original_offset:
                original_offset += slice_end-slice_start
        old_size = resource.Size
        new_size = refinery_strip(memoryview(pe.__data__)[original_offset:original_offset + old_size], pe.OPTIONAL_HEADER.FileAlignment)
        gap_size = old_size - new_size
        if gap_size <= 0:
            continue
        resource.Size = new_size
        adjust_offsets(pe, offset + new_size, gap_size)
        size_removed += gap_size
        data_to_delete.append((original_offset + new_size, original_offset + old_size))

    pe.OPTIONAL_HEADER.DATA_DIRECTORY[RSRC_INDEX].Size -= size_removed

def get_compressed_size(data: memoryview, offset: int, level: int = -1):
    if offset <= 1024:
        return len(zlib.compress(data[:offset], level=level))

    compress_obj = zlib.compressobj(level=level)
    compress_data_len = 0
    index = 0
    for index in range(offset//1024):
        chunk = data[index*1024 : (index+1)*1024]
        compress_data_len += len(compress_obj.compress(chunk))
    leftover = offset%1024
    if leftover:
        chunk = data[(index+1)*1024 : (index+1)*1024 + leftover]
        compress_data_len += len(compress_obj.compress(chunk))
    compress_data_len += len(compress_obj.flush())
    return compress_data_len

def check_section_compression(pe: pefile.PE, data_to_delete: List,
                              log_message: Callable[[str], None]) -> Tuple[pefile.PE, int, str]:
        biggest_section = None
        biggest_uncompressed = int
        result = ""
        for section in pe.sections:
            section_name = section.Name.decode()
            compressed_section_size = get_compressed_size(
                memoryview(pe.__data__)[section.PointerToRawData : section.PointerToRawData+section.SizeOfRawData],
                section.SizeOfRawData
            )
            section_compression_ratio = section.SizeOfRawData / compressed_section_size * 100
            log_message("Section: "  + section_name, end="\t", flush=True)
            log_message(" Compression Ratio: " + str(round(section_compression_ratio, 2)) +"%", end="\t",flush=True)
            log_message("Size of section: " + readable_size(section.SizeOfRawData) +".",flush=True)
            if biggest_section is None or section.SizeOfRawData > biggest_section.SizeOfRawData:
                biggest_section = section
                biggest_uncompressed = section_compression_ratio
        # Handle specific bloated sections
        if biggest_section.Name.decode() == ".rsrc\x00\x00\x00":
            # Get biggest resource or resources and drop them from the
            # Resource table
            log_message('''
Bloat was located in the resource section. Removing bloat..
''')
            refinery_trim_resources(pe, data_to_delete)
            result_code = 6 # Bloated resource
            return result, result_code

        elif biggest_section.Name.decode() == ".text\x00\x00\x00" and biggest_uncompressed > 3000:
            # Data stored in the .text section is often a .NET Resource. The following checks
            # to confirm it is .NET and then drops the resources.
            if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size:
                log_message('''
Bloat was detected in the text section. Bloat is likely in a .NET Resource
This use case cannot be processed at this time. ''')
            result_code = 0 # No solution
            return result, result_code
        if biggest_uncompressed > 3000:
            log_message('''
The compression ratio of ''' + biggest_section.Name.decode() + ''' is indicative of a bloated section.
''', end="", flush=True)
            # Get the size of the section.
            biggest_section_end = biggest_section.PointerToRawData + biggest_section.SizeOfRawData
            original_section_size = biggest_section.SizeOfRawData
            biggest_section_data = memoryview(pe.__data__)[biggest_section.PointerToRawData:biggest_section_end]
            delta_last_non_junk, result_code = trim_junk(pe, biggest_section_data, original_section_size)
            # Remove the junk from the section.
            if delta_last_non_junk > original_section_size:
                log_message("Section was not able to be reduced.")
                result_code = 0
                return result, result_code
            data_to_delete.append((biggest_section.PointerToRawData + delta_last_non_junk, biggest_section_end))
            
            section_bytes_to_remove = original_section_size - delta_last_non_junk
            # Adjust all offsets for the file.
            adjust_offsets(pe, biggest_section.PointerToRawData, section_bytes_to_remove)
            log_message("Bloated section reduced.")
            result_code = 7 # Bloated PE section
            return result, result_code

        # If no bloat was found, return an expected return value
        result_code = 0 # No solution
        return result, result_code

def find_chunk_start(targeted_regex, chunk_start, original_size_with_junk, bloated_content: memoryview, step):
    bloated_content_len = len(bloated_content)
    compiled_targeted_regex = re.compile(targeted_regex)
    chunk_end = chunk_start
    while original_size_with_junk > chunk_end:
        chunk_end = chunk_start + step
        targeted_regex_match = compiled_targeted_regex.search(binascii.hexlify(bytes(bloated_content[max(bloated_content_len - chunk_end, 0):bloated_content_len - chunk_start])[::-1]))
        if targeted_regex_match:
            chunk_start += targeted_regex_match.end(0)
        else:
            # If the targeted_regex_match does not
            # return anything, that indicates the previous loop
            # had content which did not match. We'll use that
            # to help ensure we do not remove too much of the file.
            chunk_start -= step * 2
            break
    return chunk_start

def trim_junk(pe: pefile.PE, bloated_content: memoryview,
              original_size_with_junk: int) -> int:
    '''Attempts multiple methods to trim junk from the end of a section.'''
    alignment = pe.OPTIONAL_HEADER.FileAlignment

    # Regex Explained:
    # Match raw bytes that are repeated more than 20 times at the end
    # of a binary.
    delta_last_non_junk = original_size_with_junk
    # First Method: Trims 1 repeating byte.
    # Check against 200 bytes, if successful, calculate full match.
    junk_match = re.search(rb'^(..)\1{20,}', bytes(bloated_content[:-601:-1]))
    chunk_start = 0
    if not junk_match:
        # Second method: remove junk using refinery_strip. This method
        # is more efficent than a previous check that was used here.
        delta_last_non_junk = refinery_strip(bloated_content, alignment)
        result_code = 3 # Pattern in overlay.

    # Junk was identified. A new size is assigned and returned.
    else:
        # First method continued...
        bloated_content_len = len(bloated_content)
        targeted_regex = rb"("+ binascii.hexlify(junk_match.group(1)) + rb")\1{1,}"
        precompiled_chunk = binascii.hexlify(junk_match.group(1)) * int(1000/len(junk_match.group(1)))
        chunk_end = chunk_start
        while original_size_with_junk > chunk_end:
            chunk_end = chunk_start + 1000
            chunk = binascii.hexlify(bytes(bloated_content[max(bloated_content_len - chunk_end, 0):bloated_content_len - chunk_start])[::-1])
            if chunk == precompiled_chunk:
                chunk_start += 1000
                continue
            else:
                # If the chunk does not match the precompiled chunk,
                # we will return to the previous chunk_start in order
                # to ensure important bytes are not removed.
                if chunk_start > 1000:
                    chunk_start -= 1000
                break
        junk_to_remove = chunk_start 

        # Third Method: check for a series of one repeated byte.
        # If the trimming did not remove more than half of the bytes then
        # this suggests the attacker may have put a random series of
        # repeated bytes. We use refinery_trim for efficiency.
        if junk_to_remove * 2 < original_size_with_junk / 2:
            delta_last_non_junk = refinery_strip(bloated_content, alignment)
            junk_to_remove = 0 # Reset junk_to_remove because Refinery Strip will remove it.
            result_code = 4 # Sets of repeated bytes in overlay.
        else:
            result_code = 2 # Single repeated byte in overlay
        delta_last_non_junk -= junk_to_remove

    # The returned size must account for the file alignment.
    # We will make sure it is aligned by adding bytes.
    not_aligned = alignment - (delta_last_non_junk % alignment)
    delta_last_non_junk = delta_last_non_junk + not_aligned
    if not result_code:
        result_code = 0
    return delta_last_non_junk, result_code

def process_pe(pe: pefile.PE, out_path: str, last_ditch_processing: bool,
                cert_preservation: bool,log_message: Callable[[str], None], 
                beginning_file_size: int = 0) -> None:
    '''Prepare PE, perform checks, remote junk, write patched binary.'''
    result_code = 0
    if not beginning_file_size:
        beginning_file_size = len(pe.write())

    # Remove Signature and modify size of Optional Header Security entry.
    signature_address, signature_size = get_signature_info(pe, cert_preservation)
    if cert_preservation == True:
        cert = [(signature_address, signature_address + signature_size)]
        certData = memoryview(pe.__data__)[signature_address:signature_address + signature_size]
        data_to_delete = [(signature_address, signature_address + signature_size)]
    else:
        if signature_size > 0:
            log_message("""A certificate is being removed from this file.\n-To preserve the certificate use the Cert Preservation option.""")
        data_to_delete = [(signature_address, signature_address + signature_size)]

    signature_abnormality = handle_signature_abnormality(signature_address,
                                                        signature_size,
                                                        beginning_file_size)
    if signature_abnormality:
        data_to_delete.append((signature_address + signature_size, beginning_file_size))
        result_code = 1  # Junk after signture

    # Handle Overlays: this includes packers and overlays which are completely junk
    elif pe.get_overlay_data_start_offset() and signature_size < len(pe.__data__) - pe.get_overlay_data_start_offset():
        possible_header = pe.__data__[pe.get_overlay_data_start_offset():pe.get_overlay_data_start_offset() + 30]
        # Check first to see if the file is NSIS
        nsis_extracted = check_and_extract_NSIS(possible_header, pe)
        if nsis_extracted:
            write_multiple_files(out_path, nsis_extracted, log_message)
            result_code = 5 # NSIS Installer
            return result_code

        else:
            log_message("Attempting dynamic trim...")
            last_section = find_last_section(pe)
            overlay = memoryview(pe.__data__)[last_section.PointerToRawData + last_section.SizeOfRawData:signature_address or beginning_file_size]
            
            # The following checks a sample of the overlay to determine if it will be able to be removed.
            overlay_compression_sample = get_compressed_size(memoryview(overlay)[-2000:], 2000)
            sample_compression = beginning_file_size / overlay_compression_sample 
            file_size_wo_overlay = len(memoryview(pe.__data__)[:last_section.PointerToRawData + last_section.SizeOfRawData])
            if sample_compression > 400000:
                required_data_from_overlay, result_code = trim_junk(pe, overlay, beginning_file_size)
                end_of_real_data = file_size_wo_overlay + required_data_from_overlay
                data_to_delete.append(((file_size_wo_overlay + required_data_from_overlay), beginning_file_size ))
                
            else:
                result, result_code = check_section_compression(pe, data_to_delete, log_message=log_message)
                if len(data_to_delete) == 1:
                    end_of_real_data = beginning_file_size
                else:
                    result_code = 12 # Packed with junk in section
                    end_of_real_data = beginning_file_size - sum(slice_end-slice_start for slice_start, slice_end in data_to_delete)

            if end_of_real_data > beginning_file_size * 0.9:
                if last_ditch_processing is True:
                    log_message("""
"Last ditch" switch detected. Running last ditch debloat technique:\n
This is the last resort that removes the whole overlay: this works in cases where the overlay lacks a pattern.
However, if the file does not run after this, it is in indicator that this method removed critical data.
                    """)
                    end_of_real_data = last_section.PointerToRawData + last_section.SizeOfRawData
                    data_to_delete.append((end_of_real_data, beginning_file_size))
                else:
                    log_message("""
Overlay was unable to be trimmed. Try unpacking with UniExtract2 or re-running
Debloat with the "--last-ditch" parameter."""
                                )
            elif result_code == 12:
                # The end was already determined and no more data needs to be removed.
                pass
            else:
                data_to_delete.append((end_of_real_data, beginning_file_size))
    # Handle bloated sections
    # TODO: break up into functions
    else:
        # In order to solve some use cases, we will find the biggest section
        # within the binary.
        result, result_code = check_section_compression(pe, data_to_delete, log_message=log_message)
        log_message(result)
    # All processing is done. Report results.
    # There is always the signature in the list
    if len(data_to_delete) == 0 or sum(slice_end-slice_start for slice_start, slice_end in data_to_delete) <= (beginning_file_size * 0.1):
        log_message("""No automated method for reducing the size worked. Please consider sharing the
sample for additional analysis.
Email: Squiblydoo@pm.me
Twitter: @SquiblydooBlog.
                    """)
        result_code = 0
        return result_code
    else:
        pe_data = bytearray()
        start = 0
        for slice_start, slice_end in sorted(data_to_delete):
            pe_data += bytearray(pe.__data__[start:slice_start])
            start = slice_end
        pe_data += bytearray(pe.__data__[start:beginning_file_size])
        if cert_preservation == True and signature_size > 0:
            pe_data += certData
            pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = len(pe_data) - signature_size

        pe.__data__ = pe_data
        final_filesize, new_pe_name = write_patched_file(out_path,
                                                         pe)
        reduction_calculation = round(((beginning_file_size \
                                        - final_filesize) \
                                        / beginning_file_size) * 100, 2)
        log_message("Beginning File size: " \
                + readable_size(beginning_file_size) + ".")
        log_message("File was reduced by " \
                    + str(reduction_calculation) + "%.")
        log_message("Final file size: " \
                    + readable_size(final_filesize) + ".")
        log_message("Processing complete.\nFile written to '" \
                    + str(new_pe_name) + "'.")
        return result_code
