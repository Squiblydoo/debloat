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
from typing import Tuple, Optional, Any, Callable
import pefile
import binascii
import zlib
from pefile import Structure, SectionStructure, DIRECTORY_ENTRY
from typing import Generator, Iterable, Optional

import debloat.utilities.nsisParser as nsisParser
import debloat.utilities.rsrc as rsrc

_KB = 1000
_MB = _KB * _KB

PACKER = {
    1 : "Nullsoft"
}

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
                         files: list, log_message: Callable[[str], None]) -> Tuple[int, str]:
    '''
    Writes multiple files to disk when applicable.
    '''
    log_message("Installer unpacked!\n")
    log_message(f"The files are being written {out_path}")
    for file in files:
        out_file_path = Path(out_path) / Path(file.path.replace("\\", "/"))
        out_dir_path = out_file_path.parent
        out_dir_path.mkdir(parents=True, exist_ok=True)
        with open(out_file_path, "wb") as f:
            f.write(file.data)
            log_message("File written: " + str(Path(file.path.replace("\\", "/"))))
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

def check_and_extract_NSIS(possible_header: bytearray, data: bytearray) -> list:
    '''Check if the PE is an NSIS installer.'''
    extractor = nsisParser.extractNSIS()
    guess = extractor._find_archive_offset(possible_header)
    if guess is not None:
        files = extractor.unpack(data)
        return files

def check_for_packer(possible_header: bytearray) -> int:
    '''Check overlay bytes for known packers.'''
    # TODO: Evalute any other packers that need special processing.

    # NullSoft is not a packer, but an installer. We will detect this. It cannot be processed at this time
    NULLSOFT_MAGICS = [
        # https://nsis.sourceforge.io/Can_I_decompile_an_existing_installer
        B'\xEF\xBE\xAD\xDE' B'Null' B'soft' B'Inst',   # v1.6
        B'\xEF\xBE\xAD\xDE' B'Null' B'Soft' B'Inst',   # v1.3
        B'\xED\xBE\xAD\xDE' B'Null' B'Soft' B'Inst',   # v1.1
        B'\xEF\xBE\xAD\xDE' B'nsis' B'inst' B'all\0',  # v1.0
    ]

    for magic in range(len(NULLSOFT_MAGICS)):
        packer_header_match = re.search(NULLSOFT_MAGICS[magic], possible_header)
        if packer_header_match:
             # Future: Handle NSIS installers
            return 1 # Nullsoft
    return 0

def find_last_section(pe: pefile.PE) -> Optional[pefile.SectionStructure]:
    '''Iterate through PE sections to identify the last one.'''
    last_section = None
    for section in pe.sections:
        if last_section is None \
                        or section.PointerToRawData > last_section.PointerToRawData:
            last_section = section
    return last_section

def get_signature_info(pe: pefile.PE) -> Tuple[int, int]:
    '''Remove PE signature and update header.''' 
    signature_address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    signature_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = 0
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
        lbound: Optional[int],
        ubound: Optional[int],
        attributes: Iterable[str]
    ):
        for attribute in attributes:
            old_value = getattr(structure, attribute, 0)
            if old_value <= threshold:
                continue
            if lbound is not None and old_value < lbound:
                continue
            if ubound is not None and old_value > ubound:
                continue
            new_value = old_value - gap_size
            if new_value < 0:
                raise RuntimeError(F'adjusting attribute {attribute} of {structure.name} would result in negative value: {new_value}')
            setattr(structure, attribute, new_value)

    it: Iterable[Structure] = iter(pe.__structures__)

    for structure in it:
        old_offset = structure.get_file_offset()
        new_offset = old_offset - gap_offset

        if old_offset > gap_offset:
            if isinstance(structure, SectionStructure) and new_offset % alignment != 0:
                raise RuntimeError(
                    F'section {(structure.Name)} would be moved to offset 0x{new_offset:X}, '
                    F'violating section alignment value 0x{alignment:X}.')
            if old_offset < gap_offset + gap_size:
                raise RuntimeError(
                    F'structure starts inside removed region: {structure}')
            structure.set_file_offset(new_offset)

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

    section.SizeOfRawData = new_section_size
    return pe
    

def refinery_strip(pe: pefile.PE, data: memoryview, block_size=_MB) -> int:
    threshold = 1
    alignment = pe.OPTIONAL_HEADER.FileAlignment
    data_overhang = len(data) % alignment
    result = data_overhang

    if not data:
        return 0
    
    if 0 < threshold < 1:
        def compression_ratio(offset: int):
            ratio = len(zlib.compress(data[:offset], level=1))
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

    match = re.search(B'(?s).(?=\\x%02x+$)' % data[result - 1], data[:result])
    if match is not None:
        cutoff = match.start() - 1
        length = result - cutoff
        if length > block_size:
            result = cutoff

    result = max(result, data_overhang)

    result = result + (data_overhang - result) % alignment

    while result > len(data):
        result -= alignment

    return result


def refinery_trim_resources(pe: pefile.PE, pe_data: bytearray) -> int:
    size_limit = 50000
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
        old_size = resource.Size
        new_size = refinery_strip(pe, memoryview(pe_data)[offset:offset + old_size])
        gap_size = old_size - new_size
        gap_offset = offset + new_size
        if gap_size <= 0:
            continue
        resource.Size = new_size
        adjust_offsets(pe, gap_offset, gap_size)
        size_removed += gap_size
        pe_data[gap_offset:gap_offset + gap_size] = []

    pe.OPTIONAL_HEADER.DATA_DIRECTORY[RSRC_INDEX].Size -= size_removed
    return size_removed
        
    

def remove_resources(pe: pefile.PE, pe_data: bytearray) -> Tuple[bytearray, int]:
    trimmed = refinery_trim_resources(pe, pe_data)
    return trimmed

def check_section_compression(pe: pefile.PE, pe_data: bytearray, end_of_real_data, 
                          log_message: Callable[[str], None]) -> Tuple[pefile.PE, int, str]:
        biggest_section = None
        biggest_uncompressed = int
        result = ""
        for section in pe.sections:
            section_name = section.Name.decode()
            compressed_section_size = len(zlib.compress(
                pe.write()[section.PointerToRawData: 
                           (section.PointerToRawData + section.SizeOfRawData)]))
            uncompressed_section_size = section.SizeOfRawData
            section_compression_ratio = uncompressed_section_size / compressed_section_size * 100
            log_message("Section: "  + section_name, end="\t", flush=True)
            log_message(" Compression Ratio: " + str(round(section_compression_ratio, 2)) +"%", end="\t",flush=True) 
            log_message("Size of section: " + readable_size(section.SizeOfRawData) +".",flush=True)
            if biggest_section == None:
                biggest_section = section
                biggest_uncompressed = section_compression_ratio
            elif section.SizeOfRawData > biggest_section.SizeOfRawData:
                biggest_section = section
                biggest_uncompressed = section_compression_ratio
        # Handle specific bloated sections
        if biggest_section.Name.decode() == ".rsrc\x00\x00\x00":
            # Get biggest resource or resources and drop them from the 
            # Resource table
            log_message('''
Bloat was located in the resource section. Removing bloat.. 
''')
            bytes_removed = remove_resources(pe, pe_data)
            end_of_real_data =- bytes_removed
            return end_of_real_data, result
        elif biggest_section.Name.decode() == ".text\x00\x00\x00":
            # Data stored in the .text section is often a .NET Resource. The following checks
            # to confirm it is .NET and then drops the resources.
            if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size:
                log_message('''
Bloat was detected in the text section. Bloat is likely in a .NET Resource 
This use case cannot be processed at this time. ''')
            return end_of_real_data, result
        if biggest_uncompressed > 3000:
            log_message('''
The compression ratio of ''' + biggest_section.Name.decode() + ''' is indicative of a bloated section.
''', end="", flush=True)
            # Get the size of the section.
            biggest_section_end = biggest_section.PointerToRawData + biggest_section.SizeOfRawData
            original_section_size = biggest_section.SizeOfRawData
            biggest_section_data = pe_data[biggest_section.PointerToRawData:biggest_section_end]

            delta_last_non_junk = trim_junk(pe, biggest_section_data, original_section_size)
            # Remove the junk from the section.
            pe_data[biggest_section.PointerToRawData + delta_last_non_junk:biggest_section_end] = []
            section_bytes_to_remove = original_section_size - delta_last_non_junk
            end_of_real_data =  end_of_real_data - section_bytes_to_remove
            # Adjust all offsets for the file.
            adjust_offsets(pe, biggest_section.PointerToRawData, section_bytes_to_remove)
            log_message("Bloated section reduced.")
            return end_of_real_data, result
            
       
        
def trim_junk(pe: pefile.PE, bloated_content: bytes, 
              original_size_with_junk: int) -> int:
    '''Attempts multiple methods to trim junk from the end of a section.'''
    alignment = pe.OPTIONAL_HEADER.FileAlignment

    backward_bloated_content = bloated_content[::-1]
    # Regex Explained:
    # Match raw bytes that are repeated more than 20 times at the end
    # of a binary. 
    delta_last_non_junk = original_size_with_junk
    # First Method: Trims 1 repeating byte.
    # Check against 200 bytes, if successful, calculate full match.
    junk_match = re.search(rb'^(..)\1{20,}', backward_bloated_content[:600])
    # Second Method: If "not junk_match" check for junk larger than 1 repeating byte
    chunk_start = 0
    if not junk_match:
        # Brute force check: check to see if there are 1-20 bytes
        # being repeated and feed the number into the regex
        for i in range(300):
            # Regex Explained:
            # Starting at the end of the PE, check for repeated bytes.
            # This indicates junk bytes in the overlay. Match that set
            # of repeated bytes 1 or more times. 
            junk_regex = rb"^(..{" + bytes(str(i), "utf-8") + rb"})\1{2,}"
            multibyte_junk_regex = re.search(junk_regex, backward_bloated_content[:1000])
            if multibyte_junk_regex:
                # Having found the pattern, we can make the regex efficient
                # by targeting the pattern using the "targeted_regex"
                targeted_regex = rb"(" + binascii.hexlify(multibyte_junk_regex.group(1)) + rb")\1{1,}"
                chunk_end = chunk_start
                while original_size_with_junk > chunk_end:
                    chunk_end = chunk_start + 1000
                    targeted_multibyte_junk_regex = re.search(targeted_regex, 
                                                              binascii.hexlify(backward_bloated_content[chunk_start:chunk_end]))
                    if targeted_multibyte_junk_regex:
                        chunk_start += targeted_multibyte_junk_regex.end(0)
                        unmatched_portion = 1000 - targeted_multibyte_junk_regex.end(0)
                    else:
                        # If the targeted_multibyte_junk_regex does not
                        # return anything, that indicates the previous loop
                        # had content which did not match. We'll use that
                        # to help ensure we do not remove too much of the file. 
                        chunk_start += unmatched_portion 
                        break
                break
                # It was determined that data cannot be removed any more
                # from the chunk_start. But the value of chunk_start
                # now tells us how much data we can safely remove.
        junk_to_remove = chunk_start  
        #junk_to_remove = int(junk_to_remove)
        delta_last_non_junk -= junk_to_remove
    # Third Method: check for a series of one repeated byte. 
    # Junk was identified. A new size is assigned and returned.
    else:
        targeted_regex = rb""+ binascii.hexlify(junk_match.string) + rb"{1,}"
        targeted_junk_match = re.search(targeted_regex, binascii.hexlify(backward_bloated_content))
        junk_to_remove = targeted_junk_match.end(0)
        # If the trimming did not remove more than half of the bytes then
        # this suggests the attacker may have put a random series of
        # repeated bytes. These will be removed by loading the overlay
        # 200 bytes at a time and removing parts which repeat for more
        # than 20 bytes.
        if junk_to_remove < original_size_with_junk / 2:
            chunk_start = targeted_junk_match.end(0)
            chunk_end = chunk_start
            unmatched_portion = 0
            while original_size_with_junk > chunk_end:
                chunk_end = chunk_start + 200
                repeated_junk_match = re.search(rb'(..)\1{20,}', 
                                                binascii.hexlify(backward_bloated_content[chunk_start:chunk_end]))
                if repeated_junk_match:
                    chunk_start += repeated_junk_match.end(0)
                    unmatched_portion = 200 - repeated_junk_match.end(0)
                else:
                    chunk_start += unmatched_portion
                    break
            junk_to_remove = chunk_start 
        else:
            junk_to_remove = int(junk_to_remove / 2)
        delta_last_non_junk -= junk_to_remove
    
    # The returned size must account for the file alignment.
    # We will make sure it is aligned by adding bytes.
    not_aligned = delta_last_non_junk % alignment
    delta_last_non_junk = delta_last_non_junk - not_aligned

    return delta_last_non_junk  

def process_pe(pe: pefile.PE, out_path: str, last_ditch_processing: bool,
               log_message: Callable[[str], None]) -> None:
    '''Prepare PE, perform checks, remote junk, write patched binary.'''
    beginning_file_size = len(pe.write())
    # We are using the variable "end_of_real_data" and are reassigning 
    # the value based on our analysis.We are assigning it now in case 
    # we are unable to reduce the binary size for any reason.
    end_of_real_data = beginning_file_size
    pe_data = bytearray(pe.__data__)
    # Remove Signature and modify size of Optional Header Security entry.
    signature_address, signature_size = get_signature_info(pe)
    pe_data[signature_address:signature_address + signature_size] = []
    signature_abnormality = handle_signature_abnormality(signature_address, 
                                                        signature_size, 
                                                        beginning_file_size)
    if signature_abnormality:
        log_message('''
We detected data after the signature. This is abnormal. Removing signature and extra data...''')
        end_of_real_data = signature_address
        pe_data = pe_data[:end_of_real_data]
    # Handle Overlays: this includes packers and overlays which are completely junk
    elif pe.get_overlay_data_start_offset() and signature_size < len(pe.get_overlay()):
        possible_header = pe.write()[pe.get_overlay_data_start_offset():pe.get_overlay_data_start_offset() + 30]
        # Check first to see if the file is NSIS
        nsis_extracted = check_and_extract_NSIS(possible_header, pe_data)
        if nsis_extracted:
            write_multiple_files(out_path, nsis_extracted, log_message)
            return 0
        log_message("An overlay was detected. Checking for known packer.")
        packer_idenfitied = check_for_packer(possible_header)
        if packer_idenfitied:
            log_message("Packer identified: " + PACKER[packer_idenfitied])
            if PACKER[1]:
                log_message("Nullsoft Installer, but unable to extract.")
        else:
            log_message("Packer not identified. Attempting dynamic trim...")
            last_section = find_last_section(pe)
            overlay = pe_data[last_section.PointerToRawData + last_section.SizeOfRawData:]
            end_of_real_data = trim_junk(pe, overlay, end_of_real_data)
            pe_data = pe_data[:end_of_real_data]
            if end_of_real_data > (beginning_file_size * 0.9) or end_of_real_data == beginning_file_size :
                if last_ditch_processing is True:
                    log_message("""
"Last ditch" switch detected. Running last ditch debloat technique:\n
This is the last resort that removes the whole overlay: this works in cases where the overlay lacks a pattern.
However, if the file does not run after this, it is in indicator that this method removed critical data.
                    """)
                    last_section = find_last_section(pe)
                    end_of_real_data = last_section.PointerToRawData + last_section.SizeOfRawData
                    pe_data = pe_data[:end_of_real_data] 
                else:
                    log_message("""
Overlay was unable to be trimmed. Try unpacking with UniExtract2 or re-running 
Debloat with the "--last-ditch" parameter."""
                                )
    # Handle bloated sections
    # TODO: break up into functions
    else:
        # In order to solve some use cases, we will find the biggest section 
        # within the binary.
        end_of_real_data, result = check_section_compression(pe, pe_data,
                                                             end_of_real_data, 
                                                             log_message=log_message)
        log_message(result)
    # All processing is done. Report results.
    if end_of_real_data > (beginning_file_size * 0.9) or end_of_real_data == beginning_file_size:
        log_message("""No automated method for reducing the size worked. Please consider sharing the
sample for additional analysis.
Email: Squiblydoo@pm.me
Twitter: @SquiblydooBlog.
                    """)
    else:
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
