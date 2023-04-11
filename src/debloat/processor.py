"""This file handles the processing of binaries and helper methods."""

import re
from typing import Tuple, Optional, Any, Callable
import pefile

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

def write_patched_file(out_path: str,
                        pe: pefile.PE, 
                        end_of_real_data: int) -> Tuple[int, str]:
    '''Writes the patched file to disk.
    
    Keyword Arguments:
    out_path -- the path and file name to write
    pe -- the pefile that is being processed
    end_of_real_data -- an int indicating the size of bytes to write'''
    with open(out_path, 'wb') as writer:
        writer.write(pe.write()[:end_of_real_data])
        final_filesize = len(pe.write()[:end_of_real_data])
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

def check_for_packer(pe: pefile.PE) -> int:
    '''Check overlay bytes for known packers.'''
    packer_header = pe.write()[pe.get_overlay_data_start_offset():pe.get_overlay_data_start_offset() + 30]
    # TODO This section is being expanded to account for multiple types
    # of packers. Packers store some important information in the 
    # overlay that we need to preserve. The intention here is to
    # find the end of the Packer content based on headers. This may 
    # result in specific rules for specific headers or may end up 
    # requiring a genernic method to handle different file types.
    packer_header_match = re.search(rb"^.\x00\x00\x00\xef\xbe\xad\xdeNullsoftInst",
                                  packer_header)
    if packer_header_match:
        print("Nullsoft Header found. Use the tool UniExtract2 to extract.")
        nullsoft_header_size = int.from_bytes(packer_header[18:21], "big")
        return nullsoft_header_size
    return 0

def find_last_section(pe: pefile.PE) -> Optional[pefile.SectionStructure]:
    '''Iterate through PE sections to identify the last one.'''
    last_section = None
    for section in pe.sections:
        if last_section is None \
                        or section.PointerToRawData > last_section.PointerToRawData:
            last_section = section
    return last_section

def remove_signature(pe: pefile.PE) -> Tuple[int, int]:
    '''Remove PE signature and update header.''' 
    signature_address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    signature_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = 0
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = 0
    return signature_address, signature_size

def remove_resources(pe: pefile.PE, biggest_section: pefile.SectionStructure) -> Tuple[pefile.PE, int]:
    # This method removed PE resources but not .NET Resources.
    # PE resources are in the .rcsc section of the binary; 
    # .NET are in the .text section.
    # The following nonsense was determined to be the best way
    # to iterate through resources and find the offending ones.
    end_of_real_data = len([pe.write()])
    entry_list = pe.DIRECTORY_ENTRY_RESOURCE.entries
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if hasattr(resource_type, 'directory'):
            for resource_id in resource_type.directory.entries:
                if hasattr(resource_id, 'directory'):
                    for resource_lang in resource_id.directory.entries:
                        if hasattr(resource_lang, 'data'):
                            if resource_lang.data.struct.Size > 50000:
                                ## If the resource is bloated, remove it with pop
                                ## then subtract the size from the end_of_real_data variable
                                resource_type.directory.entries.pop()
                                end_of_real_data -= resource_lang.data.struct.Size
                                pe.OPTIONAL_HEADER.DATA_DIRECTORY[2].Size -= resource_lang.data.struct.Size 
                                pe.sections[pe.sections.index(biggest_section)].SizeOfRawData -= resource_lang.data.struct.Size
                                pe.sections[pe.sections.index(biggest_section)].Misc_VirtualSize -= resource_lang.data.struct.Size
                                pe.sections[pe.sections.index(biggest_section)].section_max_addr -= resource_lang.data.struct.Size
        pe.DIRECTORY_ENTRY_RESOURCE.entries[entry_list.index(resource_type)] = resource_type
    return pe, end_of_real_data

def check_section_entropy(pe: pefile.PE, end_of_real_data) -> Tuple[pefile.PE, int, str]:
        biggest_section = None
        result = ""
        for section in pe.sections:
            section_name = section.Name.decode()
            section_entropy = section.get_entropy()
            result += "Section: "  + section_name + "\t "
            result += " Entropy: " + str(round(section_entropy, 4)) + "\t " 
            result += "Size of section: " + readable_size(section.SizeOfRawData) +"." + "\n"
            # The use cases covered by this section are at the end of 
            # the binary. In my experience, the bloated sections are 
            # usually at the end unless they are bloat from .NET Resources.
            if section_entropy < 0.09 and section.SizeOfRawData > 100000:
                result += "Entropy of section is exteremely low.\n This is \
                            indicative of a bloated section.\n Removing bloated\
                            section..." + "\n"
                # Get the size of the section.
                section_end = section.PointerToRawData + section.SizeOfRawData
                # If the entropy is simply 0.00, there is no data to be 
                # missed, we won't waste CPU and just drop the whole thing.
                if section_entropy == 0.00:
                    # To play it safe, we will leave 100 bytes in the 
                    # section. And thus mark the end of the binary as 
                    # the beginning of the last section + 100.
                    section_bytes_to_remove = section.SizeOfRawData - 100
                    end_of_real_data = section.PointerToRawData + 100
                # If the section has low entropy we'll try to determine
                #  how much is junk.
                else:
                    section_data = pe.write()[section.PointerToRawData:section_end]
                    section_end = section.PointerToRawData + section.SizeOfRawData
                    section_data = pe.write()[section.PointerToRawData:section_end]
                    backward_section_data = section_data[::-1]
                    junk_match = re.search(rb"(.)\1{100,}", backward_section_data)
                    if not junk_match:
                        delta_last_non_zero = len(backward_section_data)
                    else:
                        delta_last_non_zero = len(backward_section_data)\
                              - junk_match.end(0)
                    section_bytes_to_remove = end_of_real_data \
                        - (section.PointerToRawData + delta_last_non_zero + 1)
                    end_of_real_data = section.PointerToRawData + delta_last_non_zero + 1
                ## Fix last section header, SizeOfRawData, SizeOfImage.
                section.Misc_VirtualSize -= section_bytes_to_remove
                section.SizeOfRawData -= section_bytes_to_remove
                pe.OPTIONAL_HEADER.SizeOfImage -= section_bytes_to_remove
                result += "Bloated section reduced." + "\n"
                return pe, end_of_real_data, result
            # Handle specific bloated sections
            if biggest_section == None:
                biggest_section = section
            elif section.SizeOfRawData > biggest_section.SizeOfRawData:
                biggest_section = section
        if biggest_section.Name.decode() == ".rsrc\x00\x00\x00":
            # Get biggest resource or resources and drop them from the 
            # Resource table
            # TODO: recalculate PE header in situations where the 
            # resource is not at the end of an executable.
            # TODO: Handle other tomfoolery required when resource 
            # is not at end of executable.
            result += "Bloat was located in the resource section.\n\
                        Removing bloat.." + "\n"
            pe, end_of_real_data = remove_resources(pe, biggest_section)
            return pe, end_of_real_data, result
        elif biggest_section.Name.decode() == ".text\x00\x00\x00":
            result += "Bloat was detected in the text section." + "\n"
            # Data stored in the .text section is often a .NET Resource. The following checks
            # to confirm it is .NET and then drops the resources.
            if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size:
                result += "Bloat is likely in a .NET Resource\n\
                            This use case cannot be processed at this time." + "\n"
            return pe, end_of_real_data, result
        
def trim_junk(pe: pefile.PE, end_of_real_data) -> int:
    ''' Attempt multiple methods or removing junk from overlay.'''
    backwards_overlay = pe.get_overlay()[::-1]
    # Regex Explained:
    # Match raw bytes that are repeated more than 20 times at the end
    # of a binary. Trims 1 repeating byte.
    delta_last_non_junk = end_of_real_data
    # Check against 200 bytes, if successful, calculate full match.
    junk_match = re.search(rb'^(..)\1{20,}', backwards_overlay[:200])
    # If "not junk_match" check for junk larger than 1 byte
    if not junk_match:
        # Brute force check: check to see if there are 1-20 bytes
        # being repeated and feed the number into the regex
        for i in range(20):
            # Regex Explained:
            # Starting at the end of the PE, check for repeated bytes.
            # This indicates junk bytes in the overlay. Match that set
            # of repeated bytes 1 or more times. 
            junk_regex = rb"^(..{" + bytes(str(i), "utf-8") + rb"})\1{2,}"
            multibyte_junk_regex = re.search(junk_regex, backwards_overlay[:200])
            if multibyte_junk_regex:
                # Having found the pattern, we can make the regex efficient
                # by targeting the pattern using the "targeted_regex"
                targeted_regex = rb"(" + multibyte_junk_regex.string + rb")\1{2,}"
                multibyte_junk_regex = re.search(targeted_regex, backwards_overlay)
                junk_to_remove = multibyte_junk_regex.end(0)
                delta_last_non_junk = end_of_real_data - junk_to_remove
                break
    # Junk was identified. New end_of_real_data is assigned and returned.
    else:
        targeted_regex = rb""+ junk_match.string + rb"{1,}"
        targeted_junk_match = re.search(targeted_regex, backwards_overlay)
        junk_to_remove = targeted_junk_match.end(0)
        # If the trimming did not remove more than half of the bytes then
        # this suggests the attacker may have put a random series of
        # repeated bytes. These will be removed by loading the overlay
        # 200 bytes at a time and removing parts which repeat for more
        # than 20 bytes.
        if junk_to_remove < end_of_real_data / 2:
            chunk_start = targeted_junk_match.end(0)
            chunk_end = chunk_start
            while end_of_real_data > chunk_end:
                chunk_end = chunk_start + 200
                repeated_junk_match = re.search(rb'(..)\1{20,}', 
                                                backwards_overlay[chunk_start:chunk_end])
                if repeated_junk_match:
                    chunk_start += repeated_junk_match.end(0)
                else:
                    break
            junk_to_remove = chunk_start
        delta_last_non_junk = end_of_real_data - junk_to_remove
    return delta_last_non_junk

def process_pe(pe: pefile.PE, out_path: str, unsafe_processing: bool,
               log_message: Callable[[str], None]) -> None:
    '''Prepare PE, perform checks, remote junk, write patched binary.'''
    beginning_file_size = len(pe.write())
    # We are using the variable "end_of_real_data" and are reassigning 
    # the value based on our analysis.We are assigning it now in case 
    # we are unable to reduce the binary size for any reason.
    end_of_real_data = beginning_file_size
    # Remove Signature and modify size of Optional Header Security entry.
    signature_address, signature_size = remove_signature(pe)
    signature_abnormality = handle_signature_abnormality(signature_address, 
                                                        signature_size, 
                                                        beginning_file_size)
    overlay_size = len(pe.get_overlay())
    if signature_abnormality:
        log_message("We detected data after the signature.\
                     This is abnormal.\nRemoving signature and extra data...")
        end_of_real_data = signature_address
    # Handle Overlays: this includes packers and overlays which are completely junk
    elif pe.get_overlay_data_start_offset() and signature_size < overlay_size:
        log_message("An overlay was detected. Checking for known packer.")
        if check_for_packer(pe):
            log_message("Packer identified")
        else:
            log_message("Packer not identified. Attempting dynamic trim...")
            end_of_real_data = trim_junk(pe, end_of_real_data)
            if end_of_real_data == beginning_file_size:
                if unsafe_processing is True:
                    log_message("""
"Unsafe" switch detected. Running unsafe debloat technique:\n
This is the last resort of removing the whole overlay: this works in some 
cases, but can remove critical content. 
If file is a Nullsoft executable, but was not detected, the original file can 
be unpacked with the tool "UniExtract2".
                    """)
                    last_section = find_last_section(pe)
                    end_of_real_data = last_section.PointerToRawData + last_section.SizeOfRawData 
                else:
                    log_message("""
Overlay was unable to be trimmed. Try unpacking with UniExtract2 or re-running 
Debloat without the "--unsafe" parameter."""
                                )
    # Handle bloated sections
    # TODO: break up into functions
    else:
        # In order to solve some use cases, we will find the biggest section 
        # within the binary.
        pe, end_of_real_data, result = check_section_entropy(pe, end_of_real_data)
        log_message(result)
    # All processing is done. Report results.
    if end_of_real_data == beginning_file_size:
        log_message("""
No automated method for reducing the size worked. Please consider sharing the
sample for additional analysis.
Email: Squiblydoo@pm.me
Twitter: @SquiblydooBlog.
                    """)
    else:
        final_filesize, new_pe_name = write_patched_file(out_path,
                                                         pe, 
                                                         end_of_real_data)
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
