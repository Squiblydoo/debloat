import pefile
import re
from typing import Tuple, Optional, Any, Callable


## human_size was reused from Didier Steven's publicly shared pecheck
def human_size(value: int) -> str:
    if value <= 1024:
        return '%s bytes' % value
    elif value < 1024 * 1024:
        return '%.1f KB' % (float(value) / 1024.0)
    elif value < 1024 * 1024 * 1024:
        return '%.1f MB' % (float(value) / 1024.0 / 1024.0)
    else:
        return '%.1f GB' % (float(value) / 1024.0 / 1024.0 / 1024.0)


def write_patched_file(out_path: str, pe: pefile.PE, end_of_real_data: int) -> Tuple[int, str]:
    ## All file modification should be done at this point:
    with open(out_path, 'wb') as writer:
        writer.write(pe.write()[:end_of_real_data])
        final_filesize = len(pe.write()[:end_of_real_data])
        return final_filesize, out_path


def handle_signature_abnormality(signature_address: int, signatureSize: int, beginning_file_size: int) -> bool:
    # If the signature_address is 0, there was no original signature.
    ## We are setting the signature address to the filesize in order to skip the next check.
    if signature_address == 0:
        signature_address = beginning_file_size

    ### Check to see if there is data after the signature; if so, it is junk data
    if beginning_file_size > (signature_address + signatureSize):
        return True
    return False


def check_for_packet(pe: pefile.PE) -> int:
    packerHeader = pe.write()[pe.get_overlay_data_start_offset():pe.get_overlay_data_start_offset() + 30]
    ## TODO This section is being expanded to account for multiple types of packers.
    ## Packers store some important information in the overlay that we need to preserve. The intention here is to
    ## find the end of the Packer content based on headers. This may result in specific rules for specific headers
    ## or may end up requiring a genernic method to handle different file types.
    packerHeaderMatch = re.search(rb"^.\x00\x00\x00\xef\xbe\xad\xdeNullsoftInst", packerHeader)
    if packerHeaderMatch:
        print("Nullsoft Header found.")

        nullSoftInstallerSize = int.from_bytes(packerHeader[18:21], "big")
        return nullSoftInstallerSize
    return 0


def find_last_section(pe: pefile.PE) -> Optional[pefile.SectionStructure]:
    last_section = None
    for section in pe.sections:
        if last_section is None or section.PointerToRawData > last_section.PointerToRawData:
            last_section = section
    return last_section


def remove_signature(pe: pefile.PE) -> Tuple[int, int]: 
    signature_address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress
    signatureSize = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].VirtualAddress = 0
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size = 0
    return signature_address, signatureSize


def process_pe(pe: pefile.PE, out_path: str, log_message: Callable[[str], None]) -> None:
    beginning_file_size = len(pe.write())

    # We are using the variable "end_of_real_data" and are reassigning the value based on our analysis.
    # We are assigning it now in case we are unable to reduce the binary size for any reason.
    end_of_real_data = beginning_file_size
    log_message("Beginning File size: " + human_size(beginning_file_size) + ".")

    ### Remove Signature and modify size of Optional Header Security entry.
    signature_address, signatureSize = remove_signature(pe)
    signatureAbnormality = handle_signature_abnormality(signature_address, signatureSize, beginning_file_size)
    if signatureAbnormality:
        log_message("We detected data after the signature. This is abnormal.\nRemoving signature and extra data...")
        end_of_real_data = signature_address
    ## Handle Overlays: this includes packers and overlays which are completely junk
    elif pe.get_overlay_data_start_offset() and signatureSize < len(pe.get_overlay()):
        log_message("An overlay was detected. Checking for known packer.")
        if check_for_packet(pe):
            log_message("Packer identified")
        else:
            log_message("No use of packer identified. Removing whole overlay...")
            lastSection = find_last_section(pe)
            end_of_real_data = lastSection.PointerToRawData + lastSection.SizeOfRawData 
    ## Handle bloated sections
    ## TODO: break up into functions
    else:
        ### In order to solve some use cases, we will find the biggest section within the binary.
        biggestSection = None

        for section in pe.sections:
            #if lastSection is None or section.PointerToRawData > lastSection.PointerToRawData:
            section_name = section.Name.decode()
            section_entropy = section.get_entropy()
            log_message("Section "  + section_name) 
            log_message(" Entropy: " + str(round(section_entropy, 4)) + " " )
            log_message("Size of section: " + human_size(section.SizeOfRawData) +".")

            ## The use cases covered by this section are at the end of the binary.
            ## In my experience, the bloated sections are usually at the end unless they are bloat from .NET Resources.
            if section_entropy < 0.09 and section.SizeOfRawData > 100000:
                log_message("Entropy of section is exteremely low.\n This is indicative of a bloated section.\n Removing bloated section...")

                #Get the size of the section.
                sectionEnd = section.PointerToRawData + section.SizeOfRawData

                #If the entropy is simply 0.00, there is no data to be missed, we won't waste CPU and just drop the whole thing.
                if section_entropy == 0.00:
                    ## We won't waste any time. We will just drop the whole thing. Though to play it safe, we will
                    ## leave 100 bytes in the section. And thus mark the end of the binary as the beginning of the last
                    ## section + 100.
                    sectionBytesToRemove = section.SizeOfRawData - 100
                    end_of_real_data = section.PointerToRawData + 100

                ## If the section has low entropy we'll try to determine how much is junk.
                else:
                    sectionData = pe.write()[section.PointerToRawData:sectionEnd]
                    sectionEnd = section.PointerToRawData + section.SizeOfRawData
                    sectionData = pe.write()[section.PointerToRawData:sectionEnd]
                    revertedSectionData = sectionData[::-1]
                    junkMatch = re.search(rb"(.)\1{100,}", revertedSectionData)
                    if not junkMatch:
                        delta_last_non_zero = len(revertedSectionData)
                    else:
                        delta_last_non_zero = len(revertedSectionData) - junkMatch.end(0)

                    sectionBytesToRemove = beginning_file_size - (section.PointerToRawData + delta_last_non_zero + 1)
                    end_of_real_data = section.PointerToRawData + delta_last_non_zero + 1

                ## Fix last section header, SizeOfRawData, SizeOfImage.
                section.Misc_VirtualSize -= sectionBytesToRemove
                section.SizeOfRawData -= sectionBytesToRemove
                pe.OPTIONAL_HEADER.SizeOfImage -= sectionBytesToRemove 

            ## Handle specific bloated sections
            if biggestSection == None:
                biggestSection = section
            elif section.SizeOfRawData > biggestSection.SizeOfRawData:
                biggestSection = section

        if biggestSection.Name.decode() == ".rsrc\x00\x00\x00":
            ## Get biggest resource or resources and drop them from the Resource table
            ## TODO: recalculate PE header in situations where the resource is not at the end of an executable.
            ## TODO: Handle other tomfoolery required when resource is not at end of executable.
            log_message("Bloat was located in the resource section.\nRemoving bloat..")
            entryList = pe.DIRECTORY_ENTRY_RESOURCE.entries
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
                                        pe.sections[pe.sections.index(biggestSection)].SizeOfRawData -= resource_lang.data.struct.Size
                                        pe.sections[pe.sections.index(biggestSection)].Misc_VirtualSize -= resource_lang.data.struct.Size
                                        pe.sections[pe.sections.index(biggestSection)].section_max_addr -= resource_lang.data.struct.Size
                pe.DIRECTORY_ENTRY_RESOURCE.entries[entryList.index(resource_type)] = resource_type

        elif biggestSection.Name.decode() == ".text\x00\x00\x00":
            log_message("Bloat was detected in the text section.")
            ## Data stored in the .text section is often a .NET Resource. The following checks
            ## to confirm it is .NET and then drops the resources.
            if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size:
                log_message("Bloat is likely in a .NET Resource\nThis use case cannot be processed at this time.")

    ## All processing is done. Report results.
    if end_of_real_data == beginning_file_size:
        log_message("\nNo automated method for reducing the size worked.\nPlease consider sharing the sample for additional analysis.\nEmail: Squiblydoo@pm.me\nTwitter: @SquiblydooBlog.\n")
    else:
        log_message("Writing to file...")
        final_filesize, new_pe_name = write_patched_file(out_path, pe, end_of_real_data)
        reductionCalculation = round(((beginning_file_size - final_filesize) / beginning_file_size) * 100, 2)
        log_message("File was reduced by " + str(reductionCalculation) + "%.")
        log_message("Final file size: " + human_size(final_filesize) + ".")
        log_message("Processing complete.\nFile written to '" + str(new_pe_name) + "'.")
