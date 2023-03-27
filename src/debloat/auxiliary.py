"""This file contains auxillary commands for removing bloat.

The commands in this file are not included in the automated processor
and can be used by other scripts."""
import pefile

def trim_null_bytes(out_path: str,\
            pe: pefile.PE) -> None:
    '''Remove nullbytes from end of file
    
    Key Arguments:
    out_path -- new file to write
    pe -- a pe file opject'''
    trimmed_pe = pe.trim()
    with open(out_path, "wb") as output_file:
        output_file.write(trimmed_pe)