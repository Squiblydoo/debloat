"""This file handles passing the CLI arguments into the processor"""
import os
import sys
from pathlib import Path
import argparse
import pefile
import debloat.processor
from debloat.processor import DEBLOAT_VERSION
from debloat.processor import RESULT_CODES


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", 
                        help="Path to the executable to be debloated",
                        type=Path)
    parser.add_argument("--output", 
                        help="Output location", 
                        type=Path,
                        required=False)
    parser.add_argument("-yolo", "--last-ditch", dest="last_ditch_processing",
                        help="""
    Run last-ditch processing. In this mode Debloat may remove the
    whole PE Overlay as a last resort if no smarter method works.
                            """,
                        action='store_true', default=False)
    parser.add_argument("-c", "--cert", dest="cert_preservation", 
                        help="""
    Preserve the certificate on the end of the file if there is a certificate.
    The certificate will no longer be valid.""",
                        action='store_true',
                        required=False,
                        default=False)
    parser.add_argument("-v", "--version", action='version', version='debloat version ' + DEBLOAT_VERSION, help="Prints program version")
    args = parser.parse_args()

    file_path = args.executable
    out_path = args.output
    file_size = os.path.getsize(file_path)

    if not out_path:
        out_path = file_path.parent \
            / f"{file_path.stem}_patched{file_path.suffix}"

    try:
        with open(file_path, "rb") as bloated_file:
            pe_data = bloated_file.read()
        pe = pefile.PE(data=pe_data, fast_load=True)
    except Exception:
        print('''
Provided file is not an executable! Please try again with an executable. 
Maybe it needs unzipped?'''
              )
        return 1

    result_code = debloat.processor.process_pe(pe, 
                        out_path=str(out_path), 
                        last_ditch_processing=args.last_ditch_processing,
                        cert_preservation=args.cert_preservation,
                        log_message=print,
                        beginning_file_size=file_size
                        )
    print("Tactic identifed:", RESULT_CODES.get(result_code))
    return 0

if __name__ == "__main__":
    sys.exit(main())
