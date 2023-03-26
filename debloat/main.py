from pathlib import Path
import pefile
import processor
import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", help="Path to the executable to be debloated", type=Path)
    parser.add_argument("--output", help="Output location", type=Path, required=False)
    args = parser.parse_args()

    filepath = args.executable
    out_path = args.output

    if not out_path:
        out_path = filepath.parent / f"{filepath.stem}_patched{filepath.suffix}"

    try:
        pe = pefile.PE(filepath)
    except Exception:
        print("Provided file is not an executable! Please try again with an executable. Maybe it needs unzipped?")
        return 1

    processor.process_pe(pe, out_path=str(out_path), log_message=print)
    return 0


if __name__ == "__main__":
    sys.exit(main())
