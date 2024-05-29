## This script is for batch processing of samples and can be used for
## measuring memory usage.

import os
import hashlib
from memray import commands, FileReader
from memray._memray import size_fmt
import debloat.processor
import timeit
import argparse
import cProfile
import pstats
import tempfile

argparser = argparse.ArgumentParser(
    prog = "Debloat Performance test",
    description = "This program takes a test type (--mem or --cpu) and performs tests using one or more samples. If no sample or directory is specified, it defaults to a 'samples' directory in the current working directory."
)
argparser.add_argument("--cpu", help="Run the CPU profiler", action="store_true")
argparser.add_argument("--mem", help="Run the memory profiler", action="store_true")
argparser.add_argument("--sample", help="Run the debloat processor on a single sample")
argparser.add_argument("--directory", help="Specify sample directory", default="samples")
argparser.add_argument("--keep", help="Keeps patched copies.", action="store_true")
args = argparser.parse_args()

def process_samples(sample, directory):
    file_size=os.path.getsize(args.directory +"/"+ sample)
    setup = f"import pefile; import debloat; filename = '{args.directory}/{sample}'; "
    code = f"binary = pefile.PE(filename, fast_load=True); result= debloat.processor.process_pe(binary, filename + '.patched', last_ditch_processing=False, cert_preservation=False, log_message=lambda *args, **kwargs: None, beginning_file_size={file_size}); print(result, end=' ')"

    if args.mem:
        mem_profiler(setup, code, file_size, sample, directory)
    if args.cpu:
        cpu_profiler()
    if not args.keep:
        try:
            os.remove(args.directory + "/" + sample + ".patched")
        except:
            pass


def mem_profiler(setup, code, file_size, sample, directory):
    with tempfile.NamedTemporaryFile() as f:
        commands.main(["run", "-f", "-q", "-o", f.name, "-c", setup+code])
        reader = FileReader(os.fspath(f.name), report_progress=False)
        # Uncomment to hash outputed samples.
        #with open(directory +"/"+ sample + ".patched", "rb") as g:
        #    out = g.read()
        #    out_hash = hashlib.sha256(out).hexdigest()
    times = timeit.repeat(stmt=code, setup=setup, number=1, repeat=3)
    print(sample, size_fmt(file_size), size_fmt(reader.metadata.peak_memory), [round(x,2) for x in times])

def cpu_profiler():
    cProfile.run(setup+code, "tmp.prof")
    p = pstats.Stats("tmp.prof")
    p.sort_stats('tot').print_stats(10)
    p.sort_stats('cumulative').print_stats(10)

if args.sample:
    process_samples(args.sample, args.directory)    

else:
    print("Debloat Method/ Original Filename / Disk Size /  Mem Usage / Time to process x 3")
    for sample in os.listdir(args.directory):
        process_samples(sample, args.directory)

        