import pytest
import debloat.processor as processor 
import pefile


# Can we print sizes?
def test_readable_size():
    assert processor.readable_size(10) == "10 bytes"



def test_signture_abnormality():
    # Is there information after the signature?
    # Signature is at 10 with a size of 5, total file is 15
    assert processor.handle_signature_abnormality(10, 5, 15) == False
    # Is there information after the signature?
    # Signature is at 10 with a size of 5, total file is 20
    assert processor.handle_signature_abnormality(10, 5, 20) == True


class _FakeArchivedFile:
    def __init__(self, path, data):
        self.path = path
        self.data = data


def test_write_multiple_files_blocks_path_traversal(tmp_path):
    out_path = tmp_path / "out"
    out_path.mkdir()
    messages = []
    processor.write_multiple_files(
        str(out_path),
        [_FakeArchivedFile("../../evil-debloat-test.txt", b"pwned")],
        messages.append,
    )
    assert not (tmp_path / "evil-debloat-test.txt").exists()
    assert not (tmp_path.parent / "evil-debloat-test.txt").exists()


def test_write_multiple_files_writes_legit_file(tmp_path):
    out_path = tmp_path / "out"
    out_path.mkdir()
    messages = []
    processor.write_multiple_files(
        str(out_path),
        [_FakeArchivedFile("subdir/good.txt", b"hello")],
        messages.append,
    )
    assert (out_path / "subdir" / "good.txt").read_bytes() == b"hello"
