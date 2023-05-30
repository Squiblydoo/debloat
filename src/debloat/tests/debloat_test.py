import pytest
import debloat.processor as processor 

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

#def test_write_patched_file():
#    assert processor.write_patched_file(".", )


# Repeating Junk Test
#repeating_junk = b'Hello000000000000000000000000000000000000000000000000000000'
#def test_trim_junk():
    assert processor.trim_junk(repeating_junk, 60) == 60



# Patterned Junk Test
#repeating_junk = b'Helloabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef'
#def test_trim_junk():
    #assert processor.trim_junk(repeating_junk, 59) == 59