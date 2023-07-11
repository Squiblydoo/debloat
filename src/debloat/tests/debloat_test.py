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
