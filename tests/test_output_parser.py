import pytest
from vetaal.utils.output_parser import OutputParser

def test_output_parser():
    parser = OutputParser()
    res = parser.parse_banner("Apache/2.4.41", port=80)
    assert res["port"] == 80
