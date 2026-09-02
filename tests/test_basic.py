from openhop_core import CryptoUtils, LocalIdentity, MeshNode, Packet, __version__


def test_version():
    assert __version__ == "1.1.3.dev25"


def test_import():
    assert MeshNode is not None
    assert LocalIdentity is not None
    assert Packet is not None
    assert CryptoUtils is not None
