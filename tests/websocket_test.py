import unittest

from websocket import FrameMessageCodec, MaskedFrameMessageCodec, MaskFactory


class MockMaskFactory(MaskFactory):
    def __init__(self, mask: list):
        self.mask = mask

    def generate(self) -> list:
        return self.mask


class TestWebsockets(unittest.TestCase):

    def test_identity(self):
        codec = FrameMessageCodec()
        msg = ('text', 'Foo Bar')

        self.assertEqual(msg, codec.decode(codec.encode(msg)))

    def test_masked_identity(self):
        codec = MaskedFrameMessageCodec()
        msg = ('text', 'Foo Bar')

        self.assertEqual(msg, codec.decode(codec.encode(msg)))

    def test_encode(self):
        for msg, expected, input in TestWebsockets._encode_provider():
            codec = FrameMessageCodec()

            self.assertEqual(expected, codec.encode(('text', input)), msg)

    def test_masked_encode(self):
        for msg, expected, input, mask in TestWebsockets._masked_encode_provider():
            codec = MaskedFrameMessageCodec(MockMaskFactory(mask))

            self.assertEqual(expected, codec.encode(('text', input)), msg)

    def test_mask_not_same(self):
        codec = MaskedFrameMessageCodec()

        self.assertNotEqual(codec.encode(('text', 'foobar')), codec.encode(('text', 'foobar')))

    def test_decode(self):
        for msg, expected, input in TestWebsockets._decode_provider():
            codec = FrameMessageCodec()

            self.assertEqual(expected, codec.decode(input), msg)

    def test_masked_decode(self):
        for msg, expected, input in TestWebsockets._masked_decode_provider():
            codec = MaskedFrameMessageCodec()

            self.assertEqual(expected, codec.decode(input), msg)

    @staticmethod
    def _encode_provider():
        def fixture(file: str, binary: bool = False):
            with open(file, 'r%s' % ('b' if binary else '')) as f:
                return f.read()

        return [
            ('Un-masked small check', fixture('encoded_small_plain.txt', True), fixture('plain_small.txt')),
            ('Un-masked medium check', fixture('encoded_medium_plain.txt', True), fixture('plain_medium.txt')),
            ('Un-masked large check', fixture('encoded_large_plain.txt', True), fixture('plain_large.txt')),
        ]

    @staticmethod
    def _masked_encode_provider():
        def fixture(file: str, binary: bool = False):
            with open(file, 'r%s' % ('b' if binary else '')) as f:
                return f.read()

        return [
            ('Masked small check', fixture('encoded_small_masked.txt', True), fixture('plain_small.txt'), [37, 234, 102, 179]),
            ('Masked medium check', fixture('encoded_medium_masked.txt', True), fixture('plain_medium.txt'), [197, 87, 75, 34]),
            ('Masked large check', fixture('encoded_large_masked.txt', True), fixture('plain_large.txt'), [63, 93, 190, 173]),
        ]

    @staticmethod
    def _decode_provider():
        def fixture(file: str, binary: bool = False):
            with open(file, 'r%s' % ('b' if binary else '')) as f:
                return f.read()

        return [
            ('Un-masked small check', ('text', fixture('plain_small.txt')), fixture('encoded_small_plain.txt', True)),
            ('Un-masked medium check', ('text', fixture('plain_medium.txt')), fixture('encoded_medium_plain.txt', True)),
            ('Un-masked large check', ('text', fixture('plain_large.txt')), fixture('encoded_large_plain.txt', True)),
        ]

    @staticmethod
    def _masked_decode_provider():
        def fixture(file: str, binary: bool = False):
            with open(file, 'r%s' % ('b' if binary else '')) as f:
                return f.read()

        return [
            ('Masked small check', ('text', fixture('plain_small.txt')), fixture('encoded_small_masked.txt', True)),
            ('Masked medium check', ('text', fixture('plain_medium.txt')), fixture('encoded_medium_masked.txt', True)),
            ('Masked large check', ('text', fixture('plain_large.txt')), fixture('encoded_large_masked.txt', True)),
        ]

if __name__ == '__main__':
    unittest.main()
