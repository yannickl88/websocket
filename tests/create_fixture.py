import random

from websocket import FrameMessage

size = 'small'

input_file = 'fixture_%s.txt' % size
plain_file = 'expected_%s_plain.txt' % size
masked_file = 'expected_%s_masked.txt' % size

mask = [random.randint(0, 255) for _ in range(0, 4)]

with open(input_file, 'r') as f:
    content = f.read()

with open(plain_file, 'wb+') as f:
    plain = FrameMessage(message=('text', content))

    f.write(plain._encode(False))

with open(masked_file, 'wb+') as f:
    masked = FrameMessage(message=('text', content))

    f.write(masked._encode(True, mask))


print(mask)
