#!/usr/bin/python3

# NDS cart KEY2 encryption

def flip39(i):
    return int('{:039b}'.format(i)[::-1], 2)

class Key2(object):
    def __init__(self, seed4, hdrbyte):
        self.x = flip39((seed4 << 15) + 0x6000 +
            (0xE8, 0x4D, 0x5A, 0xB1, 0x17, 0x8F, 0x99, 0xD5)[hdrbyte])
        self.y = flip39(0x5C879B9B05)

    def dobyte(self, b):
        x, y = self.x, self.y
        self.x = ((((x >> 5) ^ (x >> 17) ^ (x >> 18) ^ (x >> 31)) & 0xFF) + (x << 8))
        self.y = ((((y >> 5) ^ (y >> 23) ^ (y >> 18) ^ (y >> 31)) & 0xFF) + (y << 8))
        return (b ^ (self.x ^ self.y)) & 0xFF

    def dobytes(self, bs):
        if not type(bs) is bytearray:
            bs = bytearray(bs)
        for i in range(len(bs)):
            bs[i] = self.dobyte(bs[i])
        return bs
