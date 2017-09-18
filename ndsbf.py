#!/usr/bin/python3
# vim: filetype=python3 tabstop=2 expandtab

# NDS blowfish
# Adapted from python-blowfish from
# https://github.com/jashandeep-sohi/python-blowfish/blob/master/blowfish.py
#
# blowfish
# Copyright (C) 2015 Jashandeep Sohi <jashandeep.s.sohi@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.

import struct
from struct import Struct, error as struct_error
from itertools import cycle as iter_cycle

__version__ = "0.7.0"

PI_P_ARRAY = PI_S_BOXES = ()

def init_state(state):
  import hashlib
  if len(state) != 0x1048:
    raise ValueError("state should be 0x1048 bytes")
  if (hashlib.sha1(state).hexdigest() !=
    '84e467f2485078e401a17a5f231e3fe6e9686648'):
    raise ValueError("invalid contents of state")
  global PI_P_ARRAY, PI_S_BOXES
  PI_P_ARRAY = struct.unpack("<18I", state[:0x48])
  PI_S_BOXES = tuple(struct.iter_unpack("<256I", state[0x48:]))

class Cipher(object):
  def __init__(
    self,
    byte_order = "big",
    P_array = None,
    S_boxes = None
  ):
    self.P = P_array or PI_P_ARRAY
    self.S = S_boxes or PI_S_BOXES

    if not len(self.P) or len(self.P) % 2 != 0:
      raise ValueError("P array is not an even length sequence")

    self.P = tuple((p1, p2) for p1, p2 in zip(
      self.P[0::2],
      self.P[1::2]
    ))

    if len(self.S) != 4 or any(len(box) != 256 for box in self.S):
      raise ValueError("S-boxes is not a 4 x 256 sequence")

    if byte_order == "big":
      byte_order_fmt = ">"
    elif byte_order == "little":
      byte_order_fmt = "<"
    else:
      raise ValueError("byte order must either be 'big' or 'little'")
    self.byte_order = byte_order

    # Create structs
    u4_2_struct = Struct("{}2I".format(byte_order_fmt))
    u4_1_struct = Struct(">I")
    u8_1_struct = Struct("{}Q".format(byte_order_fmt))
    u1_4_struct = Struct("=4B")

    # Save refs locally to the needed pack/unpack funcs of the structs to speed
    # up look-ups a little.
    self._u4_2_pack = u4_2_struct.pack
    self._u4_2_unpack = u4_2_struct.unpack
    self._u4_2_iter_unpack = u4_2_struct.iter_unpack

    self._u4_1_pack = u4_1_pack = u4_1_struct.pack
    self._u4_1_unpack = u4_1_unpack = u4_1_struct.unpack

    self._u1_4_unpack = u1_4_unpack = u1_4_struct.unpack

    self._u8_1_pack = u8_1_struct.pack

  def init_key(self, gamecode, level):
    def shuf(self, key):
      key[:8] = self.encrypt_block(key[:8])
      key[4:] = self.encrypt_block(key[4:])
    if type(gamecode) is str:
      gamecode = gamecode.encode('utf-8')
    if not type(gamecode) in (bytes, bytearray):
      raise ValueError('gamecode should be a str, bytes, or bytearray')
    # u4x3l = Struct("<III")
    u4x3b = Struct(">III")
    keyint, = struct.unpack("<I", gamecode)
    key = bytearray(u4x3b.pack((keyint << 1) & 0xFFFFFFFF, (keyint >> 1) & 0xFFFFFFFF, keyint))

    if level >= 1:
      shuf(self, key)
      self.expand_key(key[11:3:-1])
    if level >= 2:
      shuf(self, key)
      self.expand_key(key[11:3:-1])
    """
    # FIXME
    if level >= 3:
      keyint = u4x3b.unpack(key)
      key = bytearray(u4x3b.pack((keyint[0] >> 1) & 0xFFFFFFFF, (keyint[1] << 1) & 0xFFFFFFFF, keyint[2]))
      shuf(self, key)
      self.expand_key(key[11:3:-1])
    """

  def expand_key(self, key):
    u4_1_pack = self._u4_1_pack
    u4_1_unpack = self._u4_1_unpack
    u1_4_unpack = self._u1_4_unpack
    # Cyclic key iterator
    cyclic_key_iter = iter_cycle(iter(key))

    # Cyclic 32-bit integer iterator over key bytes
    cyclic_key_u4_iter = (
      x for (x,) in map(
        u4_1_unpack,
        map(
          bytes,
          zip(
            cyclic_key_iter,
            cyclic_key_iter,
            cyclic_key_iter,
            cyclic_key_iter
          )
        )
      )
    )

    # Create and initialize subkey P array and S-boxes

    # XOR each element in P_array with key and save as pairs.
    P = [
      (p[0] ^ k1, p[1] ^ k2) for p, k1, k2 in zip(
        self.P,
        cyclic_key_u4_iter,
        cyclic_key_u4_iter
      )
    ]

    S1, S2, S3, S4 = S = [[x for x in box] for box in self.S]

    encrypt = self._encrypt
    L = 0x00000000
    R = 0x00000000

    for i in range(len(P)):
      P[i] = L, R = encrypt(L, R, P, S1, S2, S3, S4, u4_1_pack, u1_4_unpack)

    # Save P as a tuple since working with tuples is slightly faster
    self.P = P = tuple(P)

    for box in S:
      for i in range(0, 256, 2):
        L, R = encrypt(L, R, P, S1, S2, S3, S4, u4_1_pack, u1_4_unpack)
        box[i] = L
        box[i + 1] = R

    # Save S
    self.S = tuple(tuple(box) for box in S)

  @staticmethod
  def _encrypt(L, R, P, S1, S2, S3, S4, u4_1_pack, u1_4_unpack):
    for p1, p2 in P[:-1]:
      L ^= p1
      a, b, c, d = u1_4_unpack(u4_1_pack(L))
      R ^= (S1[a] + S2[b] ^ S3[c]) + S4[d] & 0xffffffff
      R ^= p2
      a, b, c, d = u1_4_unpack(u4_1_pack(R))
      L ^= (S1[a] + S2[b] ^ S3[c]) + S4[d] & 0xffffffff
    p_penultimate, p_last = P[-1]
    return R ^ p_last, L ^ p_penultimate

  @staticmethod
  def _decrypt(L, R, P, S1, S2, S3, S4, u4_1_pack, u1_4_unpack):
    for p2, p1 in P[:0:-1]:
      L ^= p1
      a, b, c, d = u1_4_unpack(u4_1_pack(L))
      R ^= (S1[a] + S2[b] ^ S3[c]) + S4[d] & 0xffffffff
      R ^= p2
      a, b, c, d = u1_4_unpack(u4_1_pack(R))
      L ^= (S1[a] + S2[b] ^ S3[c]) + S4[d] & 0xffffffff
    p_first, p_second = P[0]
    return R ^ p_first, L ^ p_second

  def encrypt_block(self, block):
    """
    Return a :obj:`bytes` object containing the encrypted bytes of a `block`.

    `block` should be a :obj:`bytes`-like object with exactly 8 bytes.
    If it is not, a :exc:`ValueError` exception is raised.
    """
    S0, S1, S2, S3 = self.S
    P = self.P

    u4_1_pack = self._u4_1_pack
    u1_4_unpack = self._u1_4_unpack

    try:
      L, R = self._u4_2_unpack(block)
    except struct_error:
      raise ValueError("block is not 8 bytes in length")

    for p1, p2 in P[:-1]:
      L ^= p1
      a, b, c, d = u1_4_unpack(u4_1_pack(L))
      R ^= (S0[a] + S1[b] ^ S2[c]) + S3[d] & 0xffffffff
      R ^= p2
      a, b, c, d = u1_4_unpack(u4_1_pack(R))
      L ^= (S0[a] + S1[b] ^ S2[c]) + S3[d] & 0xffffffff
    p_penultimate, p_last = P[-1]
    L, R = R ^ p_last, L ^ p_penultimate
    return self._u4_2_pack(L, R)

  def decrypt_block(self, block):
    """
    Return a :obj:`bytes` object containing the decrypted bytes of a `block`.

    `block` should be a :obj:`bytes`-like object with exactly 8 bytes.
    If it is not, a :exc:`ValueError` exception is raised.
    """
    S0, S1, S2, S3 = self.S
    P = self.P

    u4_1_pack = self._u4_1_pack
    u1_4_unpack = self._u1_4_unpack

    try:
      L, R = self._u4_2_unpack(block)
    except struct_error:
      raise ValueError("block is not 8 bytes in length")

    for p2, p1 in P[:0:-1]:
      L ^= p1
      a, b, c, d = u1_4_unpack(u4_1_pack(L))
      R ^= (S0[a] + S1[b] ^ S2[c]) + S3[d] & 0xffffffff
      R ^= p2
      a, b, c, d = u1_4_unpack(u4_1_pack(R))
      L ^= (S0[a] + S1[b] ^ S2[c]) + S3[d] & 0xffffffff
    p_first, p_second = P[0]
    return self._u4_2_pack(R ^ p_first, L ^ p_second)

  def encrypt_ecb(self, data):
    """
    Return an iterator that encrypts `data` using the Electronic Codebook (ECB)
    mode of operation.

    ECB mode can only operate on `data` that is a multiple of the block-size
    in length.

    Each iteration returns a block-sized :obj:`bytes` object (i.e. 8 bytes)
    containing the encrypted bytes of the corresponding block in `data`.

    `data` should be a :obj:`bytes`-like object that is a multiple of the
    block-size in length (i.e. 8, 16, 32, etc.).
    If it is not, a :exc:`ValueError` exception is raised.
    """
    S1, S2, S3, S4 = self.S
    P = self.P

    u4_1_pack = self._u4_1_pack
    u1_4_unpack = self._u1_4_unpack
    encrypt = self._encrypt

    u4_2_pack = self._u4_2_pack

    try:
      LR_iter = self._u4_2_iter_unpack(data)
    except struct_error:
      raise ValueError("data is not a multiple of the block-size in length")

    for plain_L, plain_R in LR_iter:
      yield u4_2_pack(
        *encrypt(plain_L, plain_R, P, S1, S2, S3, S4, u4_1_pack, u1_4_unpack)
      )

  def decrypt_ecb(self, data):
    """
    Return an iterator that decrypts `data` using the Electronic Codebook (ECB)
    mode of operation.

    ECB mode can only operate on `data` that is a multiple of the block-size
    in length.

    Each iteration returns a block-sized :obj:`bytes` object (i.e. 8 bytes)
    containing the decrypted bytes of the corresponding block in `data`.

    `data` should be a :obj:`bytes`-like object that is a multiple of the
    block-size in length (i.e. 8, 16, 32, etc.).
    If it is not, a :exc:`ValueError` exception is raised.
    """
    S1, S2, S3, S4 = self.S
    P = self.P

    u4_1_pack = self._u4_1_pack
    u1_4_unpack = self._u1_4_unpack
    decrypt = self._decrypt

    u4_2_pack = self._u4_2_pack

    try:
      LR_iter = self._u4_2_iter_unpack(data)
    except struct_error:
      raise ValueError("data is not a multiple of the block-size in length")

    for cipher_L, cipher_R in LR_iter:
      yield u4_2_pack(
        *decrypt(cipher_L, cipher_R, P, S1, S2, S3, S4, u4_1_pack, u1_4_unpack)
      )

if __name__ == '__main__':
  def main():
    with open('ndsbfstate.bin', 'rb') as statef:
      init_state(statef.read())
    c = Cipher()
    c.init_key("ABXK", 3)

    d = c.decrypt_block(bytes.fromhex("07 F7 6F 3B 77 AF 94 9F"))
    assert d == b"\x40\x00\x0c\x99\xac\xe3\x9d\x46"
    print(d.hex())

  main()
