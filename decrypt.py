#!/usr/bin/python3

import struct, sys, json, ndsbf
from ndsk2 import Key2
from struct import Struct

RAW, KEY1, KEY2 = range(3)

state = RAW
bfstate = None
k2hdrbyte = None
k2state = None

su4b = Struct(">I")
uu4b = su4b.unpack

def state_str():
    global state
    if state == RAW:
        return "RAW"
    elif state == KEY1:
        return "KEY1"
    elif state == KEY2:
        return "KEY2"

def print_cmd(cmdb, cmd, resp=None):
    print("{} CMD: {}:".format(state_str(), cmdb.hex()), cmd)
    if resp:
        print("RESP:", resp)

def handle_cmd(cmd, resp):
    global state, bfstate, k2hdrbyte, k2state
    newstate = state
    if state == RAW:
        cmd0 = cmd[0]
        if cmd0 == 0x9F:
            print_cmd(cmd, "dummy")
        elif cmd0 == 0:
            gamecode = resp[0xC:0x10]
            k2hdrbyte = resp[0x13] & 0x7
            print_cmd(cmd, "header; gamecode = {}, key2 seedbyte = {}".format(gamecode.hex(), k2hdrbyte))
            bfstate = ndsbf.Cipher()
            bfstate.init_key(gamecode, 2)
        elif cmd0 == 0x90:
            print_cmd(cmd, "get chipid = {}".format(resp.hex()))
        elif cmd0 == 0x3C: # 3C ii ij jj xk kk kk xx
            i = uu4b(b'\0\0' + cmd[1:3])[0] >> 4
            j = uu4b(b'\0\0' + cmd[2:4])[0] & 0xFFF
            k = uu4b(b'\0' + cmd[4:7])[0] & 0xFFFFF
            print_cmd(cmd, "switch to KEY1; i = 0x{:X}, j = 0x{:X}, k = 0x{:X}".
                format(i, j, k))
            newstate = KEY1
        else:
            print_cmd(cmd, "unk")
    elif state == KEY1:
        cmd = bfstate.decrypt_block(cmd)
        cmd0 = cmd[0] >> 4
        if cmd0 == 0x4: # 4l ll lm mm nn nk kk kk
            k2seed = (uu4b(cmd[2:6])[0] >> 4) & 0xFFFFFF
            k2state = Key2(k2seed, k2hdrbyte)
            print_cmd(cmd, "key2 seed")
        elif k2state:
            resp = k2state.dobytes(resp)

        if cmd0 == 0x1:
            print_cmd(cmd, "get chipid = {}".format(resp[0x910:].hex()))
        elif cmd0 == 0x2: # 2b bb b...
            b = (uu4b(b'\0' + cmd[0:3]) [0] & 0xFFFF0) >> 4
            print_cmd(cmd, "get secure area @ 0x{:X}000".format(b))
        elif cmd0 == 0xA:
            print_cmd(cmd, "switch to KEY2")
            newstate = KEY2
        elif cmd0 != 0x4:
            print_cmd(cmd, "unk")
    elif state == KEY2:
        cmd = k2state.dobytes(cmd)
        resp = k2state.dobytes(resp)
        cmd0 = cmd[0]
        if cmd0 == 0xB7:
            adr, = uu4b(cmd[1:5])
            print_cmd(cmd, "load rom 0x200 @ 0x{:X} (resp is 0x{:X} bytes)".format(adr, len(resp)))
        elif cmd0 == 0xB8:
            print_cmd(cmd, "get chipid (resp is 0x{:X} bytes) = {}".format(len(resp), resp.hex()))
        else:
            lresp = len(resp)
            print_cmd(cmd, "unk (resp is 0x{:X} bytes){}".format(lresp, " = {}".format(resp.hex()) if lresp == 4 else ""))

    state = newstate


def handle(block):
    btype = block['type']
    if btype == 'command':
        cmd = bytes.fromhex(block['command'])
        resp = bytes.fromhex(block['response']) if 'response' in block else None
        handle_cmd(cmd, resp)
    elif btype == 'reset':
        print("RESET", block['comment'])
        global state, bfstate, k2hdrbyte, k2state
        state = RAW
        bfstate = None
        k2hdrbyte = None
        k2state = None
    elif btype == 'comment':
        print(block['comment'])

def main():
    with open('ndsbfstate.bin', 'rb') as statef:
        ndsbf.init_state(statef.read())
    with open(sys.argv[1], 'rb') as jsonf:
        data = json.load(jsonf)
    for block in data:
        handle(block)

if __name__ == '__main__':
    main()
