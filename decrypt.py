#!/usr/bin/python3

import sys, json, ndsbf

RAW, KEY1, KEY2 = range(3)
state = RAW

def state_str():
    global state
    if state == RAW:
        return "RAW"
    elif state == KEY1:
        return "KEY1"
    elif state == KEY2:
        return "KEY2"

def print_cmd(cmd, resp=None):
    print("{} CMD:".format(state_str()), cmd)
    if resp:
        print("RESP:", resp)

def handle_cmd(cmd, resp):
    global state, bfstate
    newstate = state
    if state == RAW:
        cmd0 = cmd[0]
        if cmd0 == 0x9F:
            print_cmd("dummy")
        elif cmd0 == 0:
            gamecode = resp[0xC:0x10]

            print_cmd("header", "gamecode: {}".format(gamecode.hex()))
            bfstate = ndsbf.Cipher()
            bfstate.init_key(gamecode, 2)
        elif cmd0 == 0x90:
            print_cmd("get chipid")
        elif cmd0 == 0x3C:
            print_cmd("switch to KEY1")
            newstate = KEY1
        else:
            print_cmd(cmd.hex())
    elif state == KEY1:
        cmd = bfstate.decrypt_block(cmd)
        cmd0 = cmd[0] >> 4
        if cmd0 == 0x4:
            print_cmd("key2 seed")
        elif cmd0 == 0x1:
            print_cmd("get chipid")
        elif cmd0 == 0x2:
            print_cmd("get secure area")
        elif cmd0 == 0xA:
            print_cmd("switch to KEY2")
            newstate = KEY2
        else:
            print_cmd(cmd.hex())
    state = newstate


def handle(block):
    global state
    btype = block['type']
    if btype == 'command':
        cmd = bytes.fromhex(block['command'])
        resp = bytes.fromhex(block['response']) if 'response' in block else None
        handle_cmd(cmd, resp)
    elif btype == 'reset':
        print("RESET", block['comment'])
        state = RAW
    elif btype == 'comment':
        print(block['comment'])

def main():
    global bfstate
    with open('ndsbfstate.bin', 'rb') as statef:
        ndsbf.init_state(statef.read())
    with open(sys.argv[1], 'rb') as jsonf:
        data = json.load(jsonf)
    for block in data:
        handle(block)

if __name__ == '__main__':
    main()
