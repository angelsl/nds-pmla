#!/usr/bin/python3
import struct, sys, io, binascii, json

NORMAL, ZEROLEN, RESET, EOF, GETNEXT = range(5)
TSDIFF_TOLERANCE = 15000

def eprint(*args, output=None, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    if not output is None:
        output.append({'type': 'comment', 'comment': ' '.join(args)})
    else:
        print(*args, **kwargs)
        print()

def getlen(f):
    b = f.read(8)
    if len(b) < 8:
        return (EOF, 0, 0)
    l, ts = struct.unpack("<II", b)
    if l == 0xFFFFFFFF:
        return (RESET, 0, ts)
    if l == 0:
        return (ZEROLEN, 0, ts)
    return (NORMAL, l, ts)

def getdata(f, l, t, alwaysreturn=False):
    b = f.read(l)
    m = len(b)
    if m < l:
        eprint("err: not enough bytes on {} (need {} but only {} left)"
            .format(t, l, m))
        if not alwaysreturn:
            return None
    return b

def combine(h, l):
    sz = len(h)
    assert sz == len(l)
    ret = bytearray(sz)
    for i in range(sz):
        ret[i] = (h[i] << 4) | l[i]
    return ret

def fmtba(ba):
    return ' '.join(map(lambda b: '{:02X}'.format(b), ba))

def main():
    output = []
    highf, lowf = open(sys.argv[1], 'rb'), open(sys.argv[2], 'rb')
    highs = lows = GETNEXT

    while True:
        if highs == GETNEXT:
            highs, highl, hights = getlen(highf)
        if lows == GETNEXT:
            lows, lowl, lowts = getlen(lowf)

        higheof, loweof = highs == EOF, lows == EOF
        high0len, low0len = highs == ZEROLEN, lows == ZEROLEN
        highreset, lowreset = highs == RESET, lows == RESET

        if (hights > 0 and lowts > 0
            and (highs == NORMAL or lows == NORMAL)):
            if hights - lowts > TSDIFF_TOLERANCE and lows == NORMAL:
                eprint("warn: skipped low data block due to lag (hights = {}, lowts = {}, diff = {})"
                    .format(hights, lowts, abs(hights-lowts)), output=output)
                lowf.seek(lowl, io.SEEK_CUR)
                lows = GETNEXT
                continue
            if lowts - hights > TSDIFF_TOLERANCE and highs == NORMAL:
                eprint("warn: skipped high data block due to lag (hights = {}, lowts = {}, diff = {})"
                    .format(hights, lowts, abs(hights-lowts)), output=output)
                highf.seek(highl, io.SEEK_CUR)
                highs = GETNEXT
                continue

        if higheof or loweof:
            if not higheof:
                eprint("warn: low EOF before high (highf.tell() = {})"
                    .format(highf.tell()), output=output)
            elif not loweof:
                eprint("warn: high EOF before low (lowf.tell() = {})"
                    .format(lowf.tell()), output=output)
            break

        if highreset or lowreset:
            if not highreset:
                assert lowreset
                eprint("warn: low RESET but not high (hights = {}, lowts = {}, diff = {})"
                    .format(hights, lowts, abs(hights-lowts)), output=output)
                lows = GETNEXT
                continue
            elif not lowreset:
                assert highreset
                eprint("warn: high RESET but not low (hights = {}, lowts = {}, diff = {})"
                    .format(hights, lowts, abs(hights-lowts)), output=output)
                highs = GETNEXT
                continue
            else:
                assert highreset and lowreset
                output.append({
                    'type': 'reset',
                    'comment': "(hights = {}, lowts = {}, diff = {})"
                        .format(hights, lowts, abs(hights-lowts))
                    })
                highs = lows = GETNEXT
                continue

        if high0len or low0len:
            if not high0len:
                assert low0len
                eprint("warn: spurious fall/rise of CS on low (hights = {}, lowts = {}, diff = {})"
                    .format(hights, lowts, abs(hights-lowts)), output=output)
                lows = GETNEXT
                continue
            elif not low0len:
                assert high0len
                eprint("warn: spurious fall/rise of CS on high (hights = {}, lowts = {}, diff = {})"
                    .format(hights, lowts, abs(hights-lowts)), output=output)
                highs = GETNEXT
                continue
            else:
                assert high0len and low0len
                eprint("warn: spurious fall/rise of CS on both (hights = {}, lowts = {}, diff = {})"
                    .format(hights, lowts, abs(hights-lowts)), output=output)
                highs = lows = GETNEXT
                continue

        assert highl != 0xFFFFFFFF and lowl != 0xFFFFFFFF and highl > 0 and lowl > 0

        if highl != lowl:
            eprint("warn: skipped block due to size mismatch (high {} != low {}) (hights = {}, lowts = {}, diff = {}, highf.tell = {}, lowf.tell = {})"
                .format(highl, lowl, hights, lowts, abs(hights-lowts), highf.tell(), lowf.tell()), output=output)
            highf.seek(highl, io.SEEK_CUR)
            lowf.seek(lowl, io.SEEK_CUR)
            highs = lows = GETNEXT
            continue

        if not (highl - 8) in [0, 4, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000]:
            eprint("warn: weird command+response length of {} (0x{:X}) (highf.tell() = {}, lowf.tell() = {})"
                .format(highl, highl, highf.tell(), lowf.tell()), output=output)
        highb, lowb = getdata(highf, highl, 'high'), getdata(lowf, lowl, 'low')
        if highb is None or lowb is None:
            break
        combined = combine(highb, lowb)
        if highl < 8:
            eprint("warn: less than 8 bytes command+response (highf.tell() = {}, lowf.tell() = {})"
                .format(highf.tell(), lowf.tell()), output=output)
            output.append({
                'type': 'command',
                'command': binascii.hexlify(combined).decode("utf-8")
            })
        else:
            output.append({
                'type': 'command',
                'command': binascii.hexlify(combined[:8]).decode("utf-8"),
                'response': binascii.hexlify(combined[8:]).decode("utf-8")
            })
        highs = lows = GETNEXT
    print(json.dumps(output))

if __name__ == "__main__":
    main()
