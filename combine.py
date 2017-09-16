#!/usr/bin/python3
import struct, sys, io

NORMAL, ZEROLEN, RESET, EOF, GETNEXT = range(5)
TSDIFF_TOLERANCE = 15000

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def check(high, low, fn, err):
    result = True
    if not fn(low):
        eprint("lowfile: {}", err)
        result = False
    if not fn(high):
        eprint("highfile: {}", err)
        result = False
    return result

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
            print("skipped low data block due to lag (hights = {}, lowts = {}, diff = {})\n".format(hights, lowts, abs(hights-lowts)))
            eprint("warn: high ahead by too many samples, skipping low..")
            lowf.seek(lowl, io.SEEK_CUR)
            lows = GETNEXT
            continue
        if lowts - hights > TSDIFF_TOLERANCE and highs == NORMAL:
            print("skipped high data block due to lag (hights = {}, lowts = {}, diff = {})\n".format(hights, lowts, abs(hights-lowts)))
            eprint("warn: low ahead by too many samples, skipping high..")
            highf.seek(highl, io.SEEK_CUR)
            highs = GETNEXT
            continue

    if higheof or loweof:
        if not higheof:
            eprint("warn: low EOF before high, before", highf.tell())
            print("LOW EOF")
        elif not loweof:
            eprint("warn: high EOF before low, before", lowf.tell())
            print("HIGH EOF")
        break

    if highreset or lowreset:
        if not highreset:
            assert lowreset
            eprint("warn: low RESET but not high")
            print("LOW RESET, hights/lowts/diff", hights, lowts, abs(hights-lowts))
            lows = GETNEXT
            continue
        elif not lowreset:
            assert highreset
            eprint("warn: high RESET but not low")
            print("HIGH RESET, hights/lowts/diff", hights, lowts, abs(hights-lowts))
            highs = GETNEXT
            continue
        else:
            assert highreset and lowreset
            print("RESET, hights/lowts/diff", hights, lowts, abs(hights-lowts))
            highs = lows = GETNEXT
            continue

    if high0len or low0len:
        if not high0len:
            assert low0len
            eprint("warn: spurious fall/rise of CS on low, before/ts", lowf.tell(), lowts)
            print("LOW SPURIOUS CS, hights/lowts/diff", hights, lowts, abs(hights-lowts))
            lows = GETNEXT
            continue
        elif not low0len:
            assert high0len
            eprint("warn: spurious fall/rise of CS on high, before/ts", highf.tell(), hights)
            print("HIGH SPURIOUS CS, hights/lowts/diff", hights, lowts, abs(hights-lowts))
            highs = GETNEXT
            continue
        else:
            assert high0len and low0len
            eprint("warn: spurious fall/rise of CS on both, before high/low/hights/lowts", highf.tell(), lowf.tell(), hights, lowts)
            print("SPURIOUS CS, hights/lowts/diff", hights, lowts, abs(hights-lowts))
            highs = lows = GETNEXT
            continue

    assert highl != 0xFFFFFFFF and lowl != 0xFFFFFFFF and highl > 0 and lowl > 0

    if highl != lowl:
        print("skipped block due to size mismatch (high {} != low {}) (hights {} lowts {} diff {})\n".format(highl, lowl, hights, lowts, abs(hights-lowts)))
        eprint("warn: high len ({}) != low len ({}) before {} (high)/{} (low), skipping".format(highl, lowl, highf.tell(), lowf.tell()))
        highf.seek(highl, io.SEEK_CUR)
        lowf.seek(lowl, io.SEEK_CUR)
        highs = lows = GETNEXT
        continue

    if not (highl - 8) in [0, 4, 0x200, 0x400, 0x800, 0x1000, 0x2000, 0x4000]:
        eprint("warn: weird command+response length of {} (0x{:X}) before {} (high)/{} (low)".format(highl, highl, highf.tell(), lowf.tell()))
    highb, lowb = getdata(highf, highl, 'high'), getdata(lowf, lowl, 'low')
    if highb is None or lowb is None:
        break
    combined = combine(highb, lowb)
    if highl < 8:
        eprint("warn: less than 8 bytes command+response before high/low", highf.tell(), lowf.tell())
        print("CMD : {}", fmtba(combined))
    else:
        print("CMD :", fmtba(combined[:8]))
        print("RESP:", fmtba(combined[8:]))
    print()
    highs = lows = GETNEXT
