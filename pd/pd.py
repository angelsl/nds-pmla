##
## This file is part of the libsigrokdecode project.
##
## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or
## (at your option) any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with this program; if not, see <http://www.gnu.org/licenses/>.
##

import sigrokdecode as srd

class Decoder(srd.Decoder):
    api_version = 3
    id = 'halfnds'
    name = 'Half NDS'
    longname = 'Half NDS ROM'
    desc = 'The Nintendo DS cart ROM protocol.'
    license = 'gplv2+'
    inputs = ['logic']
    outputs = ['halfnds']
    channels = (
        {'id': 'd0', 'name': 'D0', 'desc': 'Data 0'},
        {'id': 'd1', 'name': 'D1', 'desc': 'Data 1'},
        {'id': 'd2', 'name': 'D2', 'desc': 'Data 2'},
        {'id': 'd3', 'name': 'D3', 'desc': 'Data 3'},
        {'id': 'clk', 'name': 'CLK', 'desc': 'Clock'},
        {'id': 'cs', 'name': 'CS', 'desc': 'Chip select'},
        {'id': 'res', 'name': 'RES', 'desc': 'Reset'},
    )
    annotations = (
        ('nybbles', 'Data nybbles'),
        ('resets', 'Cart resets'),
        ('cs', 'ROM selected'),
    )
    annotation_rows = (
        ('d', 'Data', (0,)),
        ('cs', 'CS', (2,)),
        ('res', 'RES', (1,)),
    )

    def __init__(self):
        self.reset_start = None
        self.cs_start = None

    def start(self):
        self.out_ann = self.register(srd.OUTPUT_ANN)

    def handle_reset(self, data):
        # resetting
        if data[6] == 0:
            self.reset_start = self.samplenum
        # reset
        elif data[6] == 1 and not self.reset_start is None:
            self.put(self.reset_start, self.samplenum, self.out_ann,
                [1, ["Reset", "RES", "R"]])
            self.reset_start = None

    def handle_cs(self, data):
        # start select
        if data[5] == 0:
            self.cs_start = self.samplenum
        # no longer selected
        elif data[5] == 1 and not self.cs_start is None:
            self.put(self.cs_start, self.samplenum, self.out_ann,
                [2, ["Selected", "CS", "S"]])
            self.cs_start = None

    def handle_data(self, data):
        # if CLK is not high, wtf?
        assert data[4] == 1
        # if CS is high or RES is low, bail
        if data[5] == 1 or data[6] == 0:
            return
        nybble = (data[0]) + (data[1]<<1) + (data[2]<<2) + (data[3]<<3)
        self.put(self.samplenum, self.samplenum, self.out_ann,
                [0, ["{:X}".format(nybble)]])

    def decode(self):
        while True:
            result = self.wait([{4: 'r'}, {5: 'e'}, {6: 'e'}])
            clk, cs, res = self.matched
            if clk:
                self.handle_data(result)
            if cs:
                self.handle_cs(result)
            if res:
                self.handle_reset(result)

