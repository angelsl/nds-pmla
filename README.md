# Poor man's tools for logic analysing NDS carts

## `pd/`

A Sigrok protocol decoder for the NDS cart protocol. It expects 4 data channels, CLK, RES and CS. Modify as needed if you
don't want a particular channel.

## `combine.py`

A tool to combine two halves of output from Sigrok.
