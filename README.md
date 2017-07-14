# README - Wireshark Lua parser for OpenFlow 1.5
This is a largely incomplete Wireshark parser for OpenFlow 1.5.
I started it as an excuse to get exposed to Lua, and because I found myself
often struggling with the dissector which can be automatically generated 
using [LoxiGen](https://github.com/floodlight/loxigen).

Right now only few messages are parsed, and I am picking which ones
I'll be implementing next on a per-need basis.

## Installation
1. Make sure Wireshark is compiled `--with-lua` support and that it can be
   run without root permissions
2. Download this code
3. Copy the main file `openflow_lua.lua` in the Wireshark plugin folder
4. Export the `LUA_PATH` to include the path to the folder where the original
   `openflow_lua.lua` is located. For Lua>=5.2 this environment variable would
   look something like this:
```
export LUA_PATH_5_2=/home/myname/wireshark_openflow_dissector/
```
