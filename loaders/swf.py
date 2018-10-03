# Shockwave Flash File Loader
#
# Copyright (C) 2018 Kaspersky Lab
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import idaapi
import idc
from ida_idp import *
from ida_auto import *
from ida_segment import *
from ida_bytes import *
import struct
import zlib

types = {
     0 : "End",
     1 : "ShowFrame",
     2 : "DefineShape",
     3 : "FreeCharacter",
     4 : "PlaceObject",
     5 : "RemoveObject",
     6 : "DefineBits",
     7 : "DefineButton",
     8 : "JPEGTables",
     9 : "SetBackgroundColor",
    10 : "DefineFont",
    11 : "DefineText",
    12 : "DoAction",
    13 : "DefineFontInfo",
    14 : "DefineSound",
    15 : "StartSound",
    17 : "DefineButtonSound",
    18 : "SoundStreamHead",
    19 : "SoundStreamBlock",
    20 : "DefineBitsLossless",
    21 : "DefineBitsJPEG2",
    22 : "DefineShape2",
    23 : "DefineButtonCxform",
    24 : "Protect",
    25 : "PathsArePostScript",
    26 : "PlaceObject2",
    28 : "RemoveObject2",
    32 : "DefineShape3",
    33 : "DefineText2",
    34 : "DefineButton2",
    35 : "DefineBitsJPEG3",
    36 : "DefineBitsLossless2",
    39 : "DefineSprite",
    41 : "ProductInfo",
    43 : "FrameLabel",
    45 : "SoundStreamHead2",
    46 : "DefineMorphShape",
    48 : "DefineFont2",
    37 : "DefineEditText",
    56 : "ExportAssets",
    57 : "ImportAssets",
    58 : "EnableDebugger",
    59 : "DoInitAction",
    60 : "DefineVideoStream",
    61 : "VideoFrame",
    62 : "DefineFontInfo2",
    63 : "DebugID",
    64 : "EnableDebugger2",
    65 : "ScriptLimits",
    66 : "SetTabIndex",
    69 : "FileAttributes",
    70 : "PlaceObject3",
    71 : "ImportAssets2",
    72 : "DoABC", # DoABC1 - raw DoABC without flags
    73 : "DefineFontAlignZones",
    74 : "CSMTextSettings",
    75 : "DefineFont3",
    76 : "SymbolClass",
    77 : "Metadata",
    78 : "DefineScalingGrid",
    82 : "DoABC", # DoABC2 - regular DoABC 
    83 : "DefineShape4",
    84 : "DefineMorphShape2",
    86 : "DefineSceneAndFrameLabelData",
    87 : "DefineBinaryData",
    88 : "DefineFontName",
    91 : "DefineFont4"                 
}

code = ["DefineButton",
        "DoAction",
        "DoInitAction",
        "DoABC"]

def accept_file(li, filename):

    li.seek(0)

    magic = li.read(3)
    version = ord(li.read(1))

    if magic == "FWS":
        return {'format': "Shockwave Flash File (v%d)" % version, 'processor':''}
    if magic == "CWS":
        return {'format': "Compressed SWF File (v%d)" % version, 'processor':''}
    else:
        return 0

def read_rect_size(li):

    nbits = idc.get_wide_byte(8) >> 3
    return ((5 + 4*nbits) + 7) / 8

def disable_auto(offset, size):

    auto_unmark(offset, size, AU_UNK)
    auto_unmark(offset, size, AU_CODE)
    auto_unmark(offset, size, AU_WEAK)
    auto_unmark(offset, size, AU_PROC)
    auto_unmark(offset, size, AU_TAIL)
    auto_unmark(offset, size, AU_TRSP)
    auto_unmark(offset, size, AU_USED)
    auto_unmark(offset, size, AU_TYPE)
    auto_unmark(offset, size, AU_LIBF)
    auto_unmark(offset, size, AU_LBF2)
    auto_unmark(offset, size, AU_LBF3)
    auto_unmark(offset, size, AU_CHLB)
    auto_unmark(offset, size, AU_FINAL)

def load_file(li, neflags, format):

    li.seek(0)

    magic = li.read(3)
    version = ord(li.read(1))
    size = struct.unpack("<L", li.read(4))[0]

    selector = 0
    offset = 0

    set_processor_type("SWF-AS3", SETPROC_LOADER)

    if (magic == "CWS"):

        compressed = li.read(size-8)

        data = zlib.decompress(compressed)

        set_selector(selector, 0)
        add_segm(selector, offset, size, None, None, ADDSEG_QUIET)
        set_segm_addressing(getseg(offset), 1)

        put_bytes(0, "F")
        put_bytes(1, "W")
        put_bytes(2, "S")
        put_bytes(3, chr(version))
        put_bytes(4, struct.pack("<L", size))
        put_bytes(8, data)

    else:

        li.file2base(offset, offset, size, idaapi.FILEREG_PATCHABLE)

    end = 0xC + read_rect_size(li)

    set_selector(selector, 0)
    add_segm(selector, offset, end, "Header", "UNDEF")
    set_segm_addressing(getseg(offset), 1)

    while (offset < size):

        try:

            selector += 1
            offset = end
        
            tag_code_and_length = idc.get_wide_word(offset)
        
            tag_type = tag_code_and_length >> 6
            length = tag_code_and_length & 0x3F 
        
            if (length == 0x3F):
        
                length = idc.get_wide_dword(offset + 2)
                end = offset + 6 + length
        
            else:
                end = offset + 2 + length
        
            set_selector(selector, 0)
        
            if (tag_type in types):
        
                if (types[tag_type] in code):
                    add_segm(selector, offset, end, types[tag_type], "CODE")
                else:
                    add_segm(selector, offset, end, types[tag_type], "DATA")

                set_segm_addressing(getseg(offset), 1)

                if (types[tag_type] == "End"):
                    break

            else:
                add_segm(selector, offset, end, "Tag%02X" % tag_type, "DATA")
                set_segm_addressing(getseg(offset), 1)

        except:
            break

    disable_auto(0 , size)

    return 1
