# Adobe Flash ActionScript3 processor module
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
from ida_bytes import *
from ida_auto import *
from ida_name import *
from ida_lines import *
from ida_xref import *
from ida_ua import *
from ida_segment import *
from ida_problems import *
from PyQt5 import QtWidgets
import cPickle
import string
import struct

class ConstKind:

    CONSTANT_Void               = 0x00
    CONSTANT_Utf8               = 0x01
    CONSTANT_Float              = 0x02
    CONSTANT_Int                = 0x03
    CONSTANT_UInt               = 0x04
    CONSTANT_PrivateNs          = 0x05
    CONSTANT_Double             = 0x06
    CONSTANT_Qname              = 0x07
    CONSTANT_Namespace          = 0x08
    CONSTANT_Multiname          = 0x09
    CONSTANT_False              = 0x0A
    CONSTANT_True               = 0x0B
    CONSTANT_Null               = 0x0C
    CONSTANT_QnameA             = 0x0D
    CONSTANT_MultinameA         = 0x0E
    CONSTANT_RTQname            = 0x0F
    CONSTANT_RTQnameA           = 0x10
    CONSTANT_RTQnameL           = 0x11
    CONSTANT_RTQnameLA          = 0x12
    CONSTANT_NamespaceSet       = 0x15
    CONSTANT_PackageNamespace   = 0x16
    CONSTANT_PackageInternalNs  = 0x17
    CONSTANT_ProtectedNamespace = 0x18
    CONSTANT_ExplicitNamespace  = 0x19
    CONSTANT_StaticProtectedNs  = 0x1A
    CONSTANT_MultinameL         = 0x1B
    CONSTANT_MultinameLA        = 0x1C
    CONSTANT_TypeName           = 0x1D
    CONSTANT_Float4             = 0x1E

    Names = [
        "Void",
        "Utf8",
        "Decimal",
        "Integer",
        "UInteger",
        "PrivateNamespace",
        "Double",
        "QName",
        "Namespace",
        "Multiname",
        "False",
        "True",
        "Null",
        "QNameA",
        "MultinameA",
        "RTQName",
        "RTQNameA",
        "RTQNameL",
        "RTQNameLA",
        "",
        "",
        "Namespace_Set",
        "PackageNamespace",
        "PackageInternalNs",
        "ProtectedNamespace",
        "ExplicitNamespace",
        "StaticProtectedNs",
        "MultinameL",
        "MultinameLA",
        "TypeName",
        "Float4",
    ]

class MethodFlags:

    NEED_ARGUMENTS              = 0x01
    NEED_ACTIVATION             = 0x02
    NEED_REST                   = 0x04
    HAS_OPTIONAL                = 0x08
    IGNORE_REST                 = 0x10
    NATIVE                      = 0x20
    SETS_DXNS                   = 0x40
    HAS_PARAM_NAMES             = 0x80

    Names = [
        "NEED_ARGUMENTS", 
        "NEED_ACTIVATION", 
        "NEED_REST", 
        "HAS_OPTIONAL", 
        "IGNORE_REST", 
        "NATIVE", 
        "SETS_DXNS", 
        "HAS_PARAM_NAMES"
    ]

class InstanceFlags:

    CONSTANT_ClassSealed        = 0x01
    CONSTANT_ClassFinal         = 0x02
    CONSTANT_ClassInterface     = 0x04
    CONSTANT_ClassProtectedNs   = 0x08

class TraitKind:

    TRAIT_Slot                  = 0x00
    TRAIT_Method                = 0x01
    TRAIT_Getter                = 0x02
    TRAIT_Setter                = 0x03
    TRAIT_Class                 = 0x04
    TRAIT_Function              = 0x05
    TRAIT_Const                 = 0x06

    Names = [
        "slot", 
        "method", 
        "getter", 
        "setter", 
        "class", 
        "function", 
        "const"
    ]

class TraitAttributes:

    ATTR_Final                  = 0x10
    ATTR_Override               = 0x20
    ATTR_Metadata               = 0x40

class OperandType:

    CONSTANT_Unknown            = 0x00
    CONSTANT_ByteImm            = 0x01
    CONSTANT_UByteImm           = 0x02
    CONSTANT_IntImm             = 0x03
    CONSTANT_UIntImm            = 0x04
    CONSTANT_Int                = 0x05
    CONSTANT_UInt               = 0x06
    CONSTANT_Double             = 0x07
    CONSTANT_String             = 0x08
    CONSTANT_Namespace          = 0x09
    CONSTANT_Multiname          = 0x10
    CONSTANT_Class              = 0x11
    CONSTANT_Method             = 0x12
    CONSTANT_Label              = 0x13
    CONSTANT_DefaultLabel       = 0x14
    CONSTANT_LabelsList         = 0x15

class Reader:

    pos = 0

    @staticmethod
    def read_byte(insn=None):

        if (insn):
            b = insn.get_next_byte()
        else:
            b = idc.get_wide_byte(Reader.pos)
            Reader.pos += 1
        return b
    
    @staticmethod
    def read_encoded_u32(insn=None):

        value = 0
        for i in xrange(5):
        
            b = Reader.read_byte(insn)

            value |= (b & 0x7F) << (7 * i)

            if not (b & 0x80):
                break
    
        return value
    
    @staticmethod
    def read_s24(insn=None):
    
        b = Reader.read_byte(insn)
        value = b
        b = Reader.read_byte(insn)
        value |= b << 8
        b = Reader.read_byte(insn)

        value |= b << 0x10

        if (value & 0x00800000):
            value |= 0xFF000000

        return value
    
    @staticmethod
    def get_array_count():
        return Reader.read_encoded_u32()

class Tag:

    def __init__(self):
        self.start = 0
        self.tag_code = 0
        self.tag_length = 0
        self.data_length = 0
        self.flags = 0
        self.name = ""
        self.minor_version = 0
        self.major_version = 0

    def find(self):

        ea = idc.get_first_seg()

        tags = []
        while (ea != ida_idaapi.BADADDR):
            if (idc.get_segm_name(ea) == "DoABC"):
                name = idc.get_strlit_contents(ea + 0xA)
                tags.append("%d - %s" % (ea, name))

            ea = idc.get_next_seg(ea)
        
        if (tags == []):
            return False

        if (len(tags) > 1):
            app = QtWidgets.QWidget()
            ea, ok = QtWidgets.QInputDialog.getItem(app, "Select DoABC tag", 
                                                    "List of DoABC tags", 
                                                    tags, 0, False)

            if (ea and ok):
                ea = long(ea.split()[0])
            else:
                return False

        else:
            ea = long(tags[0].split()[0])

        Reader.pos = ea

        return True

    def parse(self):
    
        self.start = Reader.pos

        tag_code_and_length = idc.get_wide_word(Reader.pos)
        Reader.pos += 2
        
        self.tag_code = tag_code_and_length >> 6
        self.tag_length = tag_code_and_length & 0x3F
        
        self.data_length = idc.get_wide_dword(Reader.pos)
        Reader.pos += 4
        
        if (self.tag_code != 0x48): # DoABC1

            self.flags = idc.get_wide_dword(Reader.pos)
            Reader.pos += 4
            
            self.name = idc.get_strlit_contents(Reader.pos)
    
            if (self.name is not None):
                Reader.pos += len(self.name)
    
            Reader.pos += 1
        
        self.minor_version = idc.get_wide_word(Reader.pos)
        Reader.pos += 2
        
        self.major_version = idc.get_wide_word(Reader.pos)
        Reader.pos += 2

class ConstantPool:

    def __init__(self):

        self.abc_ints = [0]
        self.abc_uints = [0]
        self.abc_doubles = [0]
        self.abc_strings = ["null"]
        self.abc_namespaces = []
        self.abc_namespace_sets = []
        self.abc_multinames = []
        self.abc_methods = []
        self.abc_metadata = []
        self.abc_instances = []
        self.abc_scripts = []
        self.abc_bodies = []

    def parse_integers(self):

        start = Reader.pos
        idc.set_name(Reader.pos, "cpool_ints")

        count = Reader.get_array_count()
    
        for i in xrange(1, count, 1):
            self.abc_ints.append(Reader.read_encoded_u32())
    
        create_byte(start, Reader.pos - start)

    def parse_uintegers(self):

        start = Reader.pos
        idc.set_name(Reader.pos, "cpool_uints")

        count = Reader.get_array_count()
    
        for i in xrange(1, count, 1):
            self.abc_uints.append(Reader.read_encoded_u32())

        create_byte(start, Reader.pos - start)

    def parse_doubles(self):

        start = Reader.pos
        idc.set_name(Reader.pos, "cpool_doubles")

        count = Reader.get_array_count()
    
        for i in xrange(1, count, 1):
            self.abc_doubles.append(idc.get_qword(Reader.pos))
            Reader.pos += 8
    
        create_byte(start, Reader.pos - start)

    def parse_strings(self):
        
        idc.set_name(Reader.pos, "cpool_strings")

        count = Reader.get_array_count()
    
        for i in xrange(1, count, 1):
    
            size = Reader.read_encoded_u32()

            start = Reader.pos
    
            string = ""
            for i in xrange(size):
                string += chr(Reader.read_byte())
    
            self.abc_strings.append(string)
    
            create_strlit(start, size, idc.STRTYPE_C)

    def parse_namespaces(self):

        start = Reader.pos
        idc.set_name(Reader.pos, "cpool_namespaces")

        self.abc_namespaces.append({"kind": 0, "name": 0})

        count = Reader.get_array_count()
        
        for i in xrange(1, count, 1):
            kind = Reader.read_byte()
            name = Reader.read_encoded_u32()
            self.abc_namespaces.append({"kind": kind, "name": name})

        create_byte(start, Reader.pos - start)

    def parse_namespace_sets(self):
    
        start = Reader.pos
        idc.set_name(Reader.pos, "cpool_nsets")

        self.abc_namespace_sets.append([0])

        count = Reader.get_array_count()
    
        for i in xrange(1, count, 1):
        
            namespace_count = Reader.get_array_count()
            offsets = []
    
            for j in xrange(namespace_count):
                offsets.append(Reader.read_encoded_u32())
    
            self.abc_namespace_sets.append(offsets)

        create_byte(start, Reader.pos - start)

    def parse_multinames(self):
    
        start = Reader.pos
        idc.set_name(Reader.pos, "cpool_multinames")

        self.abc_multinames.append({})

        count = Reader.get_array_count()
            
        for i in xrange(1, count, 1):
        
            kind = Reader.read_byte()
    
            if (kind == ConstKind.CONSTANT_Qname or kind == ConstKind.CONSTANT_QnameA):
                ns = Reader.read_encoded_u32()
                name = Reader.read_encoded_u32()
                self.abc_multinames.append({"kind": kind, "name": name, "value": ns})
                    
            elif (kind == ConstKind.CONSTANT_RTQname or kind == ConstKind.CONSTANT_RTQnameA):
                name = Reader.read_encoded_u32()
                self.abc_multinames.append({"kind": kind, "name": name})
            
            elif (kind == ConstKind.CONSTANT_RTQnameL or kind == ConstKind.CONSTANT_RTQnameLA):
                self.abc_multinames.append({"kind": kind})
                    
            elif (kind == ConstKind.CONSTANT_Multiname or kind == ConstKind.CONSTANT_MultinameA):
                name = Reader.read_encoded_u32()
                ns_set = Reader.read_encoded_u32()
                self.abc_multinames.append({"kind": kind, "name": name, "value": ns_set})
    
            elif (kind == ConstKind.CONSTANT_MultinameL or kind == ConstKind.CONSTANT_MultinameLA):
                ns_set = Reader.read_encoded_u32()
                self.abc_multinames.append({"kind": kind, "value": ns_set})
                    
            elif (kind == ConstKind.CONSTANT_TypeName):
                name = Reader.read_encoded_u32()
                param_count = Reader.get_array_count()
    
                params = []
                for j in xrange(param_count):
                    params.append(Reader.read_encoded_u32())
    
                self.abc_multinames.append({"kind": kind, "name": name, "value": params})
                    
            else:
                raise Exception("parse_multinames: unknown kind")
    
        create_byte(start, Reader.pos - start)

    def parse_methods(self):

        start = Reader.pos
        idc.set_name(Reader.pos, "cpool_methods")

        count = Reader.get_array_count()
    
        for i in xrange(count):
        
            pos = Reader.pos

            param_count = Reader.read_encoded_u32()
            return_type = Reader.read_encoded_u32()
    
            params = []
            for j in xrange(param_count):
                params.append(Reader.read_encoded_u32())
            
            name = Reader.read_encoded_u32()
            flags = Reader.read_byte()
    
            options = []
            if ((flags & MethodFlags.HAS_OPTIONAL) != 0):
            
                option_count = Reader.get_array_count()
    
                for j in xrange(option_count):
                    value = Reader.read_encoded_u32()
                    kind = Reader.read_byte()
                    options.append({"kind": kind, "value": value})
                
            param_names = []
            if ((flags & MethodFlags.HAS_PARAM_NAMES) != 0):
    
                for j in xrange(param_count):
                    param_names.append(Reader.read_encoded_u32())
            
            self.abc_methods.append({"paramtypes": params, "returntype": return_type, "name": name, 
                                     "flags": flags, "options": options, "paramnames": param_names, 
                                     "pos": pos, "id": i})

        create_byte(start, Reader.pos - start)

    def parse_metadata(self):

        start = Reader.pos
        idc.set_name(Reader.pos, "cpool_metadata")

        count = Reader.get_array_count()
    
        for i in xrange(count):
        
            name = Reader.read_encoded_u32()
            item_count = Reader.get_array_count()
    
            items = []
            for j in xrange(item_count):
                key = Reader.read_encoded_u32()
                value = Reader.read_encoded_u32()      
                items.append({"key": key, "value": value})
    
            self.abc_metadata.append({"name": name, "items": items})

        create_byte(start, Reader.pos - start)

    def parse_traits(self):
    
        count = Reader.get_array_count()

        traits = []
        for i in xrange(count):
    
            name = Reader.read_encoded_u32()
            
            tag = Reader.read_byte()
            kind = tag & 0x0F
            attr = tag & 0xF0
    
            gen_id = Reader.read_encoded_u32()
            gen_index = Reader.read_encoded_u32()
    
            value_index = 0
            value_kind = 0

            if (kind == TraitKind.TRAIT_Slot or kind == TraitKind.TRAIT_Const):
                value_index = Reader.read_encoded_u32()
                if (value_index != 0):
                    value_kind = Reader.read_byte()
            
            metadata = []
            if ((attr & TraitAttributes.ATTR_Metadata) != 0):
            
                metadata_count = Reader.get_array_count()
    
                for j in xrange(metadata_count):
                    metadata.append(Reader.read_encoded_u32())
    
            traits.append({"name": name, "tkind": kind, "attr": attr, "metadata": metadata, 
                           "id": gen_id, "index": gen_index, "value_id": value_index, 
                           "value_kind": value_kind})
    
        return traits
    
    def parse_classes(self):
    
        start = Reader.pos
        idc.set_name(Reader.pos, "cpool_classes")

        count = Reader.get_array_count()
    
        # read instances
        for i in xrange(count):

            name = Reader.read_encoded_u32()
            super_name = Reader.read_encoded_u32()
            flags = Reader.read_byte()
    
            protected_ns = 0
            if ((flags & InstanceFlags.CONSTANT_ClassProtectedNs) != 0):
                protected_ns = Reader.read_encoded_u32()
            
            interface_count = Reader.get_array_count()
    
            interfaces = []
            for j in xrange(interface_count):
                interface = Reader.read_encoded_u32()
                interfaces.append(interface)
            
            interface_init = Reader.read_encoded_u32()
            interface_traits = self.parse_traits()
    
            self.abc_instances.append({"name": name, "supername": super_name, "flags": flags, 
                                       "protectedns": protected_ns, "interfaces": interfaces, 
                                       "iinit": interface_init, "itraits": interface_traits})

        # read classes
        for i in xrange(count):

            class_init = Reader.read_encoded_u32()
            class_traits = self.parse_traits()
        
            self.abc_instances[i]["cinit"] = class_init
            self.abc_instances[i]["ctraits"] = class_traits
    
        create_byte(start, Reader.pos - start)
    
    def parse_scripts(self):

        start = Reader.pos
        idc.set_name(Reader.pos, "cpool_scripts")

        count = Reader.get_array_count()
    
        for i in xrange(count):

            init = Reader.read_encoded_u32()
            traits = self.parse_traits()

            self.abc_scripts.append({"sinit": init, "traits": traits})

        create_byte(start, Reader.pos - start)

    def parse_method_bodies(self):
    
        count = Reader.get_array_count()
        
        for i in xrange(count):
    
            start = Reader.pos
            idc.set_name(Reader.pos, "cpool_method%d_bodyinfo" % i)

            method = Reader.read_encoded_u32() 
            max_stack = Reader.read_encoded_u32()
            local_count = Reader.read_encoded_u32()
            init_scope_depth = Reader.read_encoded_u32()
            max_scope_depth = Reader.read_encoded_u32()
            code_length = Reader.read_encoded_u32()
            code_pos = Reader.pos
    
            create_byte(start, Reader.pos - start)
    
            Reader.pos += code_length
            
            start = Reader.pos
            idc.set_name(Reader.pos, "cpool_method%d_exceptions" % i)

            exception_count = Reader.get_array_count()

            exceptions = []    
            for j in xrange(exception_count):
            
                exception_from = Reader.read_encoded_u32()
                exception_to = Reader.read_encoded_u32()
                exception_target = Reader.read_encoded_u32()
                exception_type = Reader.read_encoded_u32()
                exception_name = Reader.read_encoded_u32()
            
                exceptions.append({"from": exception_from, "to": exception_to, "target": exception_target, 
                                   "type": exception_type, "name": exception_name})
    
            create_byte(start, Reader.pos - start)

            start = Reader.pos
            idc.set_name(Reader.pos, "cpool_method%d_traits" % i)

            traits = self.parse_traits()
    
            create_byte(start, Reader.pos - start)

            self.abc_bodies.append({"pos": code_pos, "length": code_length, "method": method, 
                                    "maxstack": max_stack, "locals": local_count, 
                                    "init_depth": init_scope_depth, "max_depth": max_scope_depth, 
                                    "exceptions": exceptions, "traits": traits})

    def parse(self):
        
        self.parse_integers()
        self.parse_uintegers()
        self.parse_doubles()
        self.parse_strings()
        self.parse_namespaces()
        self.parse_namespace_sets()
        self.parse_multinames()
        self.parse_methods()
        self.parse_metadata()
        self.parse_classes()
        self.parse_scripts()
        self.parse_method_bodies()

class ABC:

    def __init__(self, cpool):

        self.cpool = cpool
    
        self.namespaces = []
        self.namespace_sets = []
        self.multinames = []
        self.methods = []
        self.metadata = []
        self.classes = []
        self.instances = []
        self.scripts = []

    def get_int(self, index):
        return self.cpool.abc_ints[index]

    def get_uint(self, index):
        return self.cpool.abc_uints[index]

    def get_double(self, index):
        return self.cpool.abc_doubles[index]

    def get_string(self, index):
        return self.cpool.abc_strings[index]

    def get_namespace(self, ns):
        return '%s("%s")' % (ConstKind.Names[ns["kind"]], ns["name"])

    def get_namespace_set(self, ns_set):

        s = "["
        length = len(ns_set)
        for i in xrange(length):
            s += self.get_namespace(ns_set[i])
            if (i < length-1):
                s += ", "
        s += "]"
        
        return s

    def get_multiname(self, mn):
        
        kind = mn["kind"]
        
        if (kind == ConstKind.CONSTANT_Qname or kind == ConstKind.CONSTANT_QnameA):
            name = mn["name"]
            namespace = mn["ns"]
            s = '%s, "%s"' % (self.get_namespace(namespace), name)
        
        elif (kind == ConstKind.CONSTANT_RTQname or kind == ConstKind.CONSTANT_RTQnameA):
            name = mn["name"]
            s = '"%s"' % name
        
        elif (kind == ConstKind.CONSTANT_Multiname or kind == ConstKind.CONSTANT_MultinameA):
            name = mn["name"]
            namespace_set = mn["ns_set"]
            s = '"%s", %s' % (name, self.get_namespace_set(namespace_set))
        
        elif (kind == ConstKind.CONSTANT_MultinameL or kind == ConstKind.CONSTANT_MultinameLA):
            namespace_set = mn["ns_set"]
            s = self.get_namespace_set(namespace_set)
        
        elif (kind == ConstKind.CONSTANT_TypeName):
            name = mn["name"]
            params = mn["params"]
            s = self.get_multiname(name)
            s += "<"
            length = len(params)
            for i in xrange(length):
                self.get_multiname(params[i])
                if (i < length-1):
                    s += ", "
            s += ">"
        
        return "%s(%s)" % (ConstKind.Names[kind], s)

    def get_value(self, value):
    
        if (value["kind"] == ConstKind.CONSTANT_Int):
            s = "%d" % value["value"]
             
        elif (value["kind"] == ConstKind.CONSTANT_UInt):
            s = "%d" % value["value"]
                
        elif (value["kind"] == ConstKind.CONSTANT_Double):
            s = "%g" % struct.unpack(">d", struct.pack(">Q", value["value"]))[0]

        elif (value["kind"] == ConstKind.CONSTANT_Utf8):
            s = value["value"]

        elif (value["kind"] == ConstKind.CONSTANT_Namespace or 
              value["kind"] == ConstKind.CONSTANT_PackageNamespace or
              value["kind"] == ConstKind.CONSTANT_PackageInternalNs or
              value["kind"] == ConstKind.CONSTANT_ProtectedNamespace or
              value["kind"] == ConstKind.CONSTANT_ExplicitNamespace or
              value["kind"] == ConstKind.CONSTANT_StaticProtectedNs or
              value["kind"] == ConstKind.CONSTANT_PrivateNs):
            s = self.get_namespace(value["value"])

        else:
            s = ""

        return "%s(%s)" % (ConstKind.Names[value["kind"]], s)

    def convert_namespaces(self):

        for namespace in self.cpool.abc_namespaces:

            kind = namespace["kind"]
            name = self.get_string(namespace["name"])

            self.namespaces.append({"kind": kind, "name": name})

    def convert_namespace_sets(self):

        for namespace_set in self.cpool.abc_namespace_sets:

            ns_set = []
            for namespace in namespace_set:
                ns_set.append(self.namespaces[namespace])

            self.namespace_sets.append(ns_set)

    def convert_multinames(self):

        for multiname in self.cpool.abc_multinames:
        
            if (multiname == {}):
                self.multinames.append({})
                continue
    
            kind = multiname["kind"]
    
            if (kind == ConstKind.CONSTANT_Qname or kind == ConstKind.CONSTANT_QnameA):
                name = self.get_string(multiname["name"])
                ns = self.namespaces[multiname["value"]]
                self.multinames.append({"kind": kind, "ns": ns, "name": name})
                    
            elif (kind == ConstKind.CONSTANT_RTQname or kind == ConstKind.CONSTANT_RTQnameA):
                name = self.get_string(multiname["name"])
                self.multinames.append({"kind": kind, "name": name})
            
            elif (kind == ConstKind.CONSTANT_RTQnameL or kind == ConstKind.CONSTANT_RTQnameLA):
                self.multinames.append({"kind": kind})
                    
            elif (kind == ConstKind.CONSTANT_Multiname or kind == ConstKind.CONSTANT_MultinameA):
                name = self.get_string(multiname["name"])
                ns_set = self.namespace_sets[multiname["value"]]
                self.multinames.append({"kind": kind, "name": name, "ns_set": ns_set})
    
            elif (kind == ConstKind.CONSTANT_MultinameL or kind == ConstKind.CONSTANT_MultinameLA):
                ns_set = self.namespace_sets[multiname["value"]]
                self.multinames.append({"kind": kind, "ns_set": ns_set})
                    
            elif (kind == ConstKind.CONSTANT_TypeName):
                self.multinames.append({"kind": kind})

    def convert_multiname_typenames(self):

        for i in xrange(len(self.cpool.abc_multinames)):

            multiname = self.cpool.abc_multinames[i]

            if (multiname == {}):
                continue

            kind = multiname["kind"]
    
            if (kind == ConstKind.CONSTANT_TypeName):   
                name = self.multinames[multiname["name"]]

                params = []
                for param in multiname["value"]: 
                    params.append(self.multinames[param])

                self.multinames[i]["name"] = name
                self.multinames[i]["params"] = params

    def convert_value(self, kind, value):
    
        if (kind == ConstKind.CONSTANT_Int):
            return {"kind": kind, "value": self.get_int(value)}
    
        elif (kind == ConstKind.CONSTANT_UInt):
            return {"kind": kind, "value": self.get_uint(value)}
    
        elif (kind == ConstKind.CONSTANT_Double):
            return {"kind": kind, "value": self.get_double(value)}
    
        elif (kind == ConstKind.CONSTANT_Utf8):
            return {"kind": kind, "value": self.get_string(value)}
    
        elif (kind == ConstKind.CONSTANT_Namespace or 
              kind == ConstKind.CONSTANT_PackageNamespace or 
              kind == ConstKind.CONSTANT_PackageInternalNs or 
              kind == ConstKind.CONSTANT_ProtectedNamespace or 
              kind == ConstKind.CONSTANT_ExplicitNamespace or 
              kind == ConstKind.CONSTANT_StaticProtectedNs or 
              kind == ConstKind.CONSTANT_PrivateNs):
            return {"kind": kind, "value": self.namespaces[value]}
    
        elif (kind == ConstKind.CONSTANT_True or 
              kind == ConstKind.CONSTANT_False or 
              kind == ConstKind.CONSTANT_Null or 
              kind == ConstKind.CONSTANT_Void):
            return {"kind": kind}
                
        else:
            raise Exception("convert_value: unknown kind")

    def convert_methods(self):
    
        for method in self.cpool.abc_methods:
    
            params = []
            for param in method["paramtypes"]:
                params.append(self.multinames[param])
    
            return_type = self.multinames[method["returntype"]]
            name = self.get_string(method["name"])
            flags = method["flags"]
    
            options = []
            for option in method["options"]:
                options.append(self.convert_value(option["kind"], option["value"]))
    
            param_names = []
            for param_name in method["paramnames"]:
                param_names.append(self.get_string(param_name))
    
            pos = method["pos"]
            index = method["id"]

            self.methods.append({"paramtypes": params, "returntype": return_type, "name": name, 
                                 "flags": flags, "options": options, "paramnames": param_names, 
                                 "pos": pos, "id": index, "refid": "", "body": None})

    def convert_metadata(self):
    
        for metadata in self.cpool.abc_metadata:

            name = self.get_string(metadata["name"])

            items = []
            for item in metadata["items"]:
                key = self.get_string(item["key"])
                value = self.get_string(item["value"])
                items.append({"key": key, "value": value})

            self.metadata.append({"name": name, "items": items})

    def convert_traits(self, traits):
        
        new_traits = []
    
        for trait in traits:
    
            name = self.multinames[trait["name"]]
            kind = trait["tkind"]
            attr = trait["attr"]

            new_trait = {"name": name, "tkind": kind, "attr": attr}
    
            if (kind == TraitKind.TRAIT_Slot or kind == TraitKind.TRAIT_Const):
                new_trait["slotid"] = trait["id"]
                new_trait["type"] = self.multinames[trait["index"]]
                new_trait["value"] = self.convert_value(trait["value_kind"], trait["value_id"])
                    
            elif (kind == TraitKind.TRAIT_Class):
                new_trait["slotid"] = trait["id"]
                new_trait["class"] = self.classes[trait["index"]]
                    
            elif (kind == TraitKind.TRAIT_Function):
                new_trait["slotid"] = trait["id"]
                new_trait["function"] = self.methods[trait["index"]]
                    
            elif (kind == TraitKind.TRAIT_Method or 
                  kind == TraitKind.TRAIT_Getter or 
                  kind == TraitKind.TRAIT_Setter):
                new_trait["dispid"] = trait["id"]
                new_trait["method"] = self.methods[trait["index"]]
    
            else:
                raise Exception("convert_traits: unknown kind")
            
            metadata = []
            for entry in trait["metadata"]:
                metadata.append(self.metadata[entry])
        
            new_trait["metadata"] = metadata
    
            new_traits.append(new_trait)
    
        return new_traits
    
    def convert_instances(self):
    
        for instance in self.cpool.abc_instances:
    
            name = instance["name"]
            super_name = self.multinames[instance["supername"]]
            flags = instance["flags"]
            protected_ns = self.namespaces[instance["protectedns"]]
            
            interfaces = []
            for interface in instance["interfaces"]:
                interfaces.append(self.multinames[interface])
    
            init = self.methods[instance["iinit"]]
            traits = self.convert_traits(instance["itraits"])

            self.instances.append({"name": name, "supername": super_name, "flags": flags, 
                                   "protectedns": protected_ns, "interfaces": interfaces, 
                                   "iinit": init, "traits": traits})

    def convert_classes(self):
    
        for i in xrange(len(self.cpool.abc_instances)):
    
            abc_class = self.cpool.abc_instances[i]

            init = self.methods[abc_class["cinit"]]
            traits = self.convert_traits(abc_class["ctraits"])
            instance = self.instances[i]
    
            self.classes.append({"cinit": init, "traits": traits, "instance": instance})

    def convert_scripts(self):
    
        for script in self.cpool.abc_scripts:

            init = self.methods[script["sinit"]]
            traits = self.convert_traits(script["traits"])
    
            self.scripts.append({"sinit": init, "traits": traits})
    
    def convert_method_bodies(self):
            
        for body in self.cpool.abc_bodies:
    
            code_pos = body["pos"]
            code_length = body["length"]
    
            method = self.methods[body["method"]]
            max_stack = body["maxstack"]
            local_count = body["locals"]
            init_scope_depth = body["init_depth"]
            max_scope_depth = body["max_depth"]
    
            exceptions = []
            for exception in body["exceptions"]:

                exception_from = exception["from"]
                exception_to = exception["to"]
                exception_target = exception["target"]
                exception_type = self.multinames[exception["type"]]
                exception_name = self.multinames[exception["name"]]
            
                exceptions.append({"from": exception_from, "to": exception_to, "target": exception_target, 
                                   "type": exception_type, "name": exception_name})
    
            traits = self.convert_traits(body["traits"])

            new_body = {"pos": code_pos, "length": code_length, "method": method, 
                        "maxstack": max_stack, "locals": local_count, 
                        "init_depth": init_scope_depth, "max_depth": max_scope_depth, 
                        "exceptions": exceptions, "traits": traits}

            self.methods[body["method"]]["body"] = new_body

    def convert(self):
    
        self.convert_namespaces()
        self.convert_namespace_sets()
        self.convert_multinames()
        self.convert_multiname_typenames()
        self.convert_methods()
        self.convert_metadata()
        self.convert_instances()
        self.convert_classes()
        self.convert_scripts()
        self.convert_method_bodies()

class MultinameStrings:

    def __init__(self):

        self.names = {}
        self.namespaces = {}
        self.namespace_sets = {}

    def get_name_offset(self, name):
        return self.names[name]

    def get_namespace_offset(self, ns):
        return self.namespaces[ns]

    def get_namespace_set_offset(self, ns_set):
        return self.namespace_sets[ns_set]

    def find_last_segment(self):

        ea = idc.get_first_seg()
    
        while(idc.get_next_seg(ea) != ida_idaapi.BADADDR):
            ea = idc.get_next_seg(ea)

        return ea  

    def find_last_address(self):
    
        ea = self.find_last_segment()
    
        # check if there are no segments
        if (ea == ida_idaapi.BADADDR):
            ea = 0
    
        # there might be data not mapped to segments
        while(idc.next_addr(ea) != ida_idaapi.BADADDR):
            ea = idc.next_addr(ea)
    
        return ea

    def get_multiname_strings(self, abc, mn):

        kind = mn["kind"]

        if (kind == ConstKind.CONSTANT_Qname or kind == ConstKind.CONSTANT_QnameA):

            name = mn["name"]
            ns = abc.get_namespace(mn["ns"])

            if (ns not in self.namespaces):
                self.namespaces[ns] = 0

            if (name not in self.names):
                self.names[name] = 0                
        
        elif (kind == ConstKind.CONSTANT_RTQname or kind == ConstKind.CONSTANT_RTQnameA):

            name = mn["name"]

            if (name not in self.names):
                self.names[name] = 0   
        
        elif (kind == ConstKind.CONSTANT_RTQnameL or kind == ConstKind.CONSTANT_RTQnameLA):
            return
        
        elif (kind == ConstKind.CONSTANT_Multiname or kind == ConstKind.CONSTANT_MultinameA):

            name = mn["name"]
            ns_set = abc.get_namespace_set(mn["ns_set"])

            if (name not in self.names):
                self.names[name] = 0   

            if (ns_set not in self.namespace_sets):
                self.namespace_sets[ns_set] = 0   
        
        elif (kind == ConstKind.CONSTANT_MultinameL or kind == ConstKind.CONSTANT_MultinameLA):

            ns_set = abc.get_namespace_set(mn["ns_set"])
        
            if (ns_set not in self.namespace_sets):
                self.namespace_sets[ns_set] = 0   

        elif (kind == ConstKind.CONSTANT_TypeName):

            name = mn["name"]
            params = mn["params"]

            self.get_multiname_strings(abc, name)

            length = len(params)
            for i in xrange(length):
                self.get_multiname_strings(abc, params[i])

    def get_strings(self, abc):

        for mn in abc.multinames:

            if (mn == {}):
                continue

            self.get_multiname_strings(abc, mn)

    def create_strings_segment(self):

        buf = ""

        addr = self.find_last_address() + 1

        for key in self.namespace_sets:
            self.namespace_sets[key] = addr + len(buf)
            buf += key.replace('"', "")[1:-1] + "\x00"

        for key in self.namespaces:

            ns_set = "[%s]" % key

            if (ns_set in self.namespace_sets):
                self.namespaces[key] = self.namespace_sets[ns_set]
                continue

            self.namespaces[key] = addr + len(buf)
            buf += key.replace('"', "") + "\x00"

        for key in self.names:
            self.names[key] = addr + len(buf)
            buf += key.replace('"', "") + "\x00"

        add_segm(0, addr, addr + len(buf), "STRINGS", None)

        patch_bytes(addr, buf)

        idc.del_items(addr, idc.DELIT_SIMPLE, len(buf))

        for key in self.namespaces:

            name = key[:-1].split("(")[1][1:-1]

            if (name == ""):
                name = "_"

            idc.set_name(self.namespaces[key], name, SN_NOCHECK | SN_NOWARN | SN_FORCE)

        for key in self.names:

            idc.set_name(self.names[key], key, SN_NOCHECK | SN_NOWARN | SN_FORCE)

class Dumper:

    @staticmethod
    def make_line(ctx, s):
        ctx.out_line(s)
        ctx.flush_outbuf(0)

    @staticmethod
    def dump_string(ctx, abc, index):
        ctx.out_line('"' + abc.get_string(index) + '"', COLOR_STRING)

    @staticmethod
    def dump_namespace(ctx, ns):

        ctx.out_line(ConstKind.Names[ns["kind"]] + "(", COLOR_KEYWORD)
        ctx.out_line('"' + ns["name"] + '"', COLOR_STRING)
        ctx.out_line(")", COLOR_KEYWORD)

    @staticmethod
    def dump_multiname(ctx, op, abc, strings, mn):

        kind = mn["kind"]
        
        ctx.out_line(ConstKind.Names[kind] + "(", COLOR_KEYWORD)
        
        if (kind == ConstKind.CONSTANT_Qname or kind == ConstKind.CONSTANT_QnameA):

            name = mn["name"]
            namespace = abc.get_namespace(mn["ns"])

            ctx.out_name_expr(op, strings.get_namespace_offset(namespace), ida_idaapi.BADADDR)
            ctx.out_line(", ", COLOR_KEYWORD)
            ctx.out_name_expr(op, strings.get_name_offset(name), ida_idaapi.BADADDR)

            if (get_first_dref_from(ctx.insn.ea) == ida_idaapi.BADADDR):
                add_dref(ctx.insn.ea, strings.get_namespace_offset(namespace), dr_I)
                add_dref(ctx.insn.ea, strings.get_name_offset(name), dr_I)

        elif (kind == ConstKind.CONSTANT_RTQname or kind == ConstKind.CONSTANT_RTQnameA):

            name = mn["name"]

            ctx.out_name_expr(op, strings.get_name_offset(name), ida_idaapi.BADADDR)

            if (get_first_dref_from(ctx.insn.ea) == ida_idaapi.BADADDR):
                add_dref(ctx.insn.ea, strings.get_name_offset(name), dr_I)

        elif (kind == ConstKind.CONSTANT_RTQnameL or kind == ConstKind.CONSTANT_RTQnameLA):
            return
        
        elif (kind == ConstKind.CONSTANT_Multiname or kind == ConstKind.CONSTANT_MultinameA):

            name = mn["name"]
            namespace_set = abc.get_namespace_set(mn["ns_set"])

            ctx.out_name_expr(op, strings.get_name_offset(name), ida_idaapi.BADADDR)
            ctx.out_line(", [", COLOR_KEYWORD)
            ctx.out_name_expr(op, strings.get_namespace_set_offset(namespace_set), ida_idaapi.BADADDR)
            ctx.out_line("]", COLOR_KEYWORD)

            if (get_first_dref_from(ctx.insn.ea) == ida_idaapi.BADADDR):
                add_dref(ctx.insn.ea, strings.get_name_offset(name), dr_I)
                add_dref(ctx.insn.ea, strings.get_namespace_set_offset(namespace_set), dr_I)
        
        elif (kind == ConstKind.CONSTANT_MultinameL or kind == ConstKind.CONSTANT_MultinameLA):

            namespace_set = abc.get_namespace_set(mn["ns_set"])

            ctx.out_line("[", COLOR_KEYWORD)
            ctx.out_name_expr(op, strings.get_namespace_set_offset(namespace_set), ida_idaapi.BADADDR)
            ctx.out_line("]", COLOR_KEYWORD)

            if (get_first_dref_from(ctx.insn.ea) == ida_idaapi.BADADDR):
                add_dref(ctx.insn.ea, strings.get_namespace_set_offset(namespace_set), dr_I)

        elif (kind == ConstKind.CONSTANT_TypeName):

            name = mn["name"]
            params = mn["params"]

            Dumper.dump_multiname(ctx, op, abc, strings, name)
            ctx.out_line("<", COLOR_KEYWORD)
            length = len(params)
            for i in xrange(length):
                Dumper.dump_multiname(ctx, op, abc, strings, params[i])
                if (i < length-1):
                    ctx.out_line(", ", COLOR_KEYWORD)
            ctx.out_line(">", COLOR_KEYWORD)
        
        ctx.out_line(")", COLOR_KEYWORD)

    @staticmethod
    def dump_class(ctx, abc, index):
        ctx.out_line('"' + abc.multinames[abc.classes[index]["instance"]["name"]]["name"] + '"', COLOR_STRING)

    @staticmethod
    def dump_flags(ctx, flags, names):
        i = 0
        while (flags != 0):

            if (flags & 1):
                Dumper.make_line(ctx, "flag " + names[i])

            i += 1
            flags >>= 1

    @staticmethod
    def dump_traits(ctx, abc, traits):
    
        for trait in traits:
        
            kind = trait["tkind"]
            name = abc.get_multiname(trait["name"])

            s = "trait %s %s" % (TraitKind.Names[kind], name)

            if (kind == TraitKind.TRAIT_Slot or kind == TraitKind.TRAIT_Const):
               
                s += " slotid %d" % trait["slotid"]
                
                if (trait["type"] != {}):
                
                    s += " type "
                    s += abc.get_multiname(trait["type"])
                
                if (trait["value"]["kind"] != 0):
                
                    s += " value "
                    s += abc.get_value(trait["value"])

            elif (kind == TraitKind.TRAIT_Class):

                s += " slotid %d" % trait["slotid"]
                
            elif (kind == TraitKind.TRAIT_Function):
      
                s += " slotid %d" % trait["slotid"]

            elif (kind == TraitKind.TRAIT_Method or 
                  kind == TraitKind.TRAIT_Getter or 
                  kind == TraitKind.TRAIT_Setter):

                s += " dispid %d" % trait["dispid"]

            Dumper.make_line(ctx, s)

    @staticmethod
    def dump_method(ctx, abc, method):

        if (method is not None):

            if (method["refid"] != ""):
                Dumper.make_line(ctx, 'refid "%s"' % method["refid"])

            for param in method["paramtypes"]:
                if param != {}:
                    Dumper.make_line(ctx, "param %s" % abc.get_multiname(param))

            if method["returntype"] != {}:
                Dumper.make_line(ctx, "returns %s" % abc.get_multiname(method["returntype"]))

            Dumper.dump_flags(ctx, method["flags"], MethodFlags.Names)

            for option in method["options"]:
                if option != {}:
                    Dumper.make_line(ctx, "optional %s" % abc.get_value(option))

            for param_name in method["paramnames"]:
                Dumper.make_line(ctx, "paramname %s" % param_name)
        
            Dumper.make_line(ctx, "maxstack %d" % method["body"]["maxstack"])
            Dumper.make_line(ctx, "locals %d" % method["body"]["locals"])
            Dumper.make_line(ctx, "init_depth %d" % method["body"]["init_depth"])
            Dumper.make_line(ctx, "max_depth %d" % method["body"]["max_depth"])

            Dumper.dump_traits(ctx, abc, method["body"]["traits"])

    @staticmethod
    def dump_exception(ctx, abc, exception):

        if (exception is not None):

            Dumper.make_line(ctx, "try")
            Dumper.make_line(ctx, "from 0x%X" % exception["from"])
            Dumper.make_line(ctx, "to 0x%X" % exception["to"])

            if (exception["type"] != {}):
                Dumper.make_line(ctx, "type %s" % abc.get_multiname(exception["type"]))

            if (exception["name"] != {}):
                Dumper.make_line(ctx, "name %s" % abc.get_multiname(exception["name"]))

    @staticmethod
    def dump_name_expr(ctx, op, addr):

        r = ctx.out_name_expr(op, addr, ida_idaapi.BADADDR)
        if not r:
            ctx.out_tagon(COLOR_ERROR)
            ctx.out_btoa(addr, 16)
            ctx.out_tagoff(COLOR_ERROR)
            remember_problem(PR_NONAME, ctx.insn.ea)  

class as3_processor_t(processor_t):

    PLFM_SWF_AS3 = 0x8A53

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = PLFM_SWF_AS3

    # Processor features
    flag = PR_USE32 | PR_DEFSEG32 | PR_RNAMESOK | PRN_HEX | PR_NO_SEGMOVE

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ["SWF-AS3"]

    # long processor names
    # No restriction on name lengthes.
    plnames = ["SWF ActionScript3"]

    # size of a segment register in bytes
    segreg_size = 0

    # icode of the first instruction
    instruc_start = 0

    # Size of long double (tbyte) for this processor
    # (meaningful only if ash.a_tbyte != NULL)
    tbyte_size = 0

    # only one assembler is supported
    assembler = {
        # flag
        'flag' : ASH_HEXF3 | AS_UNEQU | AS_COLON | ASB_BINF4,

        # user defined flags (local only for IDP)
        # you may define and use your own bits
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "SWF ActionScript3",

        # org directive
        'origin': "org",

        # end directive
        'end': "end",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': "db",

        # byte directive
        'a_byte': "db",

        # word directive
        'a_word': "dw",

        # remove if not allowed
        'a_dword': "dd",

        # remove if not allowed
        'a_qword': "dq",

        # remove if not allowed
        'a_oword': "xmmword",

        # float;  4bytes; remove if not allowed
        'a_float': "dd",

        # double; 8bytes; NULL if not allowed
        'a_double': "dq",

        # long double;    NULL if not allowed
        'a_tbyte': "dt",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "public",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "weak",

        # "extrn"  name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': "align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string)
        'a_sizeof_fmt': "size %s",
    } # Assembler

    tag = None
    abc = None
    multiname_strings = None

    switches = []
    exceptions = []

    FLo_SIGNED = 0x0001 # This is a signed operand

    # ----------------------------------------------------------------------

    def analyze_instance_references(self, instance, line):
    
        if (instance["iinit"]["refid"] == ""):
            instance["iinit"]["refid"] = "%s/instance/init" % line

        for trait in instance["traits"]:
            name = instance["protectedns"]["name"]
            self.analyze_trait_references(trait, "%s/instance" % line, name)
    
    def analyze_class_references(self, abc_class, line):
    
        if (abc_class["cinit"]["refid"] == ""):
            abc_class["cinit"]["refid"] = "%s/class/init" % line
    
        for trait in abc_class["traits"]:
            name = abc_class["instance"]["protectedns"]["name"]
            self.analyze_trait_references(trait, "%s/class" % line, name)
    
        self.analyze_instance_references(abc_class["instance"], line)
    
    def analyze_trait_references(self, trait, line, namespace):
        
        kind = trait["tkind"]

        if (kind == TraitKind.TRAIT_Class):
    
            self.analyze_class_references(trait["class"], line)
                
        elif (kind == TraitKind.TRAIT_Function):
    
            if (trait["function"]["refid"] == ""):

                name = trait["name"]["name"]
                namespace_kind = trait["name"]["ns"]["kind"]
                namespace_name = trait["name"]["ns"]["name"]

                if (namespace_kind == ConstKind.CONSTANT_Namespace):
                    trait["function"]["refid"] = "%s/%s:%s" % (line, namespace_name, name)
                elif (namespace_kind == ConstKind.CONSTANT_PrivateNamespace):
                    trait["function"]["refid"] = "%s/%s/%s" % (line, namespace, name)
                else:
                    trait["function"]["refid"] = "%s/%s" % (line, name)
                
        elif (kind == TraitKind.TRAIT_Method or 
              kind == TraitKind.TRAIT_Getter or 
              kind == TraitKind.TRAIT_Setter):
    
            if (trait["method"]["refid"] == ""):

                name = trait["name"]["name"]
                namespace_kind = trait["name"]["ns"]["kind"]
                namespace_name = trait["name"]["ns"]["name"]

                if (trait["name"]["kind"] == ConstKind.CONSTANT_Qname and 
                    (namespace_kind == ConstKind.CONSTANT_Namespace or 
                     namespace_kind == ConstKind.CONSTANT_PrivateNs)):

                    if (namespace_kind == ConstKind.CONSTANT_Namespace):
                        trait["method"]["refid"] = "%s/%s:%s" % (line, namespace_name, name)
                    elif (namespace_kind == ConstKind.CONSTANT_PrivateNs):
                        trait["method"]["refid"] = "%s/%s/%s" % (line, namespace, name)
                else:
                    trait["method"]["refid"] = "%s/%s" % (line, name)

                if (kind == TraitKind.TRAIT_Getter):
                    trait["method"]["refid"] += "/getter"

                if (kind == TraitKind.TRAIT_Setter):
                    trait["method"]["refid"] += "/setter"

    def create_unique_references(self, abc):

        for method in self.abc.methods:

            if (method["refid"] == ""):
                continue

            group = [m for m in self.abc.methods if m["refid"] == method["refid"]]

            if (len(group) > 1):

                for i in xrange(len(group)):
                    group[i]["refid"] += "_%d" % i

    def analyze_references(self, abc):

        for script in abc.scripts:

            for trait in script["traits"]:

                if (trait["name"]["kind"] == ConstKind.CONSTANT_Qname and 
                    trait["name"]["ns"]["kind"] != ConstKind.CONSTANT_PrivateNs):
        
                    name = trait["name"]["name"]
                    namespace_name = trait["name"]["ns"]["name"]

                    if (namespace_name != ""):
                        line = "%s:%s" % (namespace_name, name)
                    else:
                        line = name
        
                    script["sinit"]["refid"] = "%s/init" % line
                
                    for trait in script["traits"]:
                             
                        self.analyze_trait_references(trait, line, None)
                        
                elif (trait["name"]["kind"] == ConstKind.CONSTANT_Multiname):

                    name = trait["name"]["name"]

                    if (len(script["traits"]) == 1):
                        script["sinit"]["refid"] = "%s/init" % name

                    self.analyze_trait_references(trait, name, None)

        self.create_unique_references(abc)

    def fix_bad_name(self, refid):

        name = ""

        for char in refid:

            if (char in string.digits or 
                char in string.lowercase or 
                char in string.uppercase or 
                ord(char) in [0x2E, 0x2F, 0x3A, 0x5F]):
                name += char
            else:
                name += "\\x%02X" % ord(char)

        return name

    def analyze_code(self, is_new_file):

        for i in xrange(len(self.abc.methods)):

            if self.abc.methods[i]["body"] is not None:

                code_pos = self.abc.methods[i]["body"]["pos"]
                code_length = self.abc.methods[i]["body"]["length"]
                reference = self.abc.methods[i]["refid"]

                if (is_new_file):
                    print("%X - %X - %s" % (code_pos, code_length, reference))
                    auto_make_proc(code_pos)

                    if (reference != ""):
                        idc.set_name(code_pos, self.fix_bad_name(reference), SN_NOCHECK)
    
                for exception in self.abc.methods[i]["body"]["exceptions"]:
    
                    exception_from = code_pos + exception["from"]
                    exception_to = code_pos + exception["to"]
                    exception_target = code_pos + exception["target"]

                    if (is_new_file):
                        auto_make_code(exception_target)
                        set_dummy_name(exception_from, exception_target)
    
                    self.exceptions.append({"from": exception_from, "to": exception_to, 
                                            "target": exception_target, "type": exception["type"], 
                                            "name": exception["name"]})

    def load_file(self, is_new_file):

        self.tag = Tag()

        if not (self.tag.find()):
            print('No "DoABC" tag!')
            return

        self.tag.parse()

        if (is_new_file):
            idc.del_items(self.tag.start, idc.DELIT_SIMPLE, self.tag.data_length)

        print("Parse ABC...")

        cpool = ConstantPool()
        cpool.parse()

        print("Convert ABC...")

        self.abc = ABC(cpool)
        self.abc.convert()

        self.multiname_strings = MultinameStrings()
        self.multiname_strings.get_strings(self.abc)

        if (is_new_file):

            print("Create strings segment...")

            self.multiname_strings.create_strings_segment()

        print("Analyze references...")

        self.analyze_references(self.abc)

        print("Analyze code...")

        self.analyze_code(is_new_file)

    # ----------------------------------------------------------------------
    def notify_gen_map_file(self, qfile):
        """
        Generate map file. If this function is absent then the kernel will create the map file.
        This function returns number of lines in output file.
        0 - empty file, -1 - write error
        """
    
        dump = []
        
        for method in self.abc.methods:

            if (method["body"] is None):
                continue

            methodInfo1 = idc.get_qword(method["pos"])
            methodInfo2 = idc.get_qword(method["pos"]+8)
            index = method["id"]
            
            ea = method["body"]["pos"]
            length = method["body"]["length"]
        
            name = get_name(ea)
        
            start = ea
            end = ea + length
        
            instructions = {}
        
            while (ea < end):
            
                line = generate_disasm_line(ea, GENDSM_REMOVE_TAGS)
                instructions[ea-start] = line
        
                ea += get_item_size(ea)
        
            dump.append({"id": index, "info": methodInfo1 + methodInfo2, "name": name, "instructions": instructions})
        
        data = cPickle.dumps(dump)
        
        qfile.write(data)

        return len(data.splitlines())

    # ----------------------------------------------------------------------
    def notify_oldfile(self, filename):
        self.load_file(False)

    # ----------------------------------------------------------------------
    def notify_newfile(self, filename):   
        self.load_file(True)

    # ----------------------------------------------------------------------
    def notify_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: None or the comment string
        """
        if "cmt" in self.instruc[insn.itype]:
          return self.instruc[insn.itype]["cmt"]

    # ----------------------------------------------------------------------
    def notify_can_have_type(self, op):
        """
        Can the operand have a type as offset, segment, decimal, etc.
        (for example, a register AX can't have a type, meaning that the user can't
        change its representation. see bytes.hpp for information about types and flags)
        Returns: bool
        """
        return op.type == o_imm

    # ----------------------------------------------------------------------
    def notify_out_header(self, ctx):
        """function to produce start of disassembled text"""

        ctx.gen_block_cmt("+-------------------------------------------------------------------------+\n" \
                          "|                Adobe Flash ActionScript3 processor module               |\n" \
                          "|                           Author: Boris Larin                           |\n" \
                          "|                       <Boris.Larin@kaspersky.com>                       |\n" \
                          "+-------------------------------------------------------------------------+", COLOR_DEFAULT)
        ctx.flush_outbuf(0)

    # ----------------------------------------------------------------------
    def notify_may_be_func(self, insn, state):
        """
        can a function start here?
        the instruction is in 'insn'
          arg: state -- autoanalysis phase
            state == 0: creating functions
                  == 1: creating chunks
          returns: probability 0..100
        """

        return False
    
    # ----------------------------------------------------------------------
    def handle_operand(self, insn, op, isRead):

        optype = op.type

        if optype == o_near:
            itype = insn.itype
            if itype == self.itype_newfunction or itype == self.itype_callstatic:
                fl = fl_CN
            else:
                fl = fl_JN
            insn.add_cref(op.addr, op.offb, fl)

        if optype == o_idpspec4:

            for target in self.switches[op.value]:
                insn.add_cref(target, op.offb, fl_JN)

    # ----------------------------------------------------------------------
    def notify_emu(self, insn):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'insn' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        aux = self.get_auxpref(insn)
        feature = insn.get_canon_feature()

        if feature & CF_USE1:
            self.handle_operand(insn, insn.Op1, 1)

        if feature & CF_USE2:
            self.handle_operand(insn, insn.Op2, 1)

        if feature & CF_USE3:
            self.handle_operand(insn, insn.Op3, 1)

        if feature & CF_USE4:
            self.handle_operand(insn, insn.Op4, 1)

        if feature & CF_JUMP:
            remember_problem(PR_JUMP, insn.ea)

        uncond_jmp = insn.itype in [self.itype_jump, self.itype_lookupswitch]

        if (feature & CF_STOP == 0) and not uncond_jmp:
            add_cref(insn.ea, insn.ea + insn.size, fl_F)

        return True   

    # ----------------------------------------------------------------------
    def notify_out_operand(self, ctx, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """

        optype = op.type
        fl     = op.specval
        value  = op.value
        signed = OOF_SIGNED if fl & self.FLo_SIGNED != 0 else 0
        def_arg = is_defarg(get_flags(ctx.insn.ea), op.n)

        if optype == o_imm:
            ctx.out_value(op, OOFW_IMM | signed)

        elif optype == o_near:
            Dumper.dump_name_expr(ctx, op, op.addr)

        elif optype == o_idpspec0:
            Dumper.dump_string(ctx, self.abc, value)

        elif optype == o_idpspec1:
            Dumper.dump_namespace(ctx, self.abc.namespaces[value])

        elif optype == o_idpspec2:
            Dumper.dump_multiname(ctx, op, self.abc, self.multiname_strings, self.abc.multinames[value])

        elif optype == o_idpspec3:
            Dumper.dump_class(ctx, self.abc, value)

        elif optype == o_idpspec4:

            for target in self.switches[value]:

                ctx.out_line(", ", COLOR_KEYWORD)
                Dumper.dump_name_expr(ctx, op, target)

        else:
            return False

        return True

    # ----------------------------------------------------------------------
    # Generate the instruction mnemonics
    def out_mnem(self, ctx):
        # Init output buffer

        postfix = ""

        ctx.out_mnem(16, postfix)

    # ----------------------------------------------------------------------
    # Generate text representation of an instruction in 'ctx.insn' structure.
    # This function shouldn't change the database, flags or anything else.
    # All these actions should be performed only by u_emu() function.
    def notify_out_insn(self, ctx):

        ctx.out_mnemonic()

        ctx.out_one_operand(0)

        for i in xrange(1, 3):

            op = ctx.insn[i]

            if op.type == o_void:
                break

            ctx.out_symbol(",")
            ctx.out_char(" ")
            ctx.out_one_operand(i)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()
          
    # ----------------------------------------------------------------------
    def notify_out_label(self, ctx, label):
        """
        The kernel is going to generate an instruction label line
        or a function header.
        args:
          ctx - output context
          label - label to output
        If returns value <0, then the kernel should not generate the label
        """

        method = next((x for x in self.abc.methods if x["body"] is not None and x["body"]["pos"] == ctx.insn.ea), None)

        Dumper.dump_method(ctx, self.abc, method)

        exception = next((x for x in self.exceptions if x["target"] == ctx.insn.ea), None)

        Dumper.dump_exception(ctx, self.abc, exception)

        return True

    # ----------------------------------------------------------------------
    def decode_instr(self, insn, opbyte):

        if (self.itable[opbyte].argtypes is None):
            return True

        if (self.itable[opbyte].name == "debug"):

            ubytev = Reader.read_byte(insn)
            insn.Op1.type  = o_imm
            insn.Op1.dtype = dt_byte
            insn.Op1.value = ubytev

            index = Reader.read_encoded_u32(insn)
            length = len(self.abc.cpool.abc_strings)

            if (index >= length):
                print("Bad instr: %X - 0x%02X, %s, %X, %X" % (insn.ea, opbyte, self.itable[opbyte].name, index, length))
                return False

            insn.Op2.type  = o_idpspec0
            insn.Op2.dtype = dt_string
            insn.Op2.value = index

            ubytev = Reader.read_byte(insn)
            insn.Op3.type  = o_imm
            insn.Op3.dtype = dt_byte
            insn.Op3.value = ubytev

            uintv = Reader.read_encoded_u32(insn)
            insn.Op4.type  = o_imm
            insn.Op4.dtype = dt_dword
            insn.Op4.value = uintv      

            return True

        for i in xrange(len(self.itable[opbyte].argtypes)):

            op_type = self.itable[opbyte].argtypes[i]

            if (op_type == OperandType.CONSTANT_Unknown):
                print("Unknown operand: %s" % self.itable[opbyte].name)
                return False

            elif (op_type == OperandType.CONSTANT_ByteImm):

                bytev = Reader.read_byte(insn)
                insn.Op1.type  = o_imm
                insn.Op1.dtype = dt_byte
                insn.Op1.value = bytev

            elif (op_type == OperandType.CONSTANT_UByteImm):

                ubytev = Reader.read_byte(insn)
                insn.Op1.type  = o_imm
                insn.Op1.dtype = dt_byte
                insn.Op1.value = ubytev

            elif (op_type == OperandType.CONSTANT_IntImm):

                intv = Reader.read_encoded_u32(insn)
                insn.Op1.type  = o_imm
                insn.Op1.dtype = dt_dword
                insn.Op1.value = intv
                insn.Op1.specval = self.FLo_SIGNED

            elif (op_type == OperandType.CONSTANT_UIntImm):

                uintv = Reader.read_encoded_u32(insn)

                if (i == 0):
                    insn.Op1.type  = o_imm
                    insn.Op1.dtype = dt_dword
                    insn.Op1.value = uintv
                else:
                    insn.Op2.type  = o_imm
                    insn.Op2.dtype = dt_dword
                    insn.Op2.value = uintv                    
                
            elif (op_type == OperandType.CONSTANT_Int or 
                  op_type == OperandType.CONSTANT_UInt or 
                  op_type == OperandType.CONSTANT_Double or 
                  op_type == OperandType.CONSTANT_String or 
                  op_type == OperandType.CONSTANT_Namespace or 
                  op_type == OperandType.CONSTANT_Multiname or 
                  op_type == OperandType.CONSTANT_Class or 
                  op_type == OperandType.CONSTANT_Method):
            
                index = Reader.read_encoded_u32(insn)

                if (op_type == OperandType.CONSTANT_Int):       
                    length = len(self.abc.cpool.abc_ints)
                elif (op_type == OperandType.CONSTANT_UInt):      
                    length = len(self.abc.cpool.abc_uints)
                elif (op_type == OperandType.CONSTANT_Double):    
                    length = len(self.abc.cpool.abc_doubles)
                elif (op_type == OperandType.CONSTANT_String):    
                    length = len(self.abc.cpool.abc_strings)
                elif (op_type == OperandType.CONSTANT_Namespace): 
                    length = len(self.abc.cpool.abc_namespaces)
                elif (op_type == OperandType.CONSTANT_Multiname): 
                    length = len(self.abc.cpool.abc_multinames)
                elif (op_type == OperandType.CONSTANT_Class):     
                    length = len(self.abc.cpool.abc_instances)
                elif (op_type == OperandType.CONSTANT_Method):    
                    length = len(self.abc.cpool.abc_methods)

                if (index >= length):
                    print("Bad instr: %X - 0x%02X, %s, %X, %X" % (insn.ea, opbyte, self.itable[opbyte].name, index, length))
                    return False

                if (op_type == OperandType.CONSTANT_Int):

                    insn.Op1.type  = o_imm
                    insn.Op1.dtype = dt_dword
                    insn.Op1.value = self.abc.get_int(index)
                    insn.Op1.specval = self.FLo_SIGNED       

                elif (op_type == OperandType.CONSTANT_UInt):
                     
                    insn.Op1.type  = o_imm
                    insn.Op1.dtype = dt_dword
                    insn.Op1.value = self.abc.get_uint(index)   

                elif (op_type == OperandType.CONSTANT_Double):
                      
                    insn.Op1.type  = o_imm
                    insn.Op1.dtype = dt_qword
                    insn.Op1.value = self.abc.get_double(index)  

                elif (op_type == OperandType.CONSTANT_String):
                        
                    insn.Op1.type  = o_idpspec0
                    insn.Op1.dtype = dt_string
                    insn.Op1.value = index

                elif (op_type == OperandType.CONSTANT_Namespace):
                            
                    insn.Op1.type  = o_idpspec1
                    insn.Op1.dtype = dt_string
                    insn.Op1.value = index

                elif (op_type == OperandType.CONSTANT_Multiname):
                     
                    insn.Op1.type  = o_idpspec2
                    insn.Op1.dtype = dt_string
                    insn.Op1.value = index

                elif (op_type == OperandType.CONSTANT_Class):

                    insn.Op1.type  = o_idpspec3
                    insn.Op1.dtype = dt_string
                    insn.Op1.value = index

                elif (op_type == OperandType.CONSTANT_Method):

                    insn.Op1.type = o_near
                    insn.Op1.dtype = dt_dword

                    if (index >= len(self.abc.methods) or self.abc.methods[index]["body"] is None):
                        print("Bad instr: %X - 0x%02X, %s, %X, %X" % (insn.ea, opbyte, self.itable[opbyte].name, index, length))
                        return False

                    insn.Op1.addr = self.abc.methods[index]["body"]["pos"]

            elif (op_type == OperandType.CONSTANT_Label):
            
                delta = Reader.read_s24(insn)
                target = insn.ea + insn.size + delta

                insn.Op1.type = o_near
                insn.Op1.dtype = dt_dword
                insn.Op1.addr = target

            elif (op_type == OperandType.CONSTANT_DefaultLabel):
            
                delta = Reader.read_s24(insn)
                target = insn.ea + delta

                insn.Op1.type = o_near
                insn.Op1.dtype = dt_dword
                insn.Op1.addr = target

            elif (op_type == OperandType.CONSTANT_LabelsList):

                insn.Op2.type = o_idpspec4
                insn.Op2.dtype = dt_dword
                insn.Op2.value = len(self.switches)

                length = Reader.read_encoded_u32(insn)+1

                if (length > 0xFFFF):
                    print("Bad instr: %X - 0x%02X, %s, %X, %X" % (insn.ea, opbyte, self.itable[opbyte].name, index, length))
                    return False

                targets = []

                for label in xrange(length):
                    delta = Reader.read_s24(insn)
                    target = insn.ea + delta
                    targets.append(target)
        
                self.switches.append(targets)

        return True

    def notify_ana(self, insn):
        """
        Decodes an instruction into insn
        """

        # take opcode byte
        opcode = insn.get_next_byte()

        # opcode supported?
        try:
            ins = self.itable[opcode]
            # set default itype
            insn.itype = getattr(self, "itype_" + ins.name)
        except:
            return False
        # call the decoder
        return insn.size if self.decode_instr(insn, opcode) else 0

    # ----------------------------------------------------------------------
    def init_instructions(self):
        class idef:
            """
            Internal class that describes an instruction by:
            - instruction name
            - instruction decoding routine
            - canonical flags used by IDA
            """
            def __init__(self, name, cf, argtypes, cmt = None):
                self.name = name
                self.cf  = cf
                self.argtypes = argtypes
                self.cmt = cmt

        #
        # Instructions table
        #
        self.itable = {

            #0x00: 
            0x01: idef(name="bkpt",               cmt="Breakpoint",                                                     cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0x02: idef(name="nop",                cmt="No operation",                                                   cf = 0,                                     argtypes=None),
            0x03: idef(name="throw",              cmt="Throw exception",                                                cf = 0,                                     argtypes=None),
            0x04: idef(name="getsuper",           cmt="Get parent class property",                                      cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Multiname]),
            0x05: idef(name="setsuper",           cmt="Set parent class property",                                      cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Multiname]),
            0x06: idef(name="dxns",               cmt="Set default XML namespace",                                      cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_String]),
            0x07: idef(name="dxnslate",           cmt="Set default XML namespace at runtime",                           cf = 0,                                     argtypes=None),
            0x08: idef(name="kill",               cmt="Kill local register",                                            cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            0x09: idef(name="label",              cmt="Target of a branch",                                             cf = 0,                                     argtypes=None),
            #0x0A: 
            #0x0B: 
            0x0C: idef(name="ifnlt",              cmt="Branch if not lower than",                                       cf = CF_USE1 | CF_JUMP,                     argtypes=[OperandType.CONSTANT_Label]),
            0x0D: idef(name="ifnle",              cmt="Branch if not lower or equal",                                   cf = CF_USE1 | CF_JUMP,                     argtypes=[OperandType.CONSTANT_Label]),
            0x0E: idef(name="ifngt",              cmt="Branch if not greater than",                                     cf = CF_USE1 | CF_JUMP,                     argtypes=[OperandType.CONSTANT_Label]),
            0x0F: idef(name="ifnge",              cmt="Branch if not greater ot equal",                                 cf = CF_USE1 | CF_JUMP,                     argtypes=[OperandType.CONSTANT_Label]),
            0x10: idef(name="jump",               cmt="Jump to location",                                               cf = CF_USE1 | CF_JUMP,                     argtypes=[OperandType.CONSTANT_Label]),
            0x11: idef(name="iftrue",             cmt="Branch if true",                                                 cf = CF_USE1 | CF_JUMP,                     argtypes=[OperandType.CONSTANT_Label]),
            0x12: idef(name="iffalse",            cmt="Branch if false",                                                cf = CF_USE1 | CF_JUMP,                     argtypes=[OperandType.CONSTANT_Label]),
            0x13: idef(name="ifeq",               cmt="Branch if equal",                                                cf = CF_USE1 | CF_JUMP,                     argtypes=[OperandType.CONSTANT_Label]),
            0x14: idef(name="ifne",               cmt="Branch if not equal",                                            cf = CF_USE1 | CF_JUMP,                     argtypes=[OperandType.CONSTANT_Label]),
            0x15: idef(name="iflt",               cmt="Branch if lower than",                                           cf = CF_USE1 | CF_JUMP,                     argtypes=[OperandType.CONSTANT_Label]),
            0x16: idef(name="ifle",               cmt="Branch if lower or equal",                                       cf = CF_USE1 | CF_JUMP,                     argtypes=[OperandType.CONSTANT_Label]),
            0x17: idef(name="ifgt",               cmt="Branch if greater than",                                         cf = CF_USE1 | CF_JUMP,                     argtypes=[OperandType.CONSTANT_Label]),
            0x18: idef(name="ifge",               cmt="Branch if greater or equal",                                     cf = CF_USE1 | CF_JUMP,                     argtypes=[OperandType.CONSTANT_Label]),
            0x19: idef(name="ifstricteq",         cmt="Branch if strict equal",                                         cf = CF_USE1 | CF_JUMP,                     argtypes=[OperandType.CONSTANT_Label]),
            0x1A: idef(name="ifstrictne",         cmt="Branch if not strict equal",                                     cf = CF_USE1 | CF_JUMP,                     argtypes=[OperandType.CONSTANT_Label]),
            0x1B: idef(name="lookupswitch",       cmt="Branch based on index",                                          cf = CF_USE1 | CF_USE2 | CF_JUMP,           argtypes=[OperandType.CONSTANT_DefaultLabel, OperandType.CONSTANT_LabelsList]),
            0x1C: idef(name="pushwith",           cmt="Push with onto scope stack",                                     cf = 0,                                     argtypes=None),
            0x1D: idef(name="popscope",           cmt="Pop from scope stack and discard value",                         cf = 0,                                     argtypes=None),
            0x1E: idef(name="nextname",           cmt="Get name of next property",                                      cf = 0,                                     argtypes=None),
            0x1F: idef(name="hasnext",            cmt="Check if the object has more properties",                        cf = 0,                                     argtypes=None),
            0x20: idef(name="pushnull",           cmt="Push null value on stack",                                       cf = 0,                                     argtypes=None),
            0x21: idef(name="pushundefined",      cmt="Push undefined value on stack",                                  cf = 0,                                     argtypes=None),
            0x22: idef(name="pushuninitialized",  cmt="Push float value on stack",                                      cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0x23: idef(name="nextvalue",          cmt="Get value of next property",                                     cf = 0,                                     argtypes=None),
            0x24: idef(name="pushbyte",           cmt="Push byte value on stack",                                       cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_ByteImm]),
            0x25: idef(name="pushshort",          cmt="Push short value on stack",                                      cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_IntImm]),
            0x26: idef(name="pushtrue",           cmt="Push true on stack",                                             cf = 0,                                     argtypes=None),
            0x27: idef(name="pushfalse",          cmt="Push false on stack",                                            cf = 0,                                     argtypes=None),
            0x28: idef(name="pushnan",            cmt="Push NaN value on stack",                                        cf = 0,                                     argtypes=None),
            0x29: idef(name="pop",                cmt="Pop top value from stack",                                       cf = 0,                                     argtypes=None),
            0x2A: idef(name="dup",                cmt="Duplicate value on stack",                                       cf = 0,                                     argtypes=None),
            0x2B: idef(name="swap",               cmt="Swap two values on top of the stack",                            cf = 0,                                     argtypes=None),
            0x2C: idef(name="pushstring",         cmt="Push string value on the stack",                                 cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_String]),
            0x2D: idef(name="pushint",            cmt="Push integer value on the stack",                                cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Int]),
            0x2E: idef(name="pushuint",           cmt="Push unsigned integer value on the stack",                       cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UInt]),
            0x2F: idef(name="pushdouble",         cmt="Push double precision value on the stack",                       cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Double]),
            0x30: idef(name="pushscope",          cmt="Push object on the scope stack",                                 cf = 0,                                     argtypes=None),
            0x31: idef(name="pushnamespace",      cmt="Push namespace on the stack",                                    cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Namespace]),
            0x32: idef(name="hasnext2",           cmt="Check if the object has more properties (register based)",       cf = CF_USE1 | CF_USE2,                     argtypes=[OperandType.CONSTANT_UIntImm, OperandType.CONSTANT_UIntImm]),
            0x33: idef(name="pushdecimal",        cmt="Push decimal value on the stack",                                cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0x34: idef(name="pushdnan",           cmt="Push decimal NaN value on the stack",                            cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0x35: idef(name="li8",                cmt="Load 8bit integer value",                                        cf = 0,                                     argtypes=None),
            0x36: idef(name="li16",               cmt="Load 16bit integer value",                                       cf = 0,                                     argtypes=None),
            0x37: idef(name="li32",               cmt="Load 32bit integer value",                                       cf = 0,                                     argtypes=None),
            0x38: idef(name="lf32",               cmt="Load 32bit float value",                                         cf = 0,                                     argtypes=None),
            0x39: idef(name="lf64",               cmt="Load 64bit float value",                                         cf = 0,                                     argtypes=None),
            0x3A: idef(name="si8",                cmt="Store 8bit integer value",                                       cf = 0,                                     argtypes=None),
            0x3B: idef(name="si16",               cmt="Store 16bit integer value",                                      cf = 0,                                     argtypes=None),
            0x3C: idef(name="si32",               cmt="Store 32bit integer value",                                      cf = 0,                                     argtypes=None),
            0x3D: idef(name="sf32",               cmt="Store 32bit float value",                                        cf = 0,                                     argtypes=None),
            0x3E: idef(name="sf64",               cmt="Store 64bit float value",                                        cf = 0,                                     argtypes=None),
            #0x3F: 
            0x40: idef(name="newfunction",        cmt="Create new Function object",                                     cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Method]),
            0x41: idef(name="call",               cmt="Call function on the stack",                                     cf = CF_USE1 | CF_CALL,                     argtypes=[OperandType.CONSTANT_UIntImm]),
            0x42: idef(name="construct",          cmt="Call constructor function on the stack",                         cf = CF_USE1 | CF_CALL,                     argtypes=[OperandType.CONSTANT_UIntImm]),
            0x43: idef(name="callmethod",         cmt="Call method of object by dispatch id",                           cf = CF_USE1 | CF_USE2 | CF_CALL,           argtypes=[OperandType.CONSTANT_UIntImm, OperandType.CONSTANT_UIntImm]),
            0x44: idef(name="callstatic",         cmt="Call method by method id in ABC file",                           cf = CF_USE1 | CF_USE2 | CF_CALL,           argtypes=[OperandType.CONSTANT_Method, OperandType.CONSTANT_UIntImm]),
            0x45: idef(name="callsuper",          cmt="Call method on parent class",                                    cf = CF_USE1 | CF_USE2 | CF_CALL,           argtypes=[OperandType.CONSTANT_Multiname, OperandType.CONSTANT_UIntImm]),
            0x46: idef(name="callproperty",       cmt="Call property",                                                  cf = CF_USE1 | CF_USE2 | CF_CALL,           argtypes=[OperandType.CONSTANT_Multiname, OperandType.CONSTANT_UIntImm]),
            0x47: idef(name="returnvoid",         cmt="Return from a method",                                           cf = CF_STOP,                               argtypes=None),
            0x48: idef(name="returnvalue",        cmt="Return value from a method",                                     cf = CF_STOP,                               argtypes=None),
            0x49: idef(name="constructsuper",     cmt="Call parent constructor of an object",                           cf = CF_USE1 | CF_CALL,                     argtypes=[OperandType.CONSTANT_UIntImm]),
            0x4A: idef(name="constructprop",      cmt="Construct a property of an object",                              cf = CF_USE1 | CF_USE2,                     argtypes=[OperandType.CONSTANT_Multiname, OperandType.CONSTANT_UIntImm]),
            0x4B: idef(name="callsuperid",        cmt="Call super id",                                                  cf = CF_CALL,                               argtypes=[OperandType.CONSTANT_Unknown]),
            0x4C: idef(name="callproplex",        cmt="Call property with null as this",                                cf = CF_USE1 | CF_USE2 | CF_CALL,           argtypes=[OperandType.CONSTANT_Multiname, OperandType.CONSTANT_UIntImm]),
            0x4D: idef(name="callinterface",      cmt="Call interface",                                                 cf = CF_CALL,                               argtypes=[OperandType.CONSTANT_Unknown]),
            0x4E: idef(name="callsupervoid",      cmt="Call method on parent class, discard return value",              cf = CF_USE1 | CF_USE2 | CF_CALL,           argtypes=[OperandType.CONSTANT_Multiname, OperandType.CONSTANT_UIntImm]),
            0x4F: idef(name="callpropvoid",       cmt="Call property, discard return value",                            cf = CF_USE1 | CF_USE2 | CF_CALL,           argtypes=[OperandType.CONSTANT_Multiname, OperandType.CONSTANT_UIntImm]),
            0x50: idef(name="sxi1",               cmt="Sign extend 1bit value to 32bits",                               cf = 0,                                     argtypes=None),
            0x51: idef(name="sxi8",               cmt="Sign extend 8bit value to 32bits",                               cf = 0,                                     argtypes=None),
            0x52: idef(name="sxi16",              cmt="Sign extend 16bit value to 32bits",                              cf = 0,                                     argtypes=None),
            0x53: idef(name="applytype",          cmt="Apply type parameters",                                          cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            #0x54: 
            0x55: idef(name="newobject",          cmt="Creates new object",                                             cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            0x56: idef(name="newarray",           cmt="Creates new array",                                              cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            0x57: idef(name="newactivation",      cmt="Creates new activation object",                                  cf = 0,                                     argtypes=None),
            0x58: idef(name="newclass",           cmt="Creates new class",                                              cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Class]),
            0x59: idef(name="getdescendants",     cmt="Get descendants",                                                cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Multiname]),
            0x5A: idef(name="newcatch",           cmt="Create new catch scope",                                         cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            0x5B: idef(name="deldescendants",     cmt="Delete descendants",                                             cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            #0x5C: 
            0x5D: idef(name="findpropstrict",     cmt="Search property in scope stack, error when not found",           cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Multiname]),
            0x5E: idef(name="findproperty",       cmt="Search property in scope stack, top object when not found",      cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Multiname]),
            0x5F: idef(name="finddef",            cmt="Search script level definition",                                 cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Multiname]),
            0x60: idef(name="getlex",             cmt="Find and get property",                                          cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Multiname]),
            0x61: idef(name="setproperty",        cmt="Set property",                                                   cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Multiname]),
            0x62: idef(name="getlocal",           cmt="Get local register value",                                       cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            0x63: idef(name="setlocal",           cmt="Set local register value",                                       cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            0x64: idef(name="getglobalscope",     cmt="Get global scope",                                               cf = 0,                                     argtypes=None),
            0x65: idef(name="getscopeobject",     cmt="Get scope object",                                               cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UByteImm]),
            0x66: idef(name="getproperty",        cmt="Get property",                                                   cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Multiname]),
            0x67: idef(name="getpropertylate",    cmt="Get scope object on all levels",                                 cf = 0,                                     argtypes=None),
            0x68: idef(name="initproperty",       cmt="Initialize property",                                            cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Multiname]),
            0x69: idef(name="setpropertylate",    cmt="Set property (stack based)",                                     cf = 0,                                     argtypes=None),
            0x6A: idef(name="deleteproperty",     cmt="Delete property",                                                cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Multiname]),
            0x6B: idef(name="deletepropertylate", cmt="Delete property (stack based)",                                  cf = 0,                                     argtypes=None),
            0x6C: idef(name="getslot",            cmt="Get value of a slot",                                            cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            0x6D: idef(name="setslot",            cmt="Set value of a slot",                                            cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            0x6E: idef(name="getglobalslot",      cmt="Get value of slot on global scope",                              cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            0x6F: idef(name="setglobalslot",      cmt="Set value of slot on global scope",                              cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            0x70: idef(name="convert_s",          cmt="Convert value to string",                                        cf = 0,                                     argtypes=None),
            0x71: idef(name="esc_xelem",          cmt="Escape XML element",                                             cf = 0,                                     argtypes=None),
            0x72: idef(name="esc_xattr",          cmt="Escape XML attribute",                                           cf = 0,                                     argtypes=None),
            0x73: idef(name="convert_i",          cmt="Convert value to integer",                                       cf = 0,                                     argtypes=None),
            0x74: idef(name="convert_u",          cmt="Convert value to unsigned integer",                              cf = 0,                                     argtypes=None),
            0x75: idef(name="convert_d",          cmt="Convert value to double",                                        cf = 0,                                     argtypes=None),
            0x76: idef(name="convert_b",          cmt="Convert value to boolean",                                       cf = 0,                                     argtypes=None),
            0x77: idef(name="convert_o",          cmt="Convert value to Object",                                        cf = 0,                                     argtypes=None),
            0x78: idef(name="checkfilter",        cmt="Check that object can have filter operation applied",            cf = 0,                                     argtypes=None),
            0x79: idef(name="convert_m",          cmt="Convert value to decimal",                                       cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0x7A: idef(name="convert_m_p",        cmt="Unary plus - coerce to numeric",                                 cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            #0x7B: 
            #0x7C: 
            #0x7D: 
            #0x7E: 
            #0x7F: 
            0x80: idef(name="coerce",             cmt="Coerce value to specified type",                                 cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Multiname]),
            0x81: idef(name="coerce_b",           cmt="Coerce value to boolean",                                        cf = 0,                                     argtypes=None),
            0x82: idef(name="coerce_a",           cmt="Coerce value to any type",                                       cf = 0,                                     argtypes=None),
            0x83: idef(name="coerce_i",           cmt="Coerce value to integer",                                        cf = 0,                                     argtypes=None),
            0x84: idef(name="coerce_d",           cmt="Coerce value to double",                                         cf = 0,                                     argtypes=None),
            0x85: idef(name="coerce_s",           cmt="Coerce value to string",                                         cf = 0,                                     argtypes=None),
            0x86: idef(name="astype",             cmt="Return same value or null if not specified type",                cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Multiname]),
            0x87: idef(name="astypelate",         cmt="Return same value or null if not specified type (stack based)",  cf = 0,                                     argtypes=None),
            0x88: idef(name="coerce_u",           cmt="Coerce value to unsigned integer",                               cf = 0,                                     argtypes=None),
            0x89: idef(name="coerce_o",           cmt="Coerce value to Object",                                         cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            #0x8A: 
            #0x8B: 
            #0x8C: 
            #0x8D: 
            #0x8E: 
            0x8F: idef(name="negate_p",           cmt="Negate value using number context",                              cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0x90: idef(name="negate",             cmt="Negate value",                                                   cf = 0,                                     argtypes=None),
            0x91: idef(name="increment",          cmt="Increment value",                                                cf = 0,                                     argtypes=None),
            0x92: idef(name="inclocal",           cmt="Increment local register",                                       cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            0x93: idef(name="decrement",          cmt="Decrement value",                                                cf = 0,                                     argtypes=None),
            0x94: idef(name="declocal",           cmt="Decrement local register",                                       cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            0x95: idef(name="typeof",             cmt="Get name of value type",                                         cf = 0,                                     argtypes=None),
            0x96: idef(name="not",                cmt="Boolean negate",                                                 cf = 0,                                     argtypes=None),
            0x97: idef(name="bitnot",             cmt="Bitwise negate",                                                 cf = 0,                                     argtypes=None),
            #0x98: 
            #0x99: 
            0x9A: idef(name="concat",             cmt="Concat",                                                         cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0x9B: idef(name="add_d",              cmt="Add_d",                                                          cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0x9C: idef(name="increment_p",        cmt="Increment value using number context",                           cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0x9D: idef(name="inclocal_p",         cmt="Increment local register using number context",                  cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0x9E: idef(name="decrement_p",        cmt="Decrement value using number context",                           cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0x9F: idef(name="declocal_p",         cmt="Decrement local register using number context",                  cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0xA0: idef(name="add",                cmt="Add two values",                                                 cf = 0,                                     argtypes=None),
            0xA1: idef(name="subtract",           cmt="Subtract two values",                                            cf = 0,                                     argtypes=None),
            0xA2: idef(name="multiply",           cmt="Multiply two values",                                            cf = 0,                                     argtypes=None),
            0xA3: idef(name="divide",             cmt="Divide two values",                                              cf = 0,                                     argtypes=None),
            0xA4: idef(name="modulo",             cmt="Modulo divide two values",                                       cf = 0,                                     argtypes=None),
            0xA5: idef(name="lshift",             cmt="Bitwise left shift",                                             cf = 0,                                     argtypes=None),
            0xA6: idef(name="rshift",             cmt="Bitwise right shift",                                            cf = 0,                                     argtypes=None),
            0xA7: idef(name="urshift",            cmt="Unsigned bitwise right shift",                                   cf = 0,                                     argtypes=None),
            0xA8: idef(name="bitand",             cmt="Bitwise and",                                                    cf = 0,                                     argtypes=None),
            0xA9: idef(name="bitor",              cmt="Bitwise or",                                                     cf = 0,                                     argtypes=None),
            0xAA: idef(name="bitxor",             cmt="Bitwise xor",                                                    cf = 0,                                     argtypes=None),
            0xAB: idef(name="equals",             cmt="Compare two values",                                             cf = 0,                                     argtypes=None),
            0xAC: idef(name="strictequals",       cmt="Strict compare two values",                                      cf = 0,                                     argtypes=None),
            0xAD: idef(name="lessthan",           cmt="Check that value is less than other value",                      cf = 0,                                     argtypes=None),
            0xAE: idef(name="lessequals",         cmt="Check that value is less or equal than other value",             cf = 0,                                     argtypes=None),
            0xAF: idef(name="greaterthan",        cmt="Check that value is greater or equal than other value",          cf = 0,                                     argtypes=None),
            0xB0: idef(name="greaterequals",      cmt="Check that value is greater or equal than other value",          cf = 0,                                     argtypes=None),
            0xB1: idef(name="instanceof",         cmt="Check that type exists in object prototype chain",               cf = 0,                                     argtypes=None),
            0xB2: idef(name="istype",             cmt="Check that object is of specified type",                         cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_Multiname]),
            0xB3: idef(name="istypelate",         cmt="Check that object is of specified type (stack based)",           cf = 0,                                     argtypes=None),
            0xB4: idef(name="in",                 cmt="Check that object has named property",                           cf = 0,                                     argtypes=None),
            0xB5: idef(name="add_p",              cmt="Add two values using number context",                            cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0xB6: idef(name="subtract_p",         cmt="Subtract two values using number context",                       cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0xB7: idef(name="multiply_p",         cmt="Multiply two values using number context",                       cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0xB8: idef(name="divide_p",           cmt="Divide two values using number context",                         cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0xB9: idef(name="modulo_p",           cmt="Modulo divide two values using number context",                  cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            #0xBA: 
            #0xBB: 
            #0xBC: 
            #0xBD: 
            #0xBE: 
            #0xBF: 
            0xC0: idef(name="increment_i",        cmt="Increment integer value",                                        cf = 0,                                     argtypes=None),
            0xC1: idef(name="decrement_i",        cmt="Decrement integer value",                                        cf = 0,                                     argtypes=None),
            0xC2: idef(name="inclocal_i",         cmt="Increment local register integer value",                         cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            0xC3: idef(name="declocal_i",         cmt="Decrement local register integer value",                         cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            0xC4: idef(name="negate_i",           cmt="Negate integer value",                                           cf = 0,                                     argtypes=None),
            0xC5: idef(name="add_i",              cmt="Add two integer values",                                         cf = 0,                                     argtypes=None),
            0xC6: idef(name="subtract_i",         cmt="Subtract two integer values",                                    cf = 0,                                     argtypes=None),
            0xC7: idef(name="multiply_i",         cmt="Multiply two integer values",                                    cf = 0,                                     argtypes=None),
            #0xC8: 
            #0xC9: 
            #0xCA: 
            #0xCB: 
            #0xCC: 
            #0xCD: 
            #0xCE: 
            #0xCF: 
            0xD0: idef(name="getlocal0",          cmt="Get local register 0",                                           cf = 0,                                     argtypes=None),
            0xD1: idef(name="getlocal1",          cmt="Get local register 1",                                           cf = 0,                                     argtypes=None),
            0xD2: idef(name="getlocal2",          cmt="Get local register 2",                                           cf = 0,                                     argtypes=None),
            0xD3: idef(name="getlocal3",          cmt="Get local register 3",                                           cf = 0,                                     argtypes=None),
            0xD4: idef(name="setlocal0",          cmt="Set local register 0",                                           cf = 0,                                     argtypes=None),
            0xD5: idef(name="setlocal1",          cmt="Set local register 1",                                           cf = 0,                                     argtypes=None),
            0xD6: idef(name="setlocal2",          cmt="Set local register 2",                                           cf = 0,                                     argtypes=None),
            0xD7: idef(name="setlocal3",          cmt="Set local register 3",                                           cf = 0,                                     argtypes=None),
            #0xD8: 
            #0xD9: 
            #0xDA: 
            #0xDB: 
            #0xDC: 
            #0xDD: 
            #0xDE: 
            #0xDF: 
            #0xE0: 
            #0xE1: 
            #0xE2: 
            #0xE3: 
            #0xE4: 
            #0xE5: 
            #0xE6: 
            #0xE7: 
            #0xE8: 
            #0xE9: 
            #0xEA: 
            #0xEB: 
            #0xEC: 
            #0xED: 
            #0xEE: 
            0xEF: idef(name="debug",              cmt="Debugging info",                                                 cf = CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4, argtypes=[OperandType.CONSTANT_UByteImm, OperandType.CONSTANT_String, OperandType.CONSTANT_UByteImm, OperandType.CONSTANT_UIntImm]),
            0xF0: idef(name="debugline",          cmt="Debugging line number info",                                     cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_UIntImm]),
            0xF1: idef(name="debugfile",          cmt="Debugging file info",                                            cf = CF_USE1,                               argtypes=[OperandType.CONSTANT_String]),
            0xF2: idef(name="bkptline",           cmt="Breakpoint on line",                                             cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            0xF3: idef(name="timestamp",          cmt="Timestamp",                                                      cf = 0,                                     argtypes=[OperandType.CONSTANT_Unknown]),
            #0xF4: 
            #0xF5: 
            #0xF6: 
            #0xF7: 
            #0xF8: 
            #0xF9: 
            #0xFA: 
            #0xFB: 
            #0xFC: 
            #0xFD: 
            #0xFE: 
            #0xFF: 
        }

        # Now create an instruction table compatible with IDA processor module requirements
        Instructions = []
        i = 0
        for x in self.itable.values():
            d = dict(name=x.name, feature=x.cf)
            if x.cmt is not None:
                d["cmt"] = x.cmt
            Instructions.append(d)
            setattr(self, "itype_" + x.name, i)
            i += 1

        # icode of the last instruction + 1
        self.instruc_end = len(Instructions) + 1

        # Array of instructions
        self.instruc = Instructions

        # Icode of return instruction. It is ok to give any of possible return
        # instructions
        self.icode_return = self.itype_returnvoid

    # ----------------------------------------------------------------------
    def init_registers(self):
        """This function parses the register table and creates corresponding ireg_XXX constants"""

        # Registers definition
        self.reg_names = [
            # Fake segment registers
            "CS",
            "DS"
        ]

        # Create the ireg_XXXX constants
        for i in xrange(len(self.reg_names)):
            setattr(self, "ireg_" + self.reg_names[i], i)

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.reg_first_sreg = self.ireg_CS
        self.reg_last_sreg  = self.ireg_DS

        # number of CS register
        self.reg_code_sreg = self.ireg_CS

        # number of DS register
        self.reg_data_sreg = self.ireg_DS

    # ----------------------------------------------------------------------
    def __init__(self):
        processor_t.__init__(self)
        #self.PTRSZ = 4 # Assume PTRSZ = 4 by default
        self.init_instructions()
        self.init_registers()

# ----------------------------------------------------------------------

def PROCESSOR_ENTRY():
    return as3_processor_t()
