#TODO write a description for this script
#@author NikZapp
#@category Import
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import PointerDataType, StructureDataType, DataTypeConflictHandler, ArrayDataType, UnsignedIntegerDataType, UnsignedLongDataType
from ghidra.program.model.listing import Function, ParameterImpl
from ghidra.app.util.parser import FunctionSignatureParser
from ghidra.app.util.cparser.C import ParseException
from ghidra.app.services import DataTypeManagerService
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd

import os
import re



file_path = askDirectory("Select source folder", "Open").absolutePath

# Global stuff
dataTypeManager = currentProgram.getDataTypeManager()
functionManager = currentProgram.getFunctionManager()

dtms = state.tool.getService(DataTypeManagerService)
functionParser = FunctionSignatureParser(dataTypeManager, dtms)

#for dt in dataTypeManager.getAllDataTypes():
#    print(dt.getDataTypePath())





# Define custom string type
char_ptr  = PointerDataType(ghidra.program.model.data.CharDataType.dataType)
size_type = UnsignedLongDataType()
dummy_arr = ArrayDataType(UnsignedIntegerDataType.dataType, 16, 1)

string_struct = StructureDataType("basic_string", 0)
string_struct.add(char_ptr,    "data",  "")
string_struct.add(size_type,   "size",  "")
string_struct.add(dummy_arr,   "dummy", "")

dataTypeManager.addDataType(string_struct, DataTypeConflictHandler.REPLACE_HANDLER)



type_name_map = {
    # Add stuff here like 
    "std::string" : "basic_string *",
}

# TODO:
# ---------------------------------------------------------------
# Guess unknown datatypes by the offsets they use 
# e.g. if you see thing + 0x123, 
# find things you know with offset 0x123 and suggest the results
# in a bookmark or comment
# ---------------------------------------------------------------
# For each function, get all calls to it, and check the parameters
# and modify their names. this will be useful for stuff like 
# xyz coordinates, and will make figuring out some functions 
# way easier.
# ---------------------------------------------------------------
# Also for each function, check all functions inside of it and see 
# if they use any params from the current func, and then name the
# parameters

color_enabled = False
class TextColor:
    reset = '\033[0;37;40m'
    red = '\033[1;31;40m'
    green = '\033[1;32;40m'

def print_err(text):
    if color_enabled:
        print(TextColor.red + str(text) + TextColor.reset)
    else:
        print("E: " + str(text))


def print_success(text):
    if color_enabled:
        print(TextColor.green + str(text) + TextColor.reset)
    else:
        print("I: " + str(text))


def to_datatype_string(name):
    name = name.strip()
    if name.startswith("const"):
        name = name[5:].strip()
    if name in type_name_map:
        name = type_name_map[name]
    return name


def to_datatype(name):
    # TODO: Parse arrays
    name = name.strip()
    if name.startswith("const"):
        name = name[5:].strip()
    if name.endswith("*"):
        base = to_datatype(name[:-1].strip())
        return PointerDataType(base)
    if name in type_name_map:
        name = type_name_map[name]
    base = dataTypeManager.getDataType("/" + name)
    return base


def define_function(address, name, return_type=None, params=None):
    addr = toAddr(address)
    func = getFunctionAt(addr)
    
    if not func:
        print_err("Function missing at %x" % address)
        return

    func.setName(name, SourceType.USER_DEFINED)
    func.setCallingConvention("__stdcall") # ghidra's builtin __thiscall sucks. we can do better
    
    if return_type and params is not None:
        param_list = []
        for i, param in enumerate(params):
            param_type_raw = " ".join(param[:-1])
            param_type = to_datatype_string(param_type_raw)
            param_name = param[-1].strip()
            param_list.append(param_type + " " + param_name)

        #print(params)
        signature = return_type + " " + name + "(" + ", ".join(param_list) + ")"
        try:
            sig = functionParser.parse(None, signature)
        except ParseException as e:
            print_err(e)
            print_err("In function %s %s" % (return_type, name))
            return
        cmd = ApplyFunctionSignatureCmd(addr, sig, SourceType.USER_DEFINED)
        cmd.applyTo(currentProgram)
    
    print_success("Defined function %s %s at %x" % (return_type, name, address))


for root, dirs, files in os.walk(file_path):
    for filename in files:
        if filename.endswith('.def'):
            fullpath = os.path.join(root, filename)
            file_name = os.path.splitext(os.path.basename(fullpath))[0]
            
            print(fullpath)
            struct_name = file_name
            class_struct = StructureDataType(struct_name, 0)
            has_vtable = False
            vtable_struct = StructureDataType(struct_name + "_vtable", 0)
            vtable_address = None
            
            with open(fullpath, 'r') as file:
                for line in file.readlines():
                    # wooo! indentation staircase!
                    # normal properties/methods/whatever
                    if line.startswith("size"):
                        m = re.match(r"size 0x([0-9a-fA-F]+);", line)
                        if m:
                            size = int(m.group(1), 16)
                            class_struct.setLength(size)
                    
                    elif line.startswith("constructor"):
                        m = re.match(r"constructor\s+\(([^)]+)\)\s+=\s+0x([0-9a-fA-F]+);", line)
                        if m:
                            param_str, addr = m.groups()
                            params = [p.strip().split() for p in param_str.split(",")] if param_str.strip() else []
                            define_function(int(addr, 16), struct_name + "::constructor", None, params)
                    
                    elif line.startswith("property"):
                        m = re.match(r"property\s+(\w+)\s+(\w+)\s+=\s+0x([0-9a-fA-F]+);", line)
                        if m:
                            type_name, name, offset = m.groups()
                            offset = int(offset, 16)
                            dtype = to_datatype(type_name.strip())
                            if dtype:
                                struct_length = class_struct.getLength()
                                if struct_length < offset + dtype.getLength():
                                    print_err("Struct %s is too small!" % struct_name)
                                    print_err("Cannot fit %s %s at +0x%x, resizing" % (type_name, name, offset))
                                    class_struct.setLength(offset + dtype.getLength())
                                class_struct.insertAtOffset(offset, dtype, 0, name, "")
                            else:
                                print_err("Unknown datatype %s" % type_name)
                    
                    elif line.startswith("method"):
                        m = re.match(r"method\s+(\w+)\s+(\w+)\(([^)]*)\)\s+=\s+0x([0-9a-fA-F]+);", line)
                        if m:
                            ret, name, param_str, addr = m.groups()
                            params = [[struct_name, "*this"]]
                            params += [p.strip().split() for p in param_str.split(",")] if param_str.strip() else []
                            define_function(int(addr, 16), struct_name + "::" + name, ret, params)
                    
                    # vtable stuff
                    elif line.startswith("vtable"):
                        m = re.match(r"vtable\s+0x([0-9a-fA-F]+);", line)
                        if m:
                            vtable_address = toAddr(int(m.group(1), 16))
                    
                    if line.startswith("vtable-size"):
                        m = re.match(r"vtable-size 0x([0-9a-fA-F]+);", line)
                        if m:
                            size = int(m.group(1), 16)
                            vtable_struct.setLength(size)
                    
                    elif line.startswith("virtual-method"):
                        m = re.match(r"virtual-method\s+(\w+)\s+(\w+)\(([^)]*)\)\s+=\s+0x([0-9a-fA-F]+);", line)
                        if m:
                            if not vtable_address:
                                print_err("VTable size is not defined but it has methods!")
                                continue
                            ret, name, param_str, offset = m.groups()
                            offset = int(offset, 16)
                            params = [[struct_name, "*this"]]
                            params += [p.strip().split() for p in param_str.split(",")] if param_str.strip() else []
                            # i think multiple names will be defined for one function, but im not sure how thats gonna be handled
                            # and i dont know how it *should* be handled, so i dont care
                            # OH WAIT! just change the names in the vtable struct and dont(?) name the actual function
                            # ehhh nvm, lets see if this works
                            vtable_function_address = getInt(vtable_address.add(offset))
                            define_function(vtable_function_address, struct_name + "_vtable::" + name, ret, params)
                            dtype = to_datatype(ret.strip() + "*")
                            vtable_struct.insertAtOffset(offset, dtype, 0, name, "vtable")
            
            if vtable_address:
                # create and store at location
                dataTypeManager.addDataType(vtable_struct, DataTypeConflictHandler.REPLACE_HANDLER)
                clearListing(vtable_address, vtable_address.add(vtable_struct.getLength() - 1))
                createData(vtable_address, vtable_struct)
                # add to parent class (which is a struct too, thats fun)
                dtype = to_datatype(struct_name + "_vtable*")
                class_struct.insertAtOffset(0, dtype, 0, "vtable", "")
                
                print_success("Defined vtable %s_vtable" % struct_name)
            
            dataTypeManager.addDataType(class_struct, DataTypeConflictHandler.REPLACE_HANDLER)
            print_success("Added %s struct" % struct_name)