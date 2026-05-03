#TODO write a description for this script
#@author NikZapp
#@category Import
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import PointerDataType, StructureDataType, DataTypeConflictHandler, ArrayDataType, UnsignedIntegerDataType, UnsignedLongDataType, FunctionDefinitionDataType
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

# Vectors
def make_vector_type(inner_type_name):
    print("TO_VECTOR: " + inner_type_name)
    vec_name = "vector_" + inner_type_name.replace(" ", "_").replace("*", "ptr")
    existing = dataTypeManager.getDataType("/" + vec_name)
    if existing:
        return existing
    
    inner_type = to_datatype(inner_type_name)
    if not inner_type:
        return None
    
    ptr_type = PointerDataType(inner_type)
    vec_struct = StructureDataType(vec_name, 0)
    vec_struct.add(ptr_type, "begin", "")
    vec_struct.add(ptr_type, "end", "")
    vec_struct.add(ptr_type, "capacity", "")
    
    dataTypeManager.addDataType(vec_struct, DataTypeConflictHandler.REPLACE_HANDLER)
    return dataTypeManager.getDataType("/" + vec_name)


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
    
    # Handle std::vector<T>
    vec_match = re.match(r'std::vector\s*<\s*(.*?)\s*>\s*(\*+)?$', name)
    if vec_match:
        inner_name = vec_match.group(1)
        ptrs = vec_match.group(2) or ""
        vec_name = "vector_" + inner_name.replace(" ", "_").replace("*", "ptr")
        return vec_name + ptrs  # will be resolved later by to_datatype
    
    if name.startswith("const"):
        name = name[5:].strip()
    if name in type_name_map:
        name = type_name_map[name]
    return name


def to_datatype(name):
    print("parsing " + name)
    # TODO: Parse arrays
    name = name.strip()
    
    # Handle std::vector<T>
    vec_match = re.match(r'std::vector\s*<\s*(.*?)\s*>\s*(\*+)?$', name)
    if vec_match:
        print("vector type detected")
        inner_name = vec_match.group(1)
        ptrs = vec_match.group(2) or ""
        vec_type = make_vector_type(inner_name)
        for _ in ptrs:
            vec_type = PointerDataType(vec_type)
        return vec_type
    
    if name.startswith("const"):
        name = name[5:].strip()
    if name.endswith("*"):
        base = to_datatype(name[:-1].strip())
        return PointerDataType(base)
    if name in type_name_map:
        name = type_name_map[name]
    base = dataTypeManager.getDataType("/" + name)
    if not base:
        print_err("Failed to convert '%s' to type!" % name)
    print(base)
    return base

def parse_type_and_name(decl_str, convert_to_type=True):
    # i HATE c++
    decl_str = decl_str.strip()
    print("parsing type and name: " + decl_str)
    
    # Handle array brackets first
    array_match = re.search(r'\[0x([0-9a-fA-F]+)\]', decl_str)
    array_len = None
    if array_match:
        array_len = int(array_match.group(1), 16)
        decl_str = decl_str[:array_match.start()].strip()
        print("detected array with len " + str(array_len) + " : " + str(decl_str))
    
    array_match = re.search(r'\[([0-9]+)\]', decl_str)
    if array_match:
        array_len = int(array_match.group(1))
        decl_str = decl_str[:array_match.start()].strip()
        print("detected array with len " + str(array_len) + " : " + str(decl_str))
    
    # Extract variable name from end
    var_match = re.search(r'([A-Za-z_]\w*)$', decl_str)
    if not var_match:
        raise ValueError("Could not parse variable name in: " + decl_str)
    var_name = var_match.group(1)
    type_str = decl_str[:var_match.start()].strip()
    print("type_str: '%s', var_name: '%s'" % (type_str, var_name))
    
    # Check if it's a vector BEFORE stripping pointers
    vec_match = re.match(r'(std::vector\s*<.*?>)\s*(\*+|&+)?$', type_str)
    if vec_match:
        print("detected vector!")
        if convert_to_type:
            base_type = to_datatype(type_str)
            if array_len is not None:
                base_type = ArrayDataType(base_type, array_len, base_type.getLength())
            return base_type, var_name
        else:
            return to_datatype_string(type_str), var_name
    
    # Remove pointers/references
    # why are they the same thing!??!?!??
    # I *HATE* C++!!!!!
    pointer_count = type_str.count('*') + type_str.count('&')
    type_str = type_str.replace('*', '').replace('&', '').strip()
    type_str += '*' * pointer_count
    
    if convert_to_type:
        base_type = to_datatype(type_str)
        if array_len is not None:
            base_type = ArrayDataType(base_type, array_len, base_type.getLength())
        return base_type, var_name
    else:
        if type_str in type_name_map:
            type_str = type_name_map[type_str]
        return type_str, var_name

def preprocess_def_file(filepath, extended=False):
    lines = []
    post_lines = []
    with open(filepath, 'r') as file:
        for line in file.readlines():
            m = re.match(r"extends\s+(\w+);", line.strip())
            if m:
                parent_name = m.group(1)
                parent_path = os.path.join(os.path.dirname(filepath), parent_name + '.def')
                if os.path.exists(parent_path):
                    # Recursively read parent file
                    parent_lines = preprocess_def_file(parent_path, extended=True)
                    post_lines.append("// Extend: %s\n" % parent_name)
                    post_lines.extend(parent_lines)
                    print_success("Extended %s with %s" % (os.path.basename(filepath), parent_name))
                else:
                    print_err("Parent class file not found: %s" % parent_path)
            else:
                # Filter out commands that should not be inherited
                stripped = line.strip()
                if (extended and (
                    stripped.startswith("extends ") or 
                    stripped.startswith("size ") or
                    stripped.startswith("vtable-size ") or
                    stripped.startswith("vtable ") or 
                    stripped.startswith("static-property ") or
                    stripped.startswith("static-method ") or
                    stripped.startswith("constructor ") or
                    stripped.startswith("mark-as-simple ") or
                    stripped.startswith("generate-custom-wrapper "))):
                    continue
                lines.append(line)
    return lines + post_lines

def define_function(address, name, return_type=None, params=None):
    addr = toAddr(address)
    func = getFunctionAt(addr)
    
    if not func:
        print_success("Function missing at %x, creating" % address)
        func = createFunction(addr, name)

    func.setName(name, SourceType.USER_DEFINED)
    func.setCallingConvention("__stdcall") # ghidra's builtin __thiscall sucks. we can do better
    
    if return_type and params is not None:
        param_list = []
        for i, param in enumerate(params):
            param_type_raw = " ".join(param[:-1])
            param_type = to_datatype_string(param_type_raw)
            param_name = param[-1].strip()
            param_list.append(param_type + " " + param_name)

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
            
            struct_name = file_name
            class_struct = StructureDataType(struct_name, 0)
            has_vtable = False
            vtable_struct = StructureDataType(struct_name + "_vtable", 0)
            vtable_address = None
            
            lines = preprocess_def_file(fullpath)
            for line in lines:
                if True:
                    m = None
                    # wooo! indentation staircase!
                    # normal properties/methods/whatever
                    if line.startswith("size"):
                        m = re.match(r"size 0x([0-9a-fA-F]+);", line)
                        if m:
                            size = int(m.group(1), 16)
                            class_struct.setLength(size)
                    
                    elif line.startswith("constructor"):
                        m = re.match(r"constructor\s+\(([^)]*)\)\s+=\s+0x([0-9a-fA-F]+);", line)
                        if m:
                            dtype = struct_name + "*"
                            param_str, addr = m.groups()
                            param_array = [p.strip().split() for p in param_str.split(",")] if param_str.strip() else []
                            params = [] if any(len(p) > 1 and p[1] == '*self' for p in param_array) else [[struct_name, "*self"]]
                            params += param_array
                            define_function(int(addr, 16), struct_name + "::constructor", dtype, params)
                    
                    elif line.startswith("property"):
                        m = re.match(r"property\s+(.*)\s+=\s+0x([0-9a-fA-F]+);", line)
                        if m:
                            declaration, offset = m.groups()
                            dtype, name = parse_type_and_name(declaration)
                            offset = int(offset, 16)
                            if dtype:
                                struct_length = class_struct.getLength()
                                if struct_length < offset + dtype.getLength():
                                    #print_err("Struct %s is too small!" % struct_name)
                                    #print_err("Cannot fit %s at +0x%x, resizing" % (declaration, offset))
                                    class_struct.setLength(offset + dtype.getLength())
                                class_struct.replaceAtOffset(offset, dtype, 0, name, "")
                            else:
                                print_err("Unknown datatype %s" % declaration)
                    
                    elif line.startswith("method"):
                        m = re.match(r"^\s*method\s+(.*)\(([^)]*)\)\s+(?:const\s+)*=\s+0x([0-9a-fA-F]+);", line)
                        if m:
                            declaration, param_str, addr = m.groups()
                            dtype, name = parse_type_and_name(declaration, False)
                            param_array = [p.strip().split() for p in param_str.split(",")] if param_str.strip() else []
                            params = [] if any(len(p) > 1 and p[1] == '*self' for p in param_array) else [[struct_name, "*self"]]
                            params += param_array
                            define_function(int(addr, 16), struct_name + "::" + name, dtype, params)
                    
                    elif line.startswith("static-property"):
                        m = re.match(r"static-property\s+(.*)\s+=\s+0x([0-9a-fA-F]+);", line)
                        if m:
                            declaration, addr = m.groups()
                            dtype, name = parse_type_and_name(declaration)
                            addr = int(addr, 16)
                            address = toAddr(addr)
                            if dtype:
                                clearListing(address, address.add(dtype.getLength() - 1))
                                createData(address, dtype)
                                symbol = getSymbolAt(address)
                                if not symbol:
                                    createLabel(address, struct_name + "::" + name, True)
                                    symbol = getSymbolAt(address)
                                symbol.setName(struct_name + "::" + name, SourceType.USER_DEFINED)
                                print_success("Added static property %s at 0x%x" % (declaration, addr))
                            else:
                                print_err("Unknown datatype %s" % declaration)
                    
                    elif line.startswith("static-method"):
                        m = re.match(r"static-method\s+(.*)\(([^)]*)\)\s+(?:const\s+)*=\s+0x([0-9a-fA-F]+);", line)
                        if m:
                            declaration, param_str, addr = m.groups()                            
                            dtype, name = parse_type_and_name(declaration, False)
                            params = [p.strip().split() for p in param_str.split(",")] if param_str.strip() else []
                            define_function(int(addr, 16), struct_name + "::" + name, dtype, params)
                    
                    # vtable stuff
                    elif line.startswith("vtable-size"):
                        m = re.match(r"vtable-size 0x([0-9a-fA-F]+);", line)
                        if m:
                            size = int(m.group(1), 16)
                            vtable_struct.setLength(size)
                    
                    elif line.startswith("vtable"):
                        m = re.match(r"vtable\s+0x([0-9a-fA-F]+);", line)
                        if m:
                            vtable_address = toAddr(int(m.group(1), 16))
                    
                    elif line.startswith("virtual-method"):
                        m = re.match(r"virtual-method\s+(?:const\s+)*(.*)\(([^)]*)\)\s+(?:const\s+)*=\s+0x([0-9a-fA-F]+);", line)
                        if m:
                            if not vtable_address:
                                print_err("VTable size is not defined but it has methods!")
                            declaration, param_str, offset = m.groups()
                            dtype, name = parse_type_and_name(declaration, False)
                            offset = int(offset, 16)
                            param_array = [p.strip().split() for p in param_str.split(",")] if param_str.strip() else []
                            params = [] if any(len(p) > 1 and p[1] == '*self' for p in param_array) else [[struct_name, "*self"]]
                            params += param_array
                            # i think multiple names will be defined for one function, but im not sure how thats gonna be handled
                            # and i dont know how it *should* be handled, so i dont care
                            # OH WAIT! just change the names in the vtable struct and dont(?) name the actual function
                            # ehhh nvm, lets see if this works
                            func = None
                            if vtable_address:
                                vtable_function_address = getInt(vtable_address.add(offset))
                                define_function(vtable_function_address, struct_name + "_vtable::" + name, dtype, params)
                                func = getFunctionAt(toAddr(vtable_function_address))
                            
                            if func:
                                func_def = FunctionDefinitionDataType(func, True)
                                dtype = PointerDataType(func_def)
                            else:
                                dtype = to_datatype(struct_name + "*")
                            struct_length = vtable_struct.getLength()
                            if struct_length < offset + dtype.getLength():
                                #print_err("VTable %s is too small!" % (struct_name + "_vtable"))
                                #print_err("Cannot fit %s %s at +0x%x, resizing" % (dtype, name, offset))
                                vtable_struct.setLength(offset + dtype.getLength())
                            vtable_struct.replaceAtOffset(offset, dtype, 0, name, "vtable")
                    elif line.startswith("//"):
                        m = True
                    elif line.strip() == "":
                        m = True
                    
                    if not m:
                        print_err("Could not parse line:")
                        print_err(line)
                    
            if vtable_address:
                # create and store at location
                clearListing(vtable_address, vtable_address.add(vtable_struct.getLength() - 1))
                createData(vtable_address, vtable_struct)
            if vtable_struct.getLength() > 1 or vtable_address:
                # add to parent class (which is a struct too, thats fun)
                dataTypeManager.addDataType(vtable_struct, DataTypeConflictHandler.REPLACE_HANDLER)
                dtype = to_datatype(struct_name + "_vtable*")
                struct_length = class_struct.getLength()
                if struct_length < dtype.getLength():
                    print_err("Struct %s is empty!" % struct_name)
                    print_err("Cannot fit vtable, resizing")
                    class_struct.setLength(dtype.getLength())
                class_struct.replaceAtOffset(0, dtype, 0, "vtable", "")
                
                print_success("Defined vtable %s_vtable" % struct_name)
            
            dataTypeManager.addDataType(class_struct, DataTypeConflictHandler.REPLACE_HANDLER)
            print_success("Added %s struct" % struct_name)