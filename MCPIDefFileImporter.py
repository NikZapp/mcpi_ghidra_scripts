#TODO write a description for this script
#@author NikZapp
#@category Import
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import PointerDataType, StructureDataType, DataTypeConflictHandler
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

type_name_map = {
    # Add stuff heree like 
    # "const std::string" : "string-type-in-ghidra",
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


def define_function(address, name, return_type=None, params=None):
    addr = toAddr(address)
    func = getFunctionAt(addr)
    
    if not func:
        print("Function missing at " + str(addr))
        return

    func.setName(name, SourceType.USER_DEFINED)
    func.setCallingConvention("__thiscall")
    
    if return_type and params is not None:
        param_list = []
        for i, param in enumerate(params):
            param_type_raw = " ".join(param[:-1])
            param_type = type_name_map.get(param_type_raw, param_type_raw)
            param_name = param[-1].strip()
            param_list.append(param_type + " " + param_name)

        #print(params)
        signature = return_type + " " + name + "(" + ", ".join(param_list) + ")"
        try:
            sig = functionParser.parse(None, signature)
        except ParseException as e:
            print(e)
            print(" > In function", return_type, name)
            return
        cmd = ApplyFunctionSignatureCmd(addr, sig, SourceType.USER_DEFINED)
        cmd.applyTo(currentProgram)
    
    print("+ Defined function", return_type, name, "at", addr)


for root, dirs, files in os.walk(file_path):
    for filename in files:
        if filename.endswith('.def'):
            fullpath = os.path.join(root, filename)
            file_name = os.path.splitext(os.path.basename(fullpath))[0]
            
            print(fullpath)
            
            with open(fullpath, 'r') as file:
                for line in file.readlines():
                    # wooo! indentation staircase!
                    if line.startswith("method"):
                        m = re.match(r"method\s+(\w+)\s+(\w+)\(([^)]*)\)\s+=\s+0x([0-9a-fA-F]+);", line)
                        if m:
                            ret, name, param_str, addr = m.groups()
                            #print(m.groups())
                            params = [p.strip().split() for p in param_str.split(",")] if param_str.strip() else []
                            define_function(int(addr, 16), file_name + "_" + name, ret, params)
