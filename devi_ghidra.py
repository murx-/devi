# -*- coding: utf-8 -*-

import json
import sys
from ghidra.program.model.symbol.FlowType import UNCONDITIONAL_CALL

DEBUG = True
VERSION = 0.2

def dprint(str):
    if DEBUG:
        print(str)

def get_call_info(addr, modules):
    if addr[:2] == '0x':
        addr = int(addr, 16)
    else:
        addr = int(addr)
    for module in modules:
        try:
            module_start = int(module['base'], 16)
        except TypeError:
            dprint(module)
            continue
        module_end = module_start + module['size']
        if module_start <= addr <= module_end:
            # calc offset
            call_info = dict()
            call_info['rel_addr'] = addr - module_start
            call_info['module'] = module['name']
            call_info['comment'] = module['name'] + '+' + hex(addr - module_start)
            return call_info

def add_xref(call_src, call_dst , module_name, modules):
    #print(call_src)
    call_dst = get_call_info(call_dst, modules)

    # TODO ghidra
    ghidra_offset = str(currentProgram.getMinAddress())
    ghidra_offset = int(ghidra_offset, 16)
    new_target = hex(call_src['rel_addr'] + ghidra_offset)[:-1]
    ghidra_src_address = currentProgram.getMinAddress().getAddress(new_target)

    if module_name in call_dst['comment']:

        # TODO ghidra
        new_dst = hex(call_dst['rel_addr'] + ghidra_offset)[:-1]
        ghidra_dst_address = currentProgram.getMinAddress().getAddress(new_dst)
        addInstructionXref( ghidra_src_address,  ghidra_dst_address, -1, UNCONDITIONAL_CALL)

    # TODO ghidra
    setEOLComment(ghidra_src_address, str(call_dst['comment']))
    #dprint('added xref: '+ hex(call_src['rel_addr']) +' -> ' + str(call_dst['comment']))
    dprint('added xref: '+ str(ghidra_src_address) +' -> ' + str(ghidra_dst_address))


# TODO ghidra
json_file = askFile('JSON File', 'Open')


# TODO ghidra
working_module_name = askString('Module Name Working on', 'Module Name')

# jython seems to want a str conversion...
f = open(str(json_file))
json_data = json.load(f)
f.close()

json_version = json_data['deviVersion']

if json_version < VERSION:
    print("[!] Ghidra Plugin might not support the version of the loaded json file!")

call_list = json_data['calls']
modules = json_data['modules']

# make sure list is unique 
done = list()

#print(module_name_and_offset_for_address("0x6c7c800b", modules))
for call in call_list:
    for i in call:
        src = i
        target = call[i]
    cur_call = get_call_info(src, modules)
    if working_module_name in cur_call['comment']:
        if src+target not in done:
            add_xref(cur_call, target, working_module_name, modules)