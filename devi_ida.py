import idaapi
import idautils
import idc
import json
import traceback
from ida_xref import add_cref
from ida_nalt import get_root_filename
from ida_kernwin import ask_file

# From http://www.hexblog.com/?p=886
# 1) Create the handler class
class DeviIDAHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
        self.version = 0.2

    # Executed when Menu is selected.
    def activate(self, ctx):
        json_file = ask_file(0, ".json", "Load Virtual Calls")
        with open(json_file) as f:
            devi_json_data = json.load(f)
        if self.version < devi_json_data["deviVersion"]:
            print("[!] devi JSON file has a more recent version than IDA plugin!")
            print("[!] we try parsing anyway!")
        if self.version > devi_json_data["deviVersion"]:
            print("[!] Your devi_ida and devi_frida versions are out of sync. Update your devi_ida!")

        try:
            self.devirtualize_calls(devi_json_data["calls"], devi_json_data["modules"])
            return 1
        except:
            print("[!] An error was encountered!")
            traceback.print_exc()

        

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    
    def devirtualize_calls(self, call_list, modules):
        ida_file_name = get_root_filename()

        call_cnt = 0

        for module in modules:
            if module["name"] == ida_file_name:
                loaded_module = module
                break
        
        start = int(loaded_module["base"], 16)
        end = start + loaded_module["size"]

        print("[*] Adding virtual calls for module " + ida_file_name)

        for v_call in call_list:
            for call in v_call:
                # Check if call belongs to the current module
                if start <= int(call, 16) <= end:

                    src = int(call, 16) - start
                    dst = int(v_call[call]) - start
                    add_cref(src, dst, fl_CN | XREF_USER)

                    call_cnt += 1

        print("[*] Added {} virtual calls for module {}!".format(call_cnt, ida_file_name))


# 2) Describe the action
action_desc = idaapi.action_desc_t(
    'devi:loadJSON',   # The action name. This acts like an ID and must be unique
    'Load Virtual Calls',  # The action text.
    DeviIDAHandler(),   # The action handler.
    '',      # Optional: the action shortcut
    'Load JSON file with virtual calls',  # Optional: the action tooltip (available in menus/toolbar)
    )           # Optional: the action icon (shows when in menus/toolbars)

# 3) Register the action
idaapi.register_action(action_desc)

idaapi.attach_action_to_menu(
        'File/Load file/',  # The relative path of where to add the action
        'devi:loadJSON',    # The action ID (see above)
        idaapi.SETMENU_APP) # We want to append the action after the 'Manual instruction...'