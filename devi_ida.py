import idaapi
import idautils
import json

# From http://www.hexblog.com/?p=886
# 1) Create the handler class
class DeviLoadJSONHandler(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    # Executed when Menu is selected.
    def activate(self, ctx):
        json_file = AskFile(0, ".json", "Load Virtual Calls")
        with open(json_file) as f:
            json_objects = json.load(f)
        self.devirtualize_calls(json_objects["calls"])
        return 1

    # This action is always available.
    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    
    def devirtualize_calls(self, call_list):
        print "[*] Adding " + str(len(call_list)) + " virtual calls!"
        for v_call in call_list:
            for call in v_call:
                #AddCodeXref(int(call), int(v_call[call]), fl_CN)
                # #define fl_CN   17              // Call Near
                # #define XREF_USER 32            // All user-specified xref types
                AddCodeXref(int(call), int(v_call[call]), fl_CN | XREF_USER)
        print "[*] Added " + str(len(call_list)) + " virtual calls!"


# 2) Describe the action
action_desc = idaapi.action_desc_t(
    'devi:loadJSON',   # The action name. This acts like an ID and must be unique
    'Load Virtual Calls',  # The action text.
    DeviLoadJSONHandler(),   # The action handler.
    '',      # Optional: the action shortcut
    'Load JSON file with virtual calls',  # Optional: the action tooltip (available in menus/toolbar)
    )           # Optional: the action icon (shows when in menus/toolbars)

# 3) Register the action
idaapi.register_action(action_desc)

idaapi.attach_action_to_menu(
        'File/Load file/',  # The relative path of where to add the action
        'devi:loadJSON',    # The action ID (see above)
        idaapi.SETMENU_APP) # We want to append the action after the 'Manual instruction...'