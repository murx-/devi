'use strict';

var debug = "%s"
var moduleName = '%s'
var myModule = Process.findModuleByName(moduleName)

var symboleInput = '%s'
if (isNaN(Number(symboleInput))) {
    var symbolAddress = getSymbolAddress(moduleName, symboleInput);
} else {
    var symbolAddress = Number(symboleInput) + parseInt(myModule.base, 16);
}

if (symbolAddress == undefined) {
    console.log("[!] Unable to finde symbole " + symboleInput)
    send({ "deviError": "No symbole found named: " + symboleInput })
}


if (myModule != null) {
    myModule.end = parseInt(myModule.base, 16) + myModule.size;
    attachInterceptor();
} else {
    send({ "deviError": "No module found named: " + moduleName });
    // exit javascript here?
    console.log("[!] No module found named: " + moduleName )
}


function log_d(str) {
    if (debug == "True") 
    console.log("[+] " + str);
}

/**
 * 
 * @param {*} moduleName 
 * @param {*} symbolName 
 * 
 * return the symbol in the module
 * 
 */
function getSymbolAddress(moduleName, symbolName) {
    var symbols = Module.enumerateSymbols(moduleName);
    for (var i = 0; i < symbols.length; i++) {
        if (symbols[i].name == symbolName)
            return symbols[i].address
    }
}

/**
 * 
 * @param {*} codePointer 
 * check if the instruction at codePointer is an indrect call. 
 */
function isIndirectCall(codePointer) {
    return !Instruction.parse(codePointer).toString().startsWith('call 0x')
}

function printDebugCallEvent(callEvent) {
    log_d((callEvent[1] - myModule.base).toString(16) + ' -> ' + (callEvent[2] - myModule.base).toString(16));
    log_d(Instruction.parse(callEvent[1]) + " -> " + Instruction.parse(callEvent[2]));
    log_d("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
}

/**
 * stalk the current thread. 
 */
function traceCalls() {
    Stalker.follow({
        events: {
            call: true
        },


        onReceive: function (events) {

            var callList = [];

            var call_events = Stalker.parse(events);
            call_events.forEach(function (event) {
                //todo change ifs
                if ((myModule.base <= event[1]) && (event[1] <= myModule.end)) {
                    if (isIndirectCall(ptr(event[1]))) {

                        //debug!
                        printDebugCallEvent(event);

                        var src = (event[1] - myModule.base);
                        var payload = {};
                        payload[src] = (event[2] - myModule.base).toString(10);
                        callList.push(payload);
                    }
                }
            });

            send({ "callList": callList })
        },

        onLeave: function (retval) {
            //console.log("onLeave Called");
            Stalker.unfollow(Process.getCurrentThreadId());
            Stalker.flush();
            Stalker.garbageCollect();
            send({ "finished": true });
        }

    });
}


/**
 * attach interceptor to main, and start stalker
 */
function attachInterceptor() {
    Interceptor.attach(symbolAddress, {
        onEnter: function (args) {
            log_d('[-] Start Tracing');
            log_d("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")

            traceCalls();
        },
        onLeave: function () {
            Stalker.flush();
            Stalker.unfollow(Process.getCurrentThreadId());
            Stalker.garbageCollect();
            log_d('[-] Done Tracing')
            // send here that we are done and user should detach
            send({"deviFinished":"Execution finished detach with ctrl + d"})
        }
    });
}