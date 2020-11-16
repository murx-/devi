var stalked_threads = []
var DEBUG = false;
send({"moduleMap":Process.enumerateModulesSync()})
stalk_threads(Process.enumerateThreads())
hook_threads();


function stalk_threads(all_threads) {
    for (var i=0; i< all_threads.length; i++) {
        var tid = all_threads[i].id;
        if (stalked_threads.indexOf(tid) >= 0) {
            debugLog("Already Stalked!")
        } else {
            debugLog(all_threads[i].id)
            traceCalls(all_threads[i].id)
            stalked_threads.push(all_threads[i].id)
        }
    }
}

function hook_threads() {
    Module.getExportByName("Kernel32.dll", "CreateThread")
    Interceptor.attach(Module.getExportByName("Kernel32.dll", "CreateThread"), {
        onEnter: function (args) {
            console.log('[-] Start Tracing');
            debugLog("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
            Process.enumerateThreads();
    
            //traceCalls();
        },
        onLeave: function () {
            console.log("[-] New Thread Created")
            var new_threads = Process.enumerateThreads()
            stalk_threads(new_threads)
        }
    });
}

function traceCalls(threadID) {
    Stalker.follow(threadID, {
        events: {
          call: true, // CALL instructions: yes please
        },
        
        // copy code
        onReceive: function (events) {
            debugLog(Stalker.parse(events, {
            annotate: true, // to display the type of event
            stringify: true
              // to format pointer values as strings instead of `NativePointer`
              // values, i.e. less overhead if you're just going to `send()` the
              // thing not actually parse the data agent-side
          }));
        },


        // Devi Code
        onReceive: function (events) {

            var callList = [];

            var call_events = Stalker.parse(events);
            call_events.forEach(function (event) {
                //todo change ifs
                if (isIndirectCall(ptr(event[1]))) {
                        //debug!
                    printDebugCallEvent(event);

                    Instruction.parse(ptr(event[1])).toString()


                    var src = (event[1]);
                    var payload = {};
                    payload[src] = (event[2]).toString(10);
                    callList.push(payload);
                    send(payload)
                }
            });

            send({ "callList": callList })

        },

        
      });
}

function isIndirectCall(codePointer) {
    if (Instruction.parse(codePointer).toString().startsWith('call 0x')) {
        return false
    }
    if (Instruction.parse(codePointer).toString().startsWith('call dword ptr [0x')) {
        return false
    }

    return true;
    
}

function debugLog(toPrint) {
	if (DEBUG == true) {
		console.log(toPrint);
	}
}

function printDebugCallEvent(callEvent) {
	if (DEBUG == true) {
		console.log((callEvent[1]).toString(16) + ' -> ' + (callEvent[2]).toString(16));
		console.log(Instruction.parse(callEvent[1]) + " -> " + Instruction.parse(callEvent[2]));
		console.log("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~");
	}
}
