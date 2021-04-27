# from datetime import time
import time

# TODO: fix the storeCJsonFile to include mFile and iFile information. This will need to add an additional parameter
# TODO: add the count and eip to mFileJson structure

try:
    import re
except ImportError:
    raise Exception("Can't import regex library from Python std libraries")
import immlib

try:
    import debugtypes
except ImportError:
    raise Exception("Can't import debugtypes")
import immutils
import os
import sys
from datetime import datetime

imm = immlib.Debugger()

path = 'C:\\Users\\testing\\Desktop\\'
fp = 'immunity_log.txt'
filep = path + fp
fm = 'immunity_log_mem.txt'
filem = path + fm
fl = 'immunity_raw_log.txt'
filel = path + fl
fc = "immunity_log_JSON_format.txt"
filec = path + fc
singleOperandInst = {}

cFile = open(filec, "w")
cFile.close()

fmj = 'immunity_log_mem_json.txt'
filemj = path + fmj

mJFile = open(filemj, "w")
mJFile.close()

# iFile where all information will be written to
iFile = open(filep, "w")
# mFile where all memory information will be written to
mFile = open(filem, "w")
lFile = open(filel, "w")

fr1 = '1.txt'
fr2 = '2.txt'
fileR = open(path + fr1, "r")
rFile1 = fileR.readlines()
fileR2 = open(path + fr2, "r")
rFile2 = fileR2.readlines()
command1 = False
command2 = False

list1Ops0 = {'MOVSD', 'MOVSB', 'MOVSD', 'MOVSW'}
list1Ops1 = {'CMPXCHG8B', 'XSAVE', 'XSAVEC', 'XSAVEOPT'}

iFileList = []
mFileList = []

nonAUTLoops = {}
# objectives of nonAUTLoops
# nonAUTLoops = {'module-1': {'EIP': {'target':__,'counter':___}, 'module-2': { 'EIP': {'target':__, 'counter':__}}}}
autLoops = {}
# objectives of autLoops
# autLoops = { 'EIP_1': { 'target': ___, 'counter':___}, ' EIP_2': { 'target':___, 'counter':___}, }
# so search would be --> if EIP in autLoops then check autLoops['EIP_1']['target'] is it the same? it should be the same
# then add the counter. It should be added in the analyzeCurrentInst. All actions should be in the analyzeCurrentInst
# if counter >2, then we'll run instead of step.


globalSegmentSelectors = {'DS': 0, 'ES': 0, 'SS': 0}

listOfInst = {}
# listOfInst = { 'thId' : [], 'thId2' : [] }
flowRec = {}
callTypes = {'callOutAUT', 'callUnknownTarget', 'CallInAUT'}
jumpTypes = {'loopJumpInAUT', 'jumpInAUT', 'loopJumpOutAUT', 'jumpOutAUT', 'jumpUnknownTarget'}
# moduleExceptedList = {'ws2_32.dll', 'kernel32.dll', 'ntdll.dll'}

iFileJson = {"debug_messages": [], "current_status": '', "breakpoints": [], "status": '', "current_module": '',
             "current_aut": '', "Debugged_Name": '', "Debugged_path": '', "AUT_modules": [], "opCode_type": '',
             "target_aut": "", "target_verification": "", "action": "", "true_target_module": "",
             "call_target_module": "", "jmp_target": "", "target_module": "", "thread_Id": "", "eax": "", "ecx": "",
             "edx": "", "ebx": "", "esp": "", "ebp": "", "esi": "", "edi": "", "eip": "", "opCode": "", "command": "",
             "count": ""}
mFileJson = {"eip": '', "mem_change": [], "stack_change": {}, "mem_dump": [], "count": ""}

# moduleExceptedList = {'ether.dll'}
moduleExceptedList = set()

threadsOfInterest = set()


def usage(imm):
    imm.log("Program Trace Collector")
    imm.log(
        "Usage: pycomv7 <category of trace> <additional options for local category> <additional options for any category>")
    imm.log("category of trace:")
    imm.log("-l: local == default BP is Kernel32.LoadLibrary")
    imm.log("-r: remote")
    imm.log("additional options for local category:")
    imm.log("-b <bp> : additional custom breakpoint")
    imm.log("-e <module> : excepted module to treat as AUT -- default BP is Kernel32.LoadLibrary")
    imm.log("additional options for any category:")
    imm.log("-a : for all loops, add common kernel32 breakpoint symbols")
    imm.log(
        "-s < addr > : only add the common kernel32 breakpoint symbols for loops that have the same lastInstAddr as addr")
    imm.log("above order of arguments must be honoured")
    imm.log("-b switch must always be before the -e switch")
    imm.log("-e switch must always be before -a or -s switches")


def main(args):
    imm.log("pycom7 STARTED")
    imm.log("Main program trace recording script")
    imm.markBegin()
    addBPsFlag = False
    addBPsCond = False
    addBPsCondAddr = 0
    # time_allocation: total time allowed for testing in seconds (to be provided in minutes)
    time_allocation = 20*60
    if not args:
        usage(imm)
        return "PROGRAM TERMINATED IN ERROR"
    # elif len(args) == 1 and args[0] == '-l':
    #     usage(imm)
    #     return "PROGRAM TERMINATED IN ERROR"
    # elif len(args) == 2 and args[0] == '-r':
    #     usage(imm)
    #     return "PROGRAM TERMINATED IN ERROR"
    # moduleExceptedList.add(str(args[1]))
    # imm.log(str(moduleExceptedList))
    callCounter = 1
    mainThread = ''
    vulnThread = ''
    instCount = 0
    # psAUT = attachAUT()
    # if psAUT['pidAUT'] != 0:
    #     imm.Attach(psAUT['pidAUT'])
    # else:
    #     return "FATAL ERROR - TERMINATING PROGRAM - LINE 72"

    # status that will be used as main condition for while loop to continue stepping In/Over instructions
    status = imm.getStatus()
    iFileList.append("status:" + str(status) + "\n")
    # list of all modules to be able to identify which system modules are being called This will be converted to a
    # list later on.
    allModules = imm.getAllModules()
    # information about the application that is being debugged, name and path (path will be used to identify modules
    # called are within the AUT domain or not) debugged name is acquired from a ready made API, however to get path,
    # we'll get list of all processes, and use API to identify the path of each process in the list. This will give
    # us the path of our debugged application.
    debugged = dict()
    debugged = getDebugged(debugged)
    # list of AUT modules
    autModulesSet = set()
    autModulesSet = getAUTModules(autModulesSet, debugged, allModules)
    iFileList.append("Program status: " + str(status) + "\n")
    # iFile.write("Program status: " + str(status) + "\n")

    # This will be the container holding context information
    # lastState = [{'threadId': "", 'stackTop': "", 'stackBottom': "", 'ESP': "", 'memRecFlag': False,
    #               'memList': {'impact': False, 'address': "", 'content': ""}, 'lastInstAddr': 0, 'lastInstCounter': 0,
    #               'lastInstType': "", 'autLoops': {}, 'nonAUTLoops': {}, 'autModule': False, 'breakpoints': [],
    #               'bpFlag': False,
    #               'addBPsFlag': False,
    #               'addBPsCond': False,
    #               'addBPsCondAddr': 0}]

    lastState = {}

    # {'threadId': thId, 'stackTop': regs['EBP'], 'stackBottom': regs['ESP'], 'ESP': regs['ESP'],
    #  'memRecFlag': False,
    #  'memList': {'impact': False, 'address': "", 'content': ""}, 'lastInstAddr': current, 'lastInstCounter': 0,
    #  'lastInstType': "", 'autLoops': {}, 'nonAUTLoops': {}, 'autModule': True}
    #
    switchFlag = False

    currentModule = dict()
    firstRunFlag = True
    iFileList.append("**start\n")
    # iFile.write("**start\n")
    firstAUT = True
    printCounter = 0

    # review of all cases that are recorded below for the input arguments
    # * 1
    # a custom breakpoint situatoin
    # len      1  2  3    4    5      6   7
    # args     0  1  2    3    4      5   6
    # pycomv7 -l -b <bp>
    # pycomv7 -l -b <bp> -e <module>
    # pycomv7 -l -b <bp> -a
    # pycomv7 -l -b <bp> -s <addr>
    # pycomv7 -l -b <bp> -e <module> -a
    # pycomv7 -l -b <bp> -e <module> -s <addr>
    # * 2
    # len      1  2    3      4    5
    # args     0  1    2      3    4
    # pycomv7 -l -e <module>
    # pycomv7 -l -e <module> -a
    # pycomv7 -l -e <module> -s <addr>
    # * 3
    # len     1  2
    # args    0  1
    # pycomv7 -l -a
    # pycomv7 -r -a
    # * 4
    # len      1  2   3
    # args     0  1   2
    # pycomv7 -l -s <addr>
    # pycomv7 -r -s <addr>

    ####### START ########
    ###### identifying the start of the program from point of attachment ########
    if args[0] == '-r':
        # set the breakpoint
        # len      1  2   3
        # args     0  1   2
        # pycomv7 -r -a
        # pycomv7 -r -s <addr>
        kernel32CreateThreadStub = imm.setBreakpointOnName('Kernel32.CreateThread')
        imm.log("breakpoint created at : " + hex(kernel32CreateThreadStub))
        iFileList.append("breakpoint created at: " + hex(kernel32CreateThreadStub) + "\n")
        iFileJson["breakpoints"] = []
        iFileJson["breakpoints"].append(kernel32CreateThreadStub)
        iFileJson["debug_messages"] = []
        iFileJson["debug_messages"].append(
            "breakpoint created: " + str(kernel32CreateThreadStub) + " is for Kernel32.CreateThreadStub")
        iFileJson["count"] = instCount
        storeIFileJsonLog()
        if 2 <= len(args) <= 3:
            if args[1] == '-a' and len(args) == 2:
                addBPsFlag = True
            elif args[1] == '-s' and len(args) == 2:
                addBPsCond = True
                addBPsCondAddr = int(args[2])
            else:
                return "PROGORAM ERROR: INVALID ARGUMENTS, PLEASE REVIEW THE USAGE FUNCTION"

    elif args[0] == '-l':
        if len(args) > 1:
            if args[1] == '-b' and (3 <= len(args) <= 7):
                # *1
                # a custom breakpoint situatoin
                # len      1  2  3    4    5      6   7
                # args     0  1  2    3    4      5   6
                # pycomv7 -l -b <bp>
                # pycomv7 -l -b <bp> -e <module>
                # pycomv7 -l -b <bp> -a
                # pycomv7 -l -b <bp> -s <addr>
                # pycomv7 -l -b <bp> -e <module> -a
                # pycomv7 -l -b <bp> -e <module> -s <addr>
                customBreakpoint = imm.setBreakpointOnName(str(args[2]))
                imm.log("breakpoint created at : " + hex(customBreakpoint))
                iFileList.append("breakpoint created at: " + hex(customBreakpoint) + "\n")
                iFileJson["breakpoints"] = []
                iFileJson["breakpoints"].append(customBreakpoint)
                iFileJson["debug_messages"] = []
                iFileJson["debug_messages"].append("breakpoint created: " + str(customBreakpoint))
                iFileJson["count"] = instCount
                if len(args) >= 4:
                    if args[3] == '-e' and (4 <= len(args) <= 7):
                        # subset of above
                        # additional excepted module should be included
                        if args[4] not in moduleExceptedList:
                            iFileJson["debug_messages"].append("exceptedModuleAddition: " + str(args[5]))
                            moduleExceptedList.add(str(args[5]))
                        else:
                            imm.log("excepted module already in exceptedModuleList")
                        if 6 <= len(args) <= 7:
                            if args[5] == '-a':
                                addBPsFlag = True
                            elif args[5] == '-s':
                                addBPsCond = True
                                addBPsCondAddr = int(args[6])
                    elif args[3] == '-a':
                        addBPsFlag = True
                    elif args[3] == '-s':
                        addBPsCond = True
                        addBPsCondAddr = int(args[4])
                    else:
                        imm.log(
                            "Error in supplied arguments, please refer to usage by typing name of the script and pressig enter")
                        return "PROGRAM TERMINATED IN ERROR"
                    storeIFileJsonLog()
            elif args[1] == '-e' and (3 <= len(args) <= 5):
                # *2
                # len      1  2    3      4    5
                # args     0  1    2      3    4
                # pycomv7 -l -e <module>
                # pycomv7 -l -e <module> -a
                # pycomv7 -l -e <module> -s <addr>
                if args[2] not in moduleExceptedList:
                    moduleExceptedList.add(str(args[2]))
                    imm.log("setting the close breakpoint to Kernel32.LoadLibraryA")
                    # kernel32LoadLibraryA = imm.setBreakpointOnName('Kernel32.LoadLibraryA')
                    # kernel32LoadLibrary = imm.setBreakpointOnName('KernelBase.LoadLibraryExW')
                    kernel32LoadLibrary = imm.setBreakpointOnName('Kernel32.LoadLibraryA')
                    imm.log("breakpoint created at : " + hex(kernel32LoadLibrary))
                    iFileList.append("breakpoint crated at: " + hex(kernel32LoadLibrary) + "\n")
                    iFileJson["breakpoints"] = []
                    iFileJson["breakpoints"].append(kernel32LoadLibrary)
                    iFileJson["debug_messages"] = []
                    iFileJson["debug_messages"].append(
                        "breakpoint created: " + str(kernel32LoadLibrary) + " is for Kernel32.LoadLibraryA")
                    iFileJson["debug_messages"].append("exceptedModuleAddition: " + str(args[2]))
                    iFileJson["count"] = instCount
                    storeIFileJsonLog()
                else:
                    imm.log("excepted module already in the exceptedModuleList")
                if args[3] == '-a' and len(args) == 4:
                    # len      1  2  3    4
                    # args     0  1  2    3
                    # pycomv7 -l -b <bp> -a
                    addBPsFlag = True
                elif args[3] == '-s' and len(args) == 5:
                    # len      1  2  3    4   5
                    # args     0  1  2    3   4
                    # pycomv7 -l -b <bp> -s <addr>
                    addBPsCond = True
                    addBPsCondAddr = int(args[4])
                else:
                    imm.log("this is an error")
                    imm.log("Please review the usage function")
                    return "PROGRAM ENDED BECAUSE OF WRONG ARGUMENT STRUCTURE"

            elif args[1] == '-a' and len(args) == 2:
                # * 3
                # len     1  2
                # args    0  1
                # pycomv7 -l -a
                # pycomv7 -r -a
                addBPsFlag = True
            elif args[1] == '-s' and len(args) == 3:
                # * 4
                # len      1  2   3
                # args     0  1   2
                # pycomv7 -l -s <addr>
                # pycomv7 -r -s <addr>
                addBPsCond = True
                addBPsCondAddr = int(args[4])
            else:
                imm.log(
                    "Error in supplied arguments, please refer to Usage by typing name of script and pressing enter")
                return "PROGRAM TERMINATED IN ERROR DUE TO ARGUMENT LIST"
        else:
            imm.log("setting the close breakpoint to Kernel32.LoadLibraryA")
            # kernel32LoadLibraryA = imm.setBreakpointOnName('Kernel32.LoadLibraryA')
            # kernel32LoadLibrary = imm.setBreakpointOnName('KernelBase.LoadLibraryExW')
            kernel32LoadLibrary = imm.setBreakpointOnName('Kernel32.LoadLibraryA')
            imm.log("breakpoint created at : " + hex(kernel32LoadLibrary))
            iFileList.append("breakpoint crated at: " + hex(kernel32LoadLibrary) + "\n")
            iFileJson["breakpoints"] = []
            iFileJson["breakpoints"].append(kernel32LoadLibrary)
            iFileJson["debug_messages"] = []
            iFileJson["debug_messages"].append(
                "breakpoint created: " + str(kernel32LoadLibrary) + " is for Kernel32.LoadLibraryA")
            iFileJson["count"] = instCount
            storeIFileJsonLog()
    else:
        imm.log("non-valid argument passed to program")
        return "PROGRAM ENDED"
    # kernel32BaseThreadInitThunkAddr = imm.setBreakpointOnName('Kernel32.BaseThreadInitThunk')
    # imm.log("breakpoint created at : "+hex(kernel32BaseThreadInitThunkAddr))
    # iFileList.append("breakpoint created at: "+hex(kernel32BaseThreadInitThunkAddr)+"\n")

    imm.run()
    continueFlag = True
    payloadFlag = False
    while continueFlag:
        regs = imm.getRegs()
        current = imm.getCurrentAddress()
        opCode = imm.disasm(current)
        command = opCode.getDisasm()
        if status == 1:
            threadsOfInterest.add(str(imm.getThreadId()))
            if args[0] == '-r':
                imm.deleteBreakpoint(kernel32CreateThreadStub)
                iFileList.append("breakpoint deleted at: " + hex(kernel32CreateThreadStub) + "\n")
                iFileJson["debug_messages"] = []
                iFileJson["debug_messages"].append(
                    "breakpoint deleted: " + str(kernel32CreateThreadStub) + " is for Kernel32.CreateThreadStub")
                imm.log("breakpoint deleted at : " + hex(kernel32CreateThreadStub))
            elif args[0] == '-l' and (2 <= len(args) <= 7 ):
                if args[1] == '-b':
                    imm.deleteBreakpoint(customBreakpoint)
                    iFileList.append("breakpoint deleted at: " + hex(customBreakpoint) + "\n")
                    iFileJson["debug_messages"] = []
                    iFileJson["debug_messages"].append("breakpoint deleted: " + str(customBreakpoint))
                    imm.log("breakpoint deleted at: " + hex(customBreakpoint))
                elif args[1] == '-e':
                    moduleExceptedList.add(str(args[2]))
                    imm.deleteBreakpoint(kernel32LoadLibrary)
                    iFileList.append("breakpoint deleted at: " + hex(kernel32LoadLibrary) + "\n")
                    iFileJson["debug_messages"] = []
                    iFileJson["debug_messages"].append(
                        "breakpoint deleted: " + str(kernel32LoadLibrary) + " is for Kernel32.CreateThreadStub")
                    imm.log("breakpoint deleted at : " + hex(kernel32LoadLibrary))
            elif args[0] == '-l':
                imm.deleteBreakpoint(kernel32LoadLibrary)
                iFileList.append("breakpoint deleted at: " + hex(kernel32LoadLibrary) + "\n")
                iFileJson["debug_messages"] = []
                iFileJson["debug_messages"].append(
                    "breakpoint deleted: " + str(kernel32LoadLibrary) + " is for Kernel32.CreateThreadStub")
                imm.log("breakpoint deleted at : " + hex(kernel32LoadLibrary))
            mainThread = str(imm.getThreadId())
            iFileList.append("main thread is : " + mainThread + "\n")
            iFileJson["debug_messages"].append({"main_thread": mainThread})
            if not payloadFlag:
                # executePayload(psAUT['pidAUT'])
                payloadFlag = True
                continueFlag = False
            # that means that the program currently stopped
            # right now, it could be one of the following reasons;
            # 1. Just attached to the process
            # 2. in the middle of runs between BP Kernel32
            #
            # startTracingFlag = checkProgTrace(current, regs, autModulesSet)
            # if startTracingFlag:
            #     continueFlag = False
            # else:
            #     imm.run()
            #
        status = imm.getStatus()
        imm.log("status: " + str(status))

    if args[0] == '-r':
        kernel32BaseThreadInitThunkAddr = imm.setBreakpointOnName('Kernel32.BaseThreadInitThunk')
        imm.log("breakpoint created at : " + hex(kernel32BaseThreadInitThunkAddr))
        iFileList.append("breakpoint created at: " + hex(kernel32BaseThreadInitThunkAddr) + "\n")
        iFileJson["breakpoints"] = []
        iFileJson["breakpoints"].append(str(kernel32BaseThreadInitThunkAddr))
        iFileJson["debug_messages"].append(
            "breakpoint created: " + str(kernel32BaseThreadInitThunkAddr) + " is for Kernel32!BaseThreadInitThunk")
        iFileJson["count"] = instCount
        storeIFileJsonLog()
        imm.run()
    else:
        kernel32BaseThreadInitThunkAddr = 0

    loopStatusFlag = False
    startTracingFlag = False
    stepOverFlag = False
    # alienThreadCounter = 0
    # status:
    # 0: NONE
    # 1: STOPPED
    # 2: EVENT
    # 3: RUNNING
    # 4: FINISHED
    # 5: CLOSING
    try:
        statusThreeCounter = 0
        threadChangeFlag = False
        setOfBreakpoints = set()
        payloadAddr = 0
        if payloadAddr != 0:
            imm.setTemporaryBreakpoint(payloadAddr, continue_execution=True, stoptrace=False)
            # imm.setBreakpoint(payloadAddr)
        currentTime = datetime.now()
        while status != 4 or status != 5:
            # THE BELOW IS FOR ADDRESSING THE LOOP OF STATUS 3
            testTime = datetime.now()
            diffMin2Sec = (testTime.minute - currentTime.minute) * 60
            diffSec = testTime.second - currentTime.second
            diffTotal = diffMin2Sec + diffSec
            if diffTotal >= time_allocation:
                iFileList.append("execution time: " + str(imm.markEnd()) + "seconds \n")
                iFilePrint()
                mFilePrint()
                mFile.close()
                iFile.close()
                imm.log("last status: " + str(imm.getStatus()))
                return "PROGRAM TERMINATED BECAUSE ALLOCATED TEST TIME ENDED"
            instCount += 1
            dumpFlag = False
            if status == 3:
                status = imm.getStatus()
                # if statusThreeCounter == 100000*100:
                # statusThreeCounter += 1
                if statusThreeCounter == 0:
                    imm.log("PROGRAM LOCKED IN THE RUN STATE")
                    iFileList.append("PROGRAM LOCKED IN THE RUN STATE, PERHAPS WAITING FOR AN EVENT\n")
                    imm.log("action: PAUSE")
                    iFileList.append("==> action: PAUSE\n")
                    imm.pause()
                    if not threadChangeFlag:
                        bps = getKernelBPs()
                        for bp in bps:
                            imm.setBreakpoint(int(bp))
                        # kernel32GetExitCodeThread = imm.setBreakpointOnName('Kernel32.GetExitCodeThread')
                        # kernel32GetCurrentThreadId = imm.setBreakpointOnName('Kernel32.GetThreadId')
                        # kernel32CurrentProcess = imm.setBreakpointOnName('Kernel32.GetCurrentProcess')
                        # # kernel32WaitForSingleObject = imm.setBreakpointOnName('Kernel32.WaitForSingleObject')
                        # # kernel32SetEvent = imm.setBreakpointOnName('Kernel32.SetEvent')
                        # # kernel32ResetEvent = imm.setBreakpointOnName('Kernel32.ResetEvent')
                        # # setOfBreakpoints = {kernel32GetExitCodeThread, kernel32GetCurrentThreadId, kernel32CurrentProcess,
                        # # kernel32WaitForSingleObject, kernel32SetEvent, kernel32ResetEvent}
                        # setOfBreakpoints = {kernel32GetExitCodeThread, kernel32GetCurrentThreadId,
                        #                     kernel32CurrentProcess}
                        threadChangeFlag = True
                        iFileList.append("--> action: RUN\n")
                        iFileJson["debug_messages"].append("created a threadChange breakpoint.")
                        imm.run()
                # statusThreeCounter += 1
                continue

            # THE BELOW IS FOR ADDRESSING THE DEMO RUNS

            # if tempCounter == 1000:
            #     iFileList.append("execution time: " + str(imm.markEnd()) + "seconds \n")
            #     # iFile.write("execution time: " + str(imm.markEnd()) + "seconds \n")
            #     iFilePrint()
            #     mFilePrint()
            #     del iFileList[0:len(iFileList)]
            #     del mFileList[0:len(mFileList)]
            #     imm.log("iFileList:" + str(iFileList))
            #     imm.log("mFileList:" + str(mFileList))
            #     mFile.close()
            #     iFile.close()
            #     return "PROGRAM TERMINATED FOR DEMO PURPOSES"
            # tempCounter += 1

            # if printCounter == 5:
            #     iFilePrint()
            #     mFilePrint()
            #     del iFileList[0:len(iFileList)]
            #     del mFileList[0:len(mFileList)]
            #     printCounter = 0
            # else:
            #     printCounter += 1

            iFileJson["status"] = str(status)
            iFileJson["count"] = instCount
            mFileJson["count"] = instCount

            iFileList.append("##\n")
            # iFile.write("##\n")  # in iFile this signifies a new instruction will begin
            thId = imm.getThreadId()
            regs = imm.getRegs()
            current = imm.getCurrentAddress()
            opCode = imm.disasm(current)
            command = opCode.getDisasm()
            printRegs(thId, regs, current, opCode, command)
            mFileJson["eip"] = str(regs["EIP"]).rstrip("L")

            # BELOW IS FOR ADDING A BREAKPOINT FOR VULNERABLE THREAD
            kernel32GetExitCodeThread = 0
            if current == kernel32BaseThreadInitThunkAddr:
                threadsOfInterest.add(str(thId))
                imm.deleteBreakpoint(kernel32BaseThreadInitThunkAddr)
                vulnThread = str(thId)
                iFileList.append("vulnerable thread: " + vulnThread + "\n")
                iFileJson["debug_messages"].append("breakpoint deleted at: " + str(
                    kernel32BaseThreadInitThunkAddr) + " which is Kernel32!BaseThreadInitThunk")
                iFileJson["debug_messages"].append({"vulnThread": str(thId)})

            # if current == kernel32GetExitCodeThread:
            #     #TODO: add check to make sure that main vulnerable thread didn't exit.
            #     imm.deleteBreakpoint(kernel32GetExitCodeThread)

            # THE BELOW IS FOR AVOIDING JUMPING INTO NON-AUT MODULES WITH BREAKPOINT AT KERNEL32.BASETHREADINITTHUNK
            # if current == kernel32BaseThreadInitThunkAddr:
            #     imm.log("jumped to new thread...")
            #     iFileList.append("new thread detected\n")
            #     startTracingFlag = checkProgTrace(current, iFileList, command, regs, autModulesSet)
            #     if not startTracingFlag:
            #         imm.log("new thread doesn't launch an AUT")
            #         iFileList.append("new thread doesn't launch an AUT\n")
            #         imm.run()
            #         status = imm.getStatus()
            #         continue
            #     else:
            #         imm.log("new thread will launch an AUT")
            #         iFileList.append("new thread will launch an AUT\n")
            if str(thId) not in threadsOfInterest:
                iFileList.append("thId:" + str(thId) + " is not within threads of interest\n")
                iFileJson["debug_messages"].append("thId: " + str(thId) + " is not within threads of interest")
                iFileJson["current_status"] = str(status)
                iFileJson["count"] = instCount
                storeIFileJsonLog()
                imm.log("wrong thread")
                imm.run()
                status = imm.getStatus()
                continue
            else:
                if threadChangeFlag:
                    bps = getKernelBPs()
                    for bp in bps:
                        imm.deleteBreakpoint(int(bp))
                        imm.log("deleted: " + str(bp))
                        iFileList.append("deleted breakpoint: " + str(bp) + "\n")
                        iFileJson["debug_messages"].append(
                            "deleted breakpoint: " + str(bp) + " part of setOfBreakpoints")
                    threadChangeFlag = False
            # if current == payloadEIP:
            #     imm.deleteBreakpoint(payloadEIP)
            #     imm.log("deleted payloadEIP_malicious payload started")
            #     iFileJson["debug_messages"].append("deleted payloadEIP..we just started the malicious payload")
            if str(thId) in listOfInst:
                listOfInst[str(thId)].append(current)
            else:
                listOfInst[str(thId)] = [current]
            iFileList.append("acquiring current module -- calling getModuleByAddr \n")
            currentModule = getModuleByAddr(regs['EIP'], autModulesSet)
            iFileList.append("current_module:" + str(currentModule['name']) + "\n")
            iFileJson["current_module"] = str(currentModule['name'])
            if currentModule['aut']:
                iFileList.append("current_aut:True\n")
                iFileJson["current_aut"] = "True"
                # iFile.write("current_aut:True\n")
                if firstAUT:
                    firstAUT = False
                    lastState = {str(thId): {'ESP': regs['ESP'], 'memRecFlag': False,
                                             'memList': {'impact': False, 'address': "", 'content': ""},
                                             'lastInstAddr': current,
                                             'lastInstCounter': 0,
                                             'lastInstType': "", 'autLoops': {}, 'nonAUTLoops': {}, 'autModule': True,
                                             'breakpoints': [],
                                             'bpFlag': False,
                                             'addBPsFlag': addBPsFlag,
                                             'addBPsCond': addBPsCond,
                                             'addBPsCondAddr': addBPsCondAddr}}
                    evaluateSegmentSelectors(thId, regs)
                    dumpMemory()
                    lastState = analyzeCurrentInst(opCode, lastState, autModulesSet, command, regs, current, thId, args,
                                                   callCounter)
                else:
                    # step1.1: check if we're on the same thread, yes --> proceed, no --> TERMINATE Program
                    # if moduleExceptedList:
                    #     moduleExceptedList.clear()
                    if str(thId) not in lastState:
                        lastState[str(thId)] = {'ESP': regs['ESP'], 'memRecFlag': False,
                                                'memList': {'impact': False, 'address': "", 'content': ""},
                                                'lastInstAddr': current,
                                                'lastInstCounter': 0,
                                                'lastInstType': "", 'autLoops': {}, 'nonAUTLoops': {},
                                                'autModule': True,
                                                'breakpoints': [],
                                                'bpFlag': False,
                                                'addBPsFlag': addBPsFlag,
                                                'addBPsCond': addBPsCond,
                                                'addBPsCondAddr': addBPsCondAddr}
                    coreThreadWordResult = coreThreadWork(lastState, current, opCode, command,
                                                          switchFlag, loopStatusFlag,
                                                          dumpFlag, regs, autModulesSet, thId, args, callCounter)
                    lastState = coreThreadWordResult['lastState']
                    loopStatusFlag = coreThreadWordResult['loopStatusFlag']
                    switchFlag = coreThreadWordResult['switchFlag']
            else:
                switchFlag = True
                iFileList.append("current_aut:False\n")
                iFileJson["current_aut"] = "False"
                if str(thId) not in lastState:
                    lastState[str(thId)] = {'ESP': regs['ESP'], 'memRecFlag': False,
                                            'memList': {'impact': False, 'address': "", 'content': ""},
                                            'lastInstAddr': current,
                                            'lastInstCounter': 0,
                                            'lastInstType': "", 'autLoops': {}, 'nonAUTLoops': {}, 'autModule': True,
                                            'breakpoints': [],
                                            'bpFlag': False,
                                            'addBPsFlag': addBPsFlag,
                                            'addBPsCond': addBPsCond,
                                            'addBPsCondAddr': addBPsCondAddr}
                coreThreadWordResult = coreThreadWork(lastState, current, opCode, command,
                                                      switchFlag, loopStatusFlag, dumpFlag, regs, autModulesSet, thId,
                                                      args, callCounter)
                lastState = coreThreadWordResult['lastState']
                loopStatusFlag = coreThreadWordResult['loopStatusFlag']
                switchFlag = coreThreadWordResult['switchFlag']
            hangFlag = hangDetector(current, thId)
            if hangFlag:
                break
            status = imm.getStatus()
            imm.log("Status: " + str(status))
            iFileList.append("status:" + str(status) + "\n")
            iFileJson["status"] = str(status)
            iFileJson["count"] = instCount
            storeIFileJsonLog()
            storeMFileJsonLog()
            iFilePrint()
            mFilePrint()
            del iFileList[0:len(iFileList)]
            del mFileList[0:len(mFileList)]
    except:
        iFileList.append("execution time: " + str(imm.markEnd()) + "seconds \n")
        iFileList.append(str(sys.exc_info()))
        iFilePrint()
        mFilePrint()
        mFile.close()
        iFile.close()
        return "PROGRAM EXCEPTIONALLY TERMINATED"
    iFileList.append("execution time: " + str(imm.markEnd()) + "seconds \n")
    iFilePrint()
    mFilePrint()
    mFile.close()
    iFile.close()
    imm.log("last status: " + str(imm.getStatus()))
    return "PROGRAM SUCCESSFULLY TERMINATED - LINE 252"


def storeMFileJsonLog():
    if mFileJson["mem_change"] or mFileJson["stack_change"] or mFileJson["mem_dump"]:
        mJFile = open(filemj, "a")
        mJFile.write(str(mFileJson))
        mJFile.write("\n")
        mJFile.close()
        mFileJson["eip"] = ""
        mFileJson["mem_change"] = []
        mFileJson["stack_change"] = {}
        mFileJson["mem_dump"] = []
        mFileJson["count"] = ""
    return "mFileJson reset"


def storeIFileJsonLog():
    cFile = open(filec, "a")
    cFile.write(str(iFileJson))
    cFile.write("\n")
    cFile.close()
    iFileJson["debug_messages"] = []
    iFileJson["current_status"] = ''
    iFileJson["breakpoints"] = []
    iFileJson["status"] = ""
    iFileJson["current_module"] = ""
    iFileJson["current_aut"] = ""
    iFileJson["Debugged_Name"] = ""
    iFileJson["Debugged_path"] = ""
    iFileJson["AUT_modules"] = []
    iFileJson["opCode_type"] = ""
    iFileJson["target_aut"] = ""
    iFileJson["target_verification"] = ""
    iFileJson["action"] = ""
    iFileJson["true_target_module"] = ""
    iFileJson["call_target_module"] = ""
    iFileJson["jmp_target"] = ""
    iFileJson["target_module"] = ""
    iFileJson["thread_Id"] = ""
    iFileJson["eax"] = ""
    iFileJson["ecx"] = ""
    iFileJson["edx"] = ""
    iFileJson["ebx"] = ""
    iFileJson["esp"] = ""
    iFileJson["ebp"] = ""
    iFileJson["esi"] = ""
    iFileJson["edi"] = ""
    iFileJson["eip"] = ""
    iFileJson["opCode"] = ""
    iFileJson["command"] = ""
    iFileJson["count"] = ""
    return "iFileJson reset"


def coreThreadWork(lastState, current, opCode, command, switchFlag, loopStatusFlag, dumpFlag, regs,
                   autModulesSet, thId, args, callCounter):
    thId = str(thId)
    if lastState[thId]['lastInstType'] == 'callOutAUT':
        dumpMemory()
        dumpFlag = True
    if switchFlag:
        switchFlag = False
        lastState[thId]['autModule'] = True
    if loopStatusFlag:
        for bp in lastState[thId]["breakpoints"]:
            if bp == current:
                iFileJson["debug_messages"].append("current address matches a breakpoint")
                loopStatusFlag = False
                deleteBreakpoints(lastState, thId)
                if not dumpFlag:
                    dumpMemory()
                lastState = analyzePrevInst(lastState, thId, regs)
                lastState = analyzeCurrentInst(opCode, lastState, autModulesSet, command, regs, current, thId, args,
                                               callCounter)
                break
        if loopStatusFlag:
            # if this instruction is reached that means that we stopped but not on the breakpoint
            iFileList.append("Error --- Anomaly Detected 756\n")
            imm.log("Error -- anomaly detected 757")
            iFileJson["debug_messages"].append(
                "Error - anomaly detected, should be stopped by breakpoint but this is not the case")
            # iFileJson["action"] = "run"
            # iFileJson["opCode_type"] = "N/A"
            # imm.run()
            loopStatusFlag = True
            lastState = analyzePrevInst(lastState, thId, regs)
            lastState = analyzeCurrentInst(opCode, lastState, autModulesSet, command, regs, current, thId, args,
                                           callCounter)
        return {'lastState': lastState, 'loopStatusFlag': loopStatusFlag,
                'switchFlag': switchFlag}
    else:
        loopStatusFlag = loopStatusCheck(lastState, current, thId)
        if loopStatusFlag:
            # this is a loop
            lastState[thId]['breakpoints'] = getBreakpoints(lastState, autModulesSet, thId)
            if lastState[thId]['breakpoints']:
                createBreakpoints(lastState, thId)
                iFileJson["debug_messages"].append("breakpoints created")
                iFileJson["action"] = "run"
                iFileJson["opCode_type"] = "N/A"
                imm.run()
            else:
                loopStatusFlag = False
                lastState = analyzePrevInst(lastState, thId, regs)
                lastState = analyzeCurrentInst(opCode, lastState, autModulesSet, command, regs,
                                               current, thId, args, callCounter)
        else:
            lastState = analyzePrevInst(lastState, thId, regs)
            lastState = analyzeCurrentInst(opCode, lastState, autModulesSet, command, regs, current, thId, args,
                                           callCounter)
    return {'lastState': lastState, 'loopStatusFlag': loopStatusFlag,
            'switchFlag': switchFlag}


def createBreakpoints(lastState, thId):
    iFileList.append("Following breakpoints to be created:\n")
    imm.log("breakpoints created")
    iFileJson["debug_messages"].append("breakpoints will be created")
    insertFlag = False
    if lastState[str(thId)]['addBPsCond']:
        if lastState['addBPsCondAddr'] == lastState[str(thId)]['lastInstAddr']:
            imm.log("add the actual list")
            # this means that I should insert additional breakpoints
            insertFlag = True
    elif lastState[str(thId)]['addBPsFlag']:
        imm.log("this is placeholder to add additional breakpoints")
        # this means that I should insert additional breakpoints
        insertFlag = True
    if insertFlag:
        kernelBPs = getKernelBPs()
        for bp in kernelBPs:
            lastState[str(thId)]['breakpoints'].append(int(bp))
        iFileList.append("Added list of kernelBPs: " + str(kernelBPs) + "\n")
    for bp in lastState[str(thId)]['breakpoints']:
        imm.setBreakpoint(bp)
        iFileList.append(hex(bp) + "--")
        iFileJson["breakpoints"].append(str(bp))
    return "createBreakpoints Finished"


def getKernelBPs():
    imm.log("this is a placeholder for kernelBPs")
    # file structure
    # Duration: 60
    # (18, 'Kernel32.InterlockedIncrement:1966543872')
    # ....
    intKernelBPs = []
    symFreqPath = "C:\\Users\\testing\\Desktop\\symbols_freq.txt"
    fileHandle = open(symFreqPath, "r")
    count = 0
    for line in fileHandle:
        if count == 0:
            count += 1
            continue
        result = re.search('(?<=:)\d+', line)
        if result is not None:
            imm.log("result: "+str(int(result.group(0))))
            intKernelBPs.append(int(result.group(0)))
    return intKernelBPs


def deleteBreakpoints(lastState, thId):
    thId = str(thId)
    iFileList.append("Following breakpoints will be deleted:\n")
    imm.log("breakpoints deleted")
    for bp in lastState[thId]['breakpoints']:
        imm.deleteBreakpoint(bp)
        iFileList.append(hex(bp) + "--")
        iFileJson["debug_messages"].append("breakpoints to be deleted: " + str(bp))
    del lastState[thId]['breakpoints'][0:len(lastState[thId]['breakpoints'])]
    return "deleteBreakpoints Finished"


def getBreakpoints(lastState, autModulesSet, thId):
    # first I want to know what type of loop, i.e. does the jump target point out of the loop or inside the loop?
    # to get this information, I need to get the loop boundaries
    # 1) get loop boundaries
    # 2) get the control flow instructions within the loop boundaries
    # 3) any control flow instruction that points outside of the loop boundaries should be set as breakpoint
    # 3.1) control flow instructions within the loop could be either - (a) seen before or (b) new
    # the way nextAddr is being used, it assumes that the LOOP HEAD is the jump instruction. But what if it is the call instruction?
    thId = str(thId)
    controlInst = lastState[thId]['lastInstAddr']
    loopListReverse = []
    iFileList.append("Started searching for breakpoints\n")
    imm.log(str(listOfInst[thId]))
    iFileList.append("listOfInst : " + str(listOfInst[thId]) + "\n")
    imm.log("len(listOfInst[thId]:" + str(len(listOfInst[thId])))
    for x in range(len(listOfInst[thId]) - 2, 0, -1):
        if listOfInst[thId][x - 1] == controlInst:
            loopListReverse.append(listOfInst[thId][x - 1])
            break
        else:
            loopListReverse.append(listOfInst[thId][x - 1])
    iFileList.append("Loop list aggregated\n")
    for ip in loopListReverse:
        iFileList.append(hex(ip) + " " + str((imm.disasm(ip)).getDisasm()) + "\n")
        prevInst = str(ip)
        if prevInst in flowRec[thId]:
            flowRec[thId][prevInst]['targetCounter'] = 0
            if 'otherCounter' in flowRec[thId][prevInst]:
                flowRec[thId][prevInst]['otherCounter'] = 0
    iFileList.append("Finished dumping aggregated Loop List\n")
    # not applying the limit check of 15 lines and type of call/jump instructions.
    # if lengthOfLoop = 14 is commented uncomment the following line.
    # lengthOfLoop = len(loopListReverse)
    lengthOfLoop = 14
    if lengthOfLoop > 15:
        # loop is too big to skip, high chance of errors
        controlFlowSafetyFlag = checkControlFlow(loopListReverse)
        # controlFlowSafetyFlag = False
        if controlFlowSafetyFlag:
            return getBreakpoints_(loopListReverse, controlInst, autModulesSet, thId)
        else:
            iFileList.append("Loop is too big to skip, high chance of errors\n")
            return []
    else:
        # loop is not too big and I can continue
        return getBreakpoints_(loopListReverse, controlInst, autModulesSet, thId)


def checkControlFlow(loopListReverse):
    # objective is to check if there is any instructions that use registers. If not, we can accept the large loop.
    for ip in loopListReverse:
        opCode = imm.disasm(ip)
        command = opCode.getDisasm()
        if opCode.isCall() or opCode.isJmp() or opCode.isConditionalJmp():
            result = re.search('EAX|ECX|EDX|EBX|ESP|EBP|ESI|EDI|EIP', command)
            if result is not None:
                return False
    return True


def getBreakpoints_(loopListReverse, controlInst, autModulesSet, thId):
    breakpointsSet = set()
    thId = str(thId)
    try:
        nextOpCode = imm.disasmForward(controlInst)
    except:
        try:
            opCode = imm.disasm(controlInst)
            opCodeSize = opCode.getSize()
            nextAddr = controlInst + opCodeSize
            nextOpCode = imm.disasm(nextAddr)
        except:
            imm.log("Failed to get nextOpCode")
            iFileJson["debug_messages"].append("Failed to get nextOpCode")
            return []
    imm.log("nextOpCode: " + str(nextOpCode))
    nextAddr = nextOpCode.getAddress()
    forLoopFlag = False
    for inst in loopListReverse:
        opCode = imm.disasm(inst)
        command = opCode.getDisasm()
        regs = imm.getRegs()
        targetAddress = 0
        otherAddress = -1
        iFileList.append(hex(inst) + " " + str(command) + "\n")
        if inst == nextAddr:
            iFileList.append("the next address is part of the loop\n")
            forLoopFlag = True
        if opCode.isCall():
            # iFileList.append("call inst address: " + hex(inst) + "\n")
            # placeholder for call
            # get call traget address
            # if call target address is outside of scope of loopList then create a breakpoint
            # first check if it is already in the list of control flow instructions
            if str(inst) in flowRec[thId]:
                iFileList.append("call recorded before\n")
                # this address was seen before
                if flowRec[thId][str(inst)]['type'] == 'callInAUT':
                    iFileList.append("call_type: callInAUT\n")
                    targetAddress = flowRec[thId][str(inst)]['targetBranch']
                    iFileList.append("call_target: " + hex(targetAddress) + "\n")
                elif flowRec[thId][str(inst)]['type'] == 'callOutAUT':
                    iFileList.append("call_type: callOutAUT\n")
            else:
                # placeholder
                # this address wasn't seen before
                # I need to check if command contains any regs if it does then I should discard this loop
                iFileList.append("call not present in history\n")
                result = re.search('EAX|ECX|EDX|EBX|ESP|EBP|ESI|EDI|EIP', command)
                if result is None:
                    targetAddress = getFuncTarget(opCode, command, regs, 'call')
                else:
                    iFileList.append("call target is dependent on registers\n")
                    return []
        elif opCode.isJmp() or opCode.isConditionalJmp():
            if str(inst) in flowRec[thId]:
                iFileList.append("jump recorded before\n")
                if flowRec[thId][str(inst)]['type'] == 'jumpInAUT':
                    targetAddress = flowRec[thId][str(inst)]['targetBranch']
                    iFileList.append("jump_type: jumpInAUT\n")
                    iFileList.append("jump_target: " + hex(targetAddress) + "\n")
                    if opCode.isConditionalJmp():
                        otherAddress = flowRec[thId][str(inst)]['otherBranch']
                        iFileList.append("next_addr: " + hex(otherAddress) + "\n")
            else:
                iFileList.append("Jump instruction wasn't found in historical record\n")
                targetAddress = opCode.getJmpAddr()
                if targetAddress == 0:
                    iFileList.append("jump instruction is complex and can't be analyzed by Immunity Debugger\n")
                    result = re.search('EAX|ECX|EDX|EBX|ESP|EBP|ESI|EDI|EIP', command)
                    if result is not None:
                        iFileList.append("attempting to get the jump target\n")
                        targetAddress = getFuncTarget(opCode, command, regs, 'jump')
                        targetModule = getModuleByAddr(targetAddress, autModulesSet)
                        if not targetModule['aut']:
                            iFileList.append("jump target is not an AUT module\n")
                            targetAddress = 0
                    else:
                        iFileList.append("Jump target contains registers and can't be identified\n")
                        return []
        else:
            continue
        if otherAddress != -1:
            if (targetAddress in loopListReverse or targetAddress == 0) and (
                    otherAddress != 0 and otherAddress in loopListReverse):
                continue
            elif (targetAddress in loopListReverse or targetAddress == 0) and (
                    otherAddress != 0 and otherAddress not in loopListReverse):
                iFileList.append("otherBranch is not within the loop and points to: " + hex(otherAddress) + "\n")
                breakpointsSet.add(int(otherAddress))
            elif (targetAddress in loopListReverse or targetAddress == 0) and (otherAddress == 0):
                continue
            else:
                # targetAddress is not within the loop
                iFileList.append("target is out of the loop body targeting: " + hex(targetAddress) + "\n")
                breakpointsSet.add(int(targetAddress))
        else:
            if targetAddress in loopListReverse or targetAddress == 0:
                continue
            else:
                iFileList.append("target is out of the loop body targeting: " + hex(targetAddress) + "\n")
                breakpointsSet.add(int(targetAddress))
    if not forLoopFlag:
        breakpointsSet.add(int(nextAddr))
    breakpoints = list(breakpointsSet)
    iFileList.append("breakpoints: \n")
    iFileList.append(str(breakpoints) + "\n")
    return breakpoints


def loopStatusCheck(lastState, current, thId):
    imm.log("entered into loopStatusCheck")
    thId = str(thId)
    prevInst = lastState[thId]['lastInstAddr']
    prevInst = str(prevInst)
    iFileList.append("prevInst: " + prevInst + "\n")
    iFileList.append("lastState[thId][lastInstType]: " + str(lastState[thId]['lastInstType']) + "\n")
    if lastState[thId]['lastInstType'] in callTypes:
        if flowRec[thId][prevInst]['targetCounter'] > 1:
            imm.log("if cond: 1033")
            flowRec[thId][prevInst]['targetCounter'] = 0
            iFileList.append("Loop detected\n")
            iFileJson["debug_messages"].append("Loop Detected")
            return True
        else:
            imm.log("else cond: 1039")
            flowRec[thId][prevInst]['targetCounter'] += 1
            return False
    elif lastState[thId]['lastInstType'] in jumpTypes:
        imm.log("elif cond: 1043")
        iFileList.append("type of control flow: " + str(lastState[thId]['lastInstType'] + "\n"))
        iFileList.append(
            "flowRec[thId][prevInst][targetBranch]: " + hex(flowRec[thId][prevInst]['targetBranch']) + "\n")
        iFileList.append("current: " + hex(current) + "\n")
        if flowRec[thId][prevInst]['targetBranch'] == current:
            imm.log("if cond: 1049")
            iFileList.append("current matched\n")
            iFileList.append("targetCounter is present in flowRec[thId][prevInst]\n")
            iFileList.append("targetCounter: " + str(flowRec[thId][prevInst]['targetCounter']) + "\n")
            if flowRec[thId][prevInst]['targetCounter'] > 1:
                imm.log("if cond: 1054")
                flowRec[thId][prevInst]['targetCounter'] = 0
                iFileList.append("Loop detected\n")
                iFileJson["debug_messages"].append("Loop Detected")
                return True
            else:
                imm.log("else cond: 1060")
                iFileList.append("targetCounter < 2\n")
                flowRec[thId][prevInst]['targetCounter'] += 1
                iFileList.append("targetCounter is : " + str(flowRec[thId][prevInst]['targetCounter']) + "\n")
                return False
        elif flowRec[thId][prevInst]['otherBranch'] == current:
            imm.log("elif cond: 1066")
            if flowRec[thId][prevInst]['otherCounter'] > 1:
                imm.log("if cond: 1068")
                flowRec[thId][prevInst]['otherCounter'] = 0
                iFileList.append("Loop detected\n")
                iFileJson["debug_messages"].append("Loop Detected")
                return True
            else:
                imm.log("else cond: 1074")
                flowRec[thId][prevInst]['otherCounter'] += 1
                return False
        elif flowRec[thId][prevInst]['otherBranch'] == 0:
            imm.log("elif cond: 1078")
            flowRec[thId][prevInst]['otherBranch'] = current
            flowRec[thId][prevInst]['otherCounter'] = 1
            return False
        else:
            imm.log("else cond: 1083")
            iFileList.append("Error -- otherBranch has a rogue value\n")
            return False
    else:
        imm.log("else cond: 1087")
        iFileList.append("non-control-flow-impacting-instruction\n")
        return False


def attachAUT():
    psList = imm.ps()
    for ps in psList:
        imm.log(str(ps))
        if ps[1] != "OneDrive" and ps[1] != "firefox":
            imm.log("found AUT")
            return {'pidAUT': ps[0], 'nameAUT': ps[1], 'pathAUT': ps[2]}
    return {'pidAUT': 0, 'nameAUT': '', 'pathAUT': ''}


def executePayload(aut):
    # exploitFile = 'py C:\\Users\\testing\\Desktop\\exploits\\fsws\\fsws_full.py 192.168.56.109'
    if aut == 'fsws':
        exploitFile = 'C:\\Python27\\python C:\\Users\\testing\\Desktop\\exploits\\fsws\\fsws_full.py 192.168.56.104'
    elif aut == 'ftpshell':
        exploitFile = 'C:\\Python27\\python C:\\Users\\testing\\Desktop\\exploits\\fsws\\ftp_shell_client_6-7.py'
    else:
        imm.log("Error in locating exploit payload")
        iFileList.append("FATAL ERROR -- Can't find payload\n")
        return "FAILURE IN EXECUTING EXPLOIT PAYLOAD"
    os.system(exploitFile)
    imm.log("executed payload")
    return "success"


def checkProgTrace(current, regs, autModulesSet):
    # lines = [1,2,3,4,5,6,7,8,9,10]
    # line = 10
    currentModule = imm.getModuleByAddress(current)
    imm.log("currentModule:" + str(currentModule.getName()))
    if currentModule.getName() == 'kernel32.dll':
        imm.log("Match")
        line = 6
        opCode = imm.disasmForward(current, nlines=line)
        imm.log("command: " + str(opCode.getResult()))
        if opCode.isCall():
            # callTargetAddress = getFuncTarget(opCode, iFileList, command, regs, 'call')
            callTargetAddress = regs['EDX']
            # getCallTarget result if it can't find the address is -1
            if callTargetAddress != -1:
                callTarget = getModuleByAddr(callTargetAddress, autModulesSet)
                if callTarget['aut']:
                    return True
                else:
                    return False
        else:
            imm.log("Kernel32.dll but not an AUT module")
            return False
    else:
        imm.log("current module: " + currentModule.getName())
        return False


def evaluateSegmentSelectors(thId, regs):
    allMemoryPages = imm.getMemoryPages()
    allThreads = imm.getAllThreads()
    for th in allThreads:
        if th.getId() == thId:
            stackTop = th.getStackTop
            stackBottom = th.getStackBottom
    for page in allMemoryPages:
        if thId == page.getThreadID():
            if page.getBaseAddress() < regs['ESP'] < page.getBaseAddress() + page.getSize():
                globalSegmentSelectors['SS'] = page.getBaseAddress()
                break
    if globalSegmentSelectors['SS'] != 0:
        for page in allMemoryPages:
            if thId == page.getThreadID():
                if globalSegmentSelectors['DS'] == 0 and page.getBaseAddress() != globalSegmentSelectors['SS']:
                    globalSegmentSelectors['DS'] = page.getBaseAddress()
                    break
        if globalSegmentSelectors['DS'] != 0:
            for page in allMemoryPages:
                if thId == page.getThreadID():
                    if globalSegmentSelectors['ES'] == 0 and page.getBaseAddress() != globalSegmentSelectors['DS'] \
                            and page.getBaseAddress() != globalSegmentSelectors['SS']:
                        globalSegmentSelectors['ES'] = page.getBaseAddress()
                        break
        else:
            imm.log("Failed to acquire segment selectors -- DS")
            return "evaluateSegmentSelectors FAILED"
    else:
        imm.log("Failed to acquire segment selectors")
        return "evaluateSegmentSelectors FAILED"

    imm.log("evaluateSegmentSelectors Success")
    imm.log("SS: " + hex(globalSegmentSelectors['SS']))
    imm.log("DS: " + hex(globalSegmentSelectors['DS']))
    imm.log("ES: " + hex(globalSegmentSelectors['ES']))
    iFileList.append("SS: " + hex(globalSegmentSelectors['SS']) + "\n")
    iFileList.append("DS: " + hex(globalSegmentSelectors['DS']) + "\n")
    iFileList.append("ES: " + hex(globalSegmentSelectors['ES']) + "\n")
    return "evaluateSegmentSelectors SUCCESS"


def hangDetector(current, thId):
    thId = str(thId)
    if len(listOfInst[thId]) > 7:
        hangCounter = 0
        for addr in range(len(listOfInst[thId]) - 1, len(listOfInst[thId]) - 6, -1):
            if addr == current:
                hangCounter += 1
        if hangCounter > 5:
            iFileList.append("Error -- Hang Detected\n")
            imm.log("hang detected")
            return True
        else:
            imm.log("hang not detected")
            return False
    else:
        imm.log("hang not detected")
        return False


def iFilePrint():
    for i in iFileList:
        iFile.write(str(i))
    return "iFilePrint DONE"


def mFilePrint():
    for m in mFileList:
        mFile.write(str(m))
    return "mFilePrint DONE"


# output: details of module that holds the target address
# {'name':___, 'path':____, 'aut': True/False}

def getModuleByAddr(target, autModulesSet):
    iFileList.append("started getModuleByAddr\n")
    iFileList.append("target address is : " + str(target) + "\n")
    # print(int(target))
    # print("\n")
    modulesList = imm.findModule(int(target))
    imm.log("modUle returned is : " + str(modulesList))
    iFileList.append("getModuleByAddr: " + str(modulesList) + "\n")
    if len(modulesList) == 2:
        if modulesList[0].lower() in autModulesSet:
            return {'name': modulesList[0], 'path': '', 'aut': True}
        else:
            return {'name': modulesList[0], 'path': '', 'aut': False}

        # the moudulesList contains two items, one is the module name and the other is the module address.
        # for m in modulesList:
        #     module = imm.findModuleByName(m)
        #     if module.getName() in autModulesSet:
        #         return {'name': module.getName(), 'path': module.getPath(), 'aut': True}
        #     else:
        #         return {'name': module.getName(), 'path': module.getPath(), 'aut': False}
    else:
        imm.log("FATAL ERROR -- LINE 173")
        imm.log("can't find module for target:" + hex(target))
        imm.log(str(target))
        iFileList.append("Error:Unknown module\n")
        return {'name': 'unknown', 'path': '', 'aut': False}


# input: opCode and iFile
# output: address of the target EIP to be executed
def getFuncTarget(opCode, command, regs, cmdType):
    if opCode.getOpInfo()[0] and opCode.getOpInfo()[0] != '' and cmdType == 'call':
        iFileList.append("Op Info: " + opCode.getOpInfo()[0] + "\n")
        # This is the scenario where the call object is DS:something or FS:something ..
        # check if the call operand contains something within [ ]
        # if there is, then capture what is after the = sign
        # this is usually some kind of external DLL (but not sure if it must be system or not)
        if re.search(r'\[.+\]', opCode.getOpInfo()[0]):
            funcTarget = re.search(r'(?<==)\S+', opCode.getOpInfo()[0]).group(0)
        # otherwise, capture what is before teh = sign
        elif re.search(r'\S+(?==)', opCode.getOpInfo()[0]):
            funcTarget = re.search(r'\S+(?==)', opCode.getOpInfo()[0]).group(0)
        # otherwise, there is a new format that wasn't recorded before and program should terminate.
        else:
            iFileList.append("problem with funcTarget\n")
            iFileList.append("PROGRAM WILL TERMINATE IN ERROR\n")
            return "FATAL ERROR"
        imm.log("cmdType:" + str(cmdType))
        imm.log("command:" + str(command))
        imm.log("opCode:" + str(opCode.getDump()))
        imm.log("opInfo:" + opCode.getOpInfo()[0])
        imm.log("funcTargetInt:" + str(funcTarget))
        funcTargetInt = int(funcTarget.lstrip('00').lower(), 16)
        iFileList.append('target call/jump addr: ' + hex(funcTargetInt))
        iFileList.append("\n")
    else:
        # i think here I should use the function identifyEarlyAddress
        funcTargetInt = identifyAddrEarlyCheck(command, regs, cmdType)
        if funcTargetInt != -1:
            iFileList.append('target call/jump addr: ' + str(funcTargetInt))
            iFileList.append("\n")
        else:
            imm.log("FATAL ERROR -- LINE 212")
            imm.log("Warning: results are not reliable")
            iFileList.append("Critical: can't find target of command")
    return funcTargetInt


def captureStackChange(oldESP, newESP):
    # imm.log(str(oldESP))
    # imm.log(str(newESP))
    memory = imm.readMemory(newESP, (oldESP - newESP))
    mFileList.append("stack+_start\n")
    mFileList.append("ESP_old:" + hex(oldESP) + "\n" + "ESP_new:" + hex(newESP) + "\n")
    mFileList.append("##\n")
    mFileList.append(immutils.hexprint(memory))
    mFileList.append("\n##\n")
    mFileList.append("stack+_end\n")
    mFileJson["stack_change"] = {"oldESP": str(oldESP),
                                 "newESP": str(newESP),
                                 "new_content": immutils.hexprint(memory)}
    # imm.log("captureStackChange has been called")
    return "captureStackChange exited"


def dumpMemory():
    key_startMemDump = "**mem_dump\n"
    key_endMemDump = "**mem_dump_end\n"
    imm.log("dumping memory")
    allMemoryPages = imm.getMemoryPages()
    thread = imm.getThreadId()
    heaps = imm.getHeapsAddress()
    allThreads = imm.getAllThreads()
    for th in allThreads:
        if th.getId() == thread:
            mFileList.append("\nstackTop: " + hex(th.getStackTop()))
            mFileList.append("\nstackBottom: " + hex(th.getStackBottom()))
            mFileList.append("\nstack Size: " + hex(th.getStackTop() - th.getStackBottom()))
            mFileJson["mem_dump"].append({"current_thread_stackTop": str(th.getStackTop()),
                                          "current_thread_stackBottom": str(th.getStackBottom()),
                                          "current_thread_stackSize": str(th.getStackTop() - th.getStackBottom())})
    mFileList.append("\nList of heap addresses:")
    for heap in heaps:
        mFileList.append(hex(heap) + "\n")
    mFileJson["mem_dump"].append({"heap_addresses": str(heaps)})
    for page in allMemoryPages:
        if thread == page.getThreadID():
            mFileList.append("start_address:" + hex(page.getBaseAddress()))
            mFileList.append("\nend_address:" + hex(page.getBaseAddress() + page.getSize()))
            mFileList.append("\nsize:" + hex(page.getSize()) + "(" + str(page.getSize() / 1024) + ") kilo bytes")
            mFileList.append("\nsection:" + str(page.getSection()))
            mFileList.append("\naccess:" + str(page.getAccess()))
            mFileList.append("\ncontent:\n")
            mFileList.append(immutils.hexprint(page.getMemory()))
            mFileList.append("\n")
            mFileJson["mem_dump"].append({str(page.getBaseAddress()): {
                'end_address': str(page.getBaseAddress() + page.getSize()),
                'size_KB': str(page.getSize() / 1024),
                'section': str(page.getSection()),
                'access': str(page.getAccess()),
                'content': immutils.hexprint(page.getMemory())
            }})
    for heapAddr in heaps:
        mFileList.append("heap addresses\n")
        mFileList.append(hex(heapAddr) + "\n")
        heap = imm.getHeap(heapAddr)
        # mFileList.append("printing using print heap cachce\n")
        # mFileList.append(heap.printHeapCache())
        # mFileList.append("\n")
        mFileList.append("printing based on enumerating heap chunks\n")
        mFileList.append("starting from addr:" + hex(heapAddr) + "\n")
        # allChunks = heap.getChunks(heapAddr)
        # imm.log("printing chunks")
        # for chunk in allChunks:
        #     chunk.printchunk()
        mFileList.append("\n")

        # This section failed
        # mFileList.append("getting all blocks\n")
        # mFileList.append(str(heap.getBlocks(heapAddr)))
        # mFileList.append("\n")

        # this section provided results but took a lot of memory
        # mFileList.append("using get chunk on heapAddr\n")
        # heapChunk = heap.get_chunk(heapAddr)
        # mFileList.append(immutils.hexprint(heapChunk.printchunk()))
        # mFileList.append("\n")
        # mFileList.append("Printing free list\n")
        # mFileList.append(str(heap.printFreeList()))
        # mFileList.append("\n")
        # mFileList.append("end of printing heapAddr:"+hex(heapAddr)+"\n")
        # mFileList.append("trying to get heap info by Memory Page\n")
        # heapMemPage = imm.getMemoryPageByAddress(heapAddr)
        # mFileList.append(immutils.hexprint(heapMemPage.getMemory()))
        # mFileList.append("\n\n")

        mFileList.append("Reading memory in a regular fashion\n")
        mFileList.append(immutils.hexprint(imm.readMemory(heapAddr, 250)))
        mFileJson["mem_dump"].append({"heap_dump": {
            'heap_start_addr': str(heapAddr),
            'heap_read_size': str(250),
            'heap_content': immutils.hexprint(imm.readMemory(heapAddr, 250))
        }})
        mFileList.append("\n\n")
    mFileList.append(key_endMemDump)
    return "Success"


def getDebugged(debugged):
    debugged['name'] = imm.getDebuggedName()
    psList = imm.ps()
    for ps in psList:
        if re.search(debugged['name'], ps[2]):
            debugged['path'] = re.search(r'C:\\.+\\', ps[2]).group(0)
    # debugged['name'] = debugged['name'].lower() -- when I tried this statement, the AUT Module wasn't detected.
    iFileList.append(
        "Debugged Name is : " + debugged['name'] + "\n" + "Debugged path is :" + debugged['path'] + debugged[
            'name'] + "\n")
    iFileJson["Debugged_Name"] = debugged['name']
    iFileJson["Debugged_path"] = debugged['path'] + debugged['name']
    return debugged


def getAUTModules(autModulesSet, debugged, allModules):
    autModules = []
    iFileList.append("if there is AUT modules they will be printed here\n")
    iFileJson["AUT_modules"] = []
    # imm.log("debugged path: " + debugged['path'])
    for module in allModules:
        name = module.getName()
        # imm.log("module: "+name)
        path = module.getPath()
        pathNameTuple = path.rpartition('\\')
        pathExcName = pathNameTuple[0] + '\\'
        # imm.log("module path: "+path)
        # pathExcName = path.rstrip(name)
        # imm.log("module: " + name + " has pathExcName: " + pathExcName)
        if pathExcName == debugged['path']:
            autModules.append({'name': module.getName(), 'base': module.getBaseAddress(),
                               'codeSize': module.getCodesize(), 'path': module.getPath(), 'size': module.getSize()})
            autModulesSet.add(module.getName())
            iFileList.append("Name: " + module.getName() + " Path: " + module.getPath())
            iFileList.append("\n")
            iFileJson["AUT_modules"].append({"name": module.getName(), "path": module.getPath()})
    imm.log(str(autModulesSet))
    return autModulesSet


def analyzePrevInst(lastState, thId, regs):
    thId = str(thId)
    # step1.1.1: was last instruction a CALL or RET or LEAVE or JUMP?  yes --> get stack limits and dump it
    if lastState[thId]['lastInstType'] == 'callOutAUT' or \
            lastState[thId]['lastInstType'] == 'jumpOutAUT' or \
            lastState[thId]['lastInstType'] == 'rep' or \
            lastState[thId]['lastInstType'] == 'loopCallOutAUT' or \
            lastState[thId]['lastInstType'] == 'loopJumpOutAUT':
        # dump the stack
        # TODO: this section is not correct. I'm no longer checking the stackBottom, and I might need to
        #  drop this instruciton as it is mis-leading.
        dumpMemory()
        if lastState[thId]['bpFlag']:
            iFileList.append("the following breakpoints will be deleted:\n")
            for addr in lastState[thId]['breakpoints']:
                imm.deleteBreakpoint(addr)
                iFileList.append(hex(addr) + "-")
                iFileJson["debug_messages"].append("breakpoint deleted at: " + str(addr) + " hex(" + hex(addr) + ")")
            del lastState[thId]['breakpoints'][0:len(lastState[thId]['breakpoints'])]
            lastState[thId]['bpFlag'] = False

    # step1.1.2: was last instruction memory changing? yes --> proceed, no --> continue
    # step1.1.2.1: get memory address, and compare it with the recorded memory address

    elif lastState[thId]['lastInstType'] == 'loopCallInAUT' or \
            lastState[thId]['lastInstType'] == 'loopJumpInAUT':
        if lastState[thId]['bpFlag']:
            iFileList.append("the following breakpoints will be deleted:\n")
            for addr in lastState[thId]['breakpoints']:
                imm.deleteBreakpoint(addr)
                iFileList.append(hex(addr) + "-")
                iFileJson["debug_messages"].append("breakpoint deleted at: " + str(addr) + " hex(" + hex(addr) + ")")
            del lastState[thId]['breakpoints'][0:len(lastState[thId]['breakpoints'])]
            lastState[thId]['bpFlag'] = False
            dumpMemory()
        else:
            iFileList.append("Error: last Inst is loopCall/Jump but no bpFlag\n")

    if lastState[thId]['memRecFlag']:
        lastState[thId]['memRecFlag'] = False
        # here I should read the memory location pointed to by lastState[thId]['memList'][0 to n]
        # in each index location there is another list composed of: [ [address],[content] ]
        targetInfo = lastState[thId]['memList']
        targetAddrRd = targetInfo['address']  # assuming that memory change
        mFileList.append("Target Address:" + hex(targetAddrRd) + "\n")
        mFileList.append("Target Address Content:" + immutils.hexprint(targetInfo['content']) + "\n")
        # affected a single address
        currentMem = imm.readMemory(targetAddrRd, 4)
        mFileList.append("Current Address Content:" + immutils.hexprint(currentMem) + "\n")
        memUpdateFlag = False
        if currentMem != targetInfo['content']:
            # memory change occured
            mFileList.append("mem-update-start\n")
            mFileList.append("update:" + hex(targetAddrRd))
            mFileList.append("\n")
            mFileList.append(immutils.hexprint(currentMem))
            mFileList.append("\n")
            mFileList.append("mem-update-end\n")
            memUpdateFlag = True
        else:
            mFileList.append("no-mem-update\n")
            iFileList.append("currentMem:" + immutils.hexprint(currentMem) + "\n")
            iFileList.append("LastState[thId]['memList']['content']:" + immutils.hexprint(
                lastState[thId]['memList']['content']) + "\n")
        mFileJson["mem_change"].append({"target_addr": str(targetAddrRd),
                                        "target_addr_content": immutils.hexprint(targetInfo['content']),
                                        "current_addr_content": immutils.hexprint(currentMem),
                                        "mem_updated": str(memUpdateFlag)})
    # step1.1.3: check if there was a change in ESP by reduction, yes --> update the content, no --> proceed
    if lastState[thId]['ESP'] > regs['ESP']:
        # imm.log("entered into comparison part")
        # imm.log(str(lastState[index - 1]['ESP']))
        captureStackChange(lastState[thId]['ESP'], regs['ESP'])
        lastState[thId]['ESP'] = regs['ESP']
    elif lastState[thId]['ESP'] < regs['ESP']:
        lastState[thId]['ESP'] = regs['ESP']
        # imm.log("data was removed from stack")
    return lastState


def analyzeCurrentInst(opCode, lastState, autModulesSet, command, regs, current, thId, args, callCounter):
    # TODO: in this function I need to include as well the "Enter" instruction

    # IMPORTANT: currently, this function only takes action regarding loops when the instruction is not a control flow
    # changing instruction. That is not to miss any calls in the middle. This is intended by design.

    # step1.1.4: check if CURRENT instr is a call, yes --> get call target, no --> step1.1.4.1
    thId = str(thId)
    lastState[thId]['lastInstAddr'] = current
    if opCode.isCall():
        callTargetAddress = getFuncTarget(opCode, command, regs, 'call')
        # getCallTarget result if it can't find the address is -1
        if callTargetAddress != -1:
            callTarget = getModuleByAddr(callTargetAddress, autModulesSet)
            if callTarget['aut']:
                verifyVar = verifyCallTarget(callTargetAddress, autModulesSet)
                if not verifyVar['flag']:
                    # FALSE flag
                    # Scenarios:
                    # Jump after call for non-AUT module
                    # Jump after call for unknown module
                    if verifyVar['module'] != 'unknown':
                        # placeholder for case when call target module is non-AUT
                        iFileList.append("target_aut:True\n")
                        iFileList.append("target_verification:False\n")
                        iFileList.append("true_target_module:" + verifyVar['module'] + "\n")
                        iFileList.append("opCode:callOutAUT\n")
                        lastState[thId]['lastInstType'] = 'callOutAUT'
                        updateFlowRec(thId, 'callOutAUT', callTargetAddress, '', 0, 0,
                                      current)
                        iFileJson["opCode_type"] = "callOutAUT"
                        iFileJson["target_aut"] = "True"
                        iFileJson["target_verification"] = "False"
                        iFileJson["true_target_module"] = str(verifyVar['module'])
                        if verifyVar['module'] in moduleExceptedList:
                            # callCounter += 1
                            # if callCounter == 2:
                            #     moduleExceptedList.clear()
                            #     iFileJson["debug_messages"].append("moduleExceptedList has been cleared")
                            iFileList.append("action:stepIn\n")
                            iFileJson["action"] = "stepIn"
                            imm.stepIn()
                        else:
                            iFileList.append("action:stepOver\n")
                            iFileJson["action"] = "stepOver"
                            imm.stepOver()

                        # funcStepOver(current, lastState, thId)
                        # iFileList.append("action:run\n")
                        # imm.run()

                    else:
                        # verifyVar['module'] = 'unknown'
                        # jump for unknown module
                        iFileList.append("target_aut:True\n")
                        iFileList.append("target_verification:False\n")
                        iFileList.append("true_target_module:" + verifyVar['module'])
                        iFileList.append("opCode:callUnknownTarget\n")
                        lastState[thId]['lastInstType'] = 'callUnknownTarget'
                        updateFlowRec(thId, 'callUnknownTarget', callTargetAddress, '', 0, 0,
                                      current)
                        iFileJson["target_aut"] = "True"
                        iFileJson["target_verification"] = "False"
                        iFileJson["true_target_module"] = str(verifyVar["module"])
                        iFileJson["opCode_type"] = "callUnknownTarget"
                        iFileJson["action"] = "stepIn"
                        iFileList.append("action:stepIn\n")
                        imm.stepIn()
                else:
                    # verifyFlag = True
                    # (1) Jump after call for AUT module
                    # (2) No Jump after call - verifyVar['module'] = ''
                    iFileList.append("target_aut:True\n")
                    iFileList.append("target_verification:True\n")
                    ##
                    # to avoid stepping by mistake in non-AUT modules loopFlag is permanently set to False
                    # loopFlag = loopCheck(current, callTargetAddress, lastState, currentModule)
                    lastState[thId]['lastInstType'] = 'callInAUT'
                    updateFlowRec(thId, 'callInAUT', callTargetAddress, '', 0, 0, current)
                    iFileList.append("opCode:callInAUT\n")
                    iFileList.append("action:stepIn\n")
                    iFileJson["target_aut"] = "True"
                    iFileJson["target_verification"] = "True"
                    iFileJson["opCode_type"] = "callInAUT"
                    iFileJson["action"] = "stepIn"
                    imm.stepIn()
            else:
                iFileList.append("target_aut:False\n")
                iFileList.append("target_module:" + callTarget['name'] + "\n")

                if callTarget['name'].lower() in moduleExceptedList:
                    # if args[0] == '-l':
                    #     callCounter += 1
                    #     if callCounter == 2:
                    #         moduleExceptedList.clear()
                    #         imm.log("cleared the exceptedListModule")
                    iFileList.append("call_target:" + str(callTarget['name']) + "\n")
                    iFileList.append("call_target_module: excepted module\n")
                    updateFlowRec(thId, 'callOutAUT', callTargetAddress, '', 0, 0, current)
                    iFileList.append("action:stepIn\n")
                    iFileJson["target_aut"] = "False"
                    iFileJson["target_module"] = str(callTarget['name'])
                    iFileJson["call_target_module"] = "excepted_module"
                    iFileJson["opCode_type"] = "callOutAUT"
                    iFileJson["action"] = "stepIn"
                    imm.stepIn()
                elif callTarget['name'] != 'unknown':
                    #
                    iFileList.append("opCode:callOutAUT\n")
                    lastState[thId]['lastInstType'] = 'callOutAUT'
                    updateFlowRec(thId, 'callOutAUT', callTargetAddress, '', 0, 0, current)
                    iFileList.append("action:stepOver\n")
                    iFileJson["target_aut"] = "False"
                    iFileJson["target_module"] = str(callTarget['name'])
                    iFileJson["call_target_module"] = "excepted_module"
                    iFileJson["opCode_type"] = "callOutAUT"
                    iFileJson["action"] = "stepOver"
                    imm.stepOver()

                    # funcStepOver(current, lastState, thId)
                    # iFileList.append("action:run\n")
                    # imm.run()


                else:
                    # then call target module is unknown
                    imm.log("ERROR LINE 619 - CALL TARGET MODULE UNKNOWN")
                    iFileList.append("Error - Call Target Module Unknown\n")
                    #
                    # to avoid stepping into non-AUT modules, loopFlag is permanently set to False
                    # loopFlag = loopCheck(current, callTargetAddress, lastState, currentModule)
                    iFileList.append("opCode:callUnknownTarget\n")
                    lastState[thId]['lastInstType'] = 'callUnknownTarget'
                    updateFlowRec(thId, 'callUnknownTarget', callTargetAddress, '', 0, 0, current)
                    iFileList.append("action:stepIn\n")
                    iFileJson["opCode_type"] = "callUnknownTarget"
                    iFileJson["debug_messages"].append("Error -- call target module unknown")
                    imm.stepIn()

        else:
            # then I can't determine the address
            iFileList.append("can't identify the target address (-1)\n")
            iFileList.append("target_aut:unknown\n")
            imm.log("FATAL ERROR - CAN'T FIND CALL TARGET ADDRESS")
            #
            # to avoid stepping into non-AUT modules, loopFlag is set to False
            # loopFlag = loopCheck(current, callTargetAddress, lastState, currentModule)
            iFileList.append("opCode:callUnknownTarget\n")
            lastState[thId]['lastInstType'] = 'callUnknownTarget'
            updateFlowRec(thId, 'callUnknownTarget', callTargetAddress, '', 0, 0, current)
            iFileList.append("action:stepIn\n")
            iFileJson["target_aut"] = "unknown"
            iFileJson["debug_messages"] = "Fatal Error - can't find call target address"
            iFileJson["opCode_type"] = "callUnknownTarget"
            iFileJson["action"] = "stepIn"
            imm.stepIn()

    # step1.1.4.1: if step1.1.4 is no, check if CURRENT instr is a RETURN, yes --> update lastState and stepIn,
    # no --> step1.1.4.2
    elif opCode.isRet():
        iFileList.append("opCode:ret\n")
        lastState[thId]['lastInstType'] = 'ret'
        iFileList.append("action:stepIn\n")
        iFileJson["opCode_type"] = "ret"
        iFileJson["action"] = "stepIn"
        imm.stepIn()
    # step1.1.4.2: if step1.1.4.1 is no, check if current instr is a JUMP, yes --> step1.1.4.3, no --> step.1.1.4.4
    # step1.1.4.3: if step1.1.4.2 is yes, get jump target, if target in AUTModules, update lastState = general &
    # stepIn, else stepOver
    elif opCode.isJmp() or opCode.isConditionalJmp():
        otherBranch = 0
        if opCode.getJmpAddr() != 0:
            jumpTarget = getModuleByAddr(opCode.getJmpAddr(), autModulesSet)
            if jumpTarget['aut']:
                lastState[thId]['lastInstType'] = 'jumpInAUT'
                iFileList.append("opCode:jumpInAUT\n")
                iFileList.append("Jmp_target:" + hex(opCode.getJmpAddr()) + "\n")
                iFileList.append("target_module:" + str(jumpTarget['name']) + "\n")
                iFileList.append("action:stepIn\n")
                if opCode.isConditionalJmp():
                    nextAddr = getNextAddr(current)
                    if nextAddr != opCode.getJmpAddr():
                        # nextAddr is not the same as the jump target (which is logical)
                        otherBranch = nextAddr
                    else:
                        # this is an anomaly
                        iFileList.append("Error: anomaly detected, next addr is the same as jump target\n")
                        iFileJson["debug_messages"] = "Error: anomaly detected, next addr is the same as jump target"
                updateFlowRec(thId, 'jumpInAUT', opCode.getJmpAddr(), otherBranch, 0, 0,
                              current)
                iFileJson["opCode_type"] = "jumpInAUT"
                iFileJson["jmp_target"] = str(opCode.getJmpAddr())
                iFileJson["target_module"] = str(jumpTarget['name'])
                iFileJson["action"] = "stepIn"
                imm.stepIn()
            else:
                if jumpTarget['name'].lower() in moduleExceptedList:
                    lastState[thId]['lastInstType'] = 'exceptedJump'
                    iFileList.append("opCode:exceptedJump\n")
                    iFileList.append("Jmp_target:" + hex(opCode.getJmpAddr()) + "\n")
                    iFileList.append("target_module:" + str(jumpTarget['name']) + "\n")
                    iFileList.append("action:stepIn\n")
                    updateFlowRec(thId, 'exceptedJump', opCode.getJmpAddr(), 0, 0, 0,
                                  current)
                    iFileJson["opCode_type"] = "exceptedJump"
                    iFileJson["jmp_target"] = str(opCode.getJmpAddr())
                    iFileJson["target_module"] = str(jumpTarget['name'])
                    iFileJson["action"] = "stepIn"
                    imm.stepIn()
                else:
                    lastState[thId]['lastInstType'] = 'jumpOutAUT'
                    iFileList.append("opCode:jumpOutAUT\n")
                    iFileList.append("Jmp_target:" + hex(opCode.getJmpAddr()) + "\n")
                    iFileList.append("target_module:" + str(jumpTarget['name']) + "\n")
                    # the approach of run is not suitable. As soon as I'm in a position of jmpOutAUT it might be a system DLL and run would loose tracing information
                    # iFileList.append("action:run\n")
                    updateFlowRec(thId, 'jumpOutAUT', opCode.getJmpAddr(), 0, 0, 0,
                                  current)
                    # # imm.stepOver()
                    # funcStepOver(current, lastState, thId)
                    # imm.run()
                    iFileList.append("action:stepIn\n")
                    iFileJson["opCode_type"] = "jumpOutAUT"
                    iFileJson["jmp_target"] = str(opCode.getJmpAddr())
                    iFileJson["target_module"] = str(jumpTarget['name'])
                    iFileJson["action"] = "stepIn"
                    imm.stepIn()
        else:
            # placeholder where Jmp Target can't be determined by Immunity Debugger API
            jumpTargetAddr = getFuncTarget(opCode, command, regs, 'jump')
            if jumpTargetAddr != -1:
                jumpTarget = getModuleByAddr(jumpTargetAddr, autModulesSet)
                if jumpTarget['aut']:
                    lastState[thId]['lastInstType'] = 'jumpInAUT'
                    iFileList.append("opCode:jumpInAUT\n")
                    iFileList.append("action:stepIn\n")
                    if opCode.isConditionalJmp():
                        nextAddr = getNextAddr(current)
                        if nextAddr != opCode.getJmpAddr():
                            # nextAddr is not the same as the jump target (which is logical)
                            otherBranch = nextAddr
                        else:
                            # this is an anomaly
                            iFileList.append("Error: anomaly detected, next addr is the same as jump target\n")
                            iFileJson[
                                "debug_messages"] = "Error: anomaly detected, next addr is the same as jump target"
                    updateFlowRec(thId, 'jumpInAUT', jumpTargetAddr, otherBranch, 0, 0,
                                  current)
                    iFileJson["opCode_type"] = "jumpInAUT"
                    iFileJson["action"] = "stepIn"
                    imm.stepIn()
                else:
                    if jumpTarget['name'].lower() in moduleExceptedList:
                        iFileList.append("target_aut:False\n")
                        iFileList.append("target_module:" + jumpTarget['name'] + "\n")
                        iFileList.append("target_module_EXCEPTED\n")
                        iFileList.append("opCode:exceptedJump\n")
                        lastState[thId]['lastInstType'] = 'exceptedJump'
                        iFileList.append("action:stepIn\n")
                        updateFlowRec(thId, 'exceptedJump', jumpTargetAddr, otherBranch, 0, 0,
                                      current)
                        iFileJson["target_aut"] = "False"
                        iFileJson["target_module"] = str(jumpTarget['name'])
                        iFileJson["opCode_type"] = "exceptedJump"
                        iFileJson["action"] = "stepIn"
                        iFileJson["debug_messages"].append("target_module_excepted")
                        imm.stepIn()
                    else:
                        iFileList.append("target_aut:False\n")
                        iFileList.append("target_module:" + jumpTarget['name'] + "\n")
                        if jumpTarget['name'] != 'unknown':
                            iFileList.append("opCode:jumpOutAUT\n")
                            lastState[thId]['lastInstType'] = 'jumpOutAUT'
                            # iFileList.append("action:run\n")
                            updateFlowRec(thId, 'jumpOutAUT', jumpTargetAddr, otherBranch, 0, 0,
                                          current)
                            # imm.stepOver()
                            # funcStepOver(current, lastState, thId)
                            # imm.run()
                            iFileList.append("action:stepIn\n")
                            iFileJson["opCode_type"] = "jumpOutAUT"
                            iFileJson["action"] = "stepIn"
                            imm.stepIn()
                        else:
                            # then call target module is unknown
                            imm.log("ERROR LINE 619 - CALL TARGET MODULE UNKNOWN")
                            iFileList.append("opCode:jumpUnknownTarget\n")
                            lastState[thId]['lastInstType'] = 'jumpUnknownTarget'
                            updateFlowRec(thId, 'jumpUnknownTarget', jumpTargetAddr, otherBranch, 0, 0,
                                          current)
                            iFileList.append("action:stepIn\n")
                            iFileJson["opCode_type"] = "jumpUnknownTarget"
                            iFileJson["action"] = "stepIn"
                            imm.stepIn()

            else:
                # then I can't determine the address
                iFileList.append("target_aut:unknown\n")
                imm.log("FATAL ERROR - CAN'T FIND CALL TARGET ADDRESS")
                iFileList.append("opCode:jumpUnknownTarget\n")
                lastState[thId]['lastInstType'] = 'jumpUnknownTarget'
                updateFlowRec(thId, 'jumpUnknownTarget', jumpTargetAddr, otherBranch, 0, 0, current)
                iFileList.append("action:stepIn\n")
                iFileJson["target_aut"] = "unknown"
                iFileJson["debug_messages"] = "FATAL ERROR - Can't find call target Address"
                iFileJson["opCode_type"] = "jumpUnknownTarget"
                iFileJson["action"] = "stepIn"
                imm.stepIn()

    # step1.1.4.4: if step1.1.4.2 is no, check if CURRENT instr is LEAVE, yes --> update lastState & stepIn,
    # no--> step1.1.4.5
    elif opCode.isRep():
        lastState[thId]['lastInstType'] = 'rep'
        iFileList.append("opCode:rep\n")
        iFileList.append("action:stepOver\n")
        iFileJson["opCode_type"] = "rep"
        iFileJson["action"] = "stepOver"
        imm.stepOver()
    elif re.search(r'leave', command):
        lastState[thId]['lastInstType'] = 'leave'
        iFileList.append("opCode:leave\n")
        iFileList.append("action:stepIn\n")
        iFileJson["opCode_type"] = "leave"
        iFileJson["action"] = "stepIn"
        imm.stepIn()
    # step1.1.4.5: if step1.1.4.4 is no, check if CURRENT instr has memory impact? record if any then stepIn.
    else:
        lastState[thId]['lastInstType'] = 'general'
        iFileList.append("opCode:general\n")
        iFileJson["opCode_type"] = "general"
        # result = memImpactCheck(opCode, mFile)
        # loopCheck = checkForLoops(opCode, lastState, current)
        # # loopCheck = {'flag': ___, 'nextAddrInt':____}
        # if loopCheck['flag']:
        #     iFileList.append("loop detected\n")
        #     iFileList.append("stepping to addr:" + hex(loopCheck['nextAddrInt']) + "\n")
        #     imm.stepIn(loopCheck['nextAddrInt'])
        # else:

        # below section was part of the else
        result = evaluateMemImpact(command, regs)
        if result['impact']:
            # imm.log("instruction WILL have impact on memory contents")
            iFileList.append("mem_change:True\n")
            lastState[thId]['memRecFlag'] = True
            lastState[thId]['memList'] = {'impact': True, 'address': result['address'],
                                          'content': result['content']}
        else:
            iFileList.append("mem_change:False\n")
            lastState[thId]['memRecFlag'] = False
            lastState[thId]['memList'] = {'impact': False, 'address': [], 'content': []}
            # imm.log("instruction WILL NOT have impact on memory contents")
        iFileList.append("action:stepIn\n")
        iFileJson["action"] = "stepIn"
        imm.stepIn()
        # end of section that was part of the else

    return lastState


def updateFlowRec(thId, instType, targetBranch, otherBranch, targetCounter, otherCounter, current):
    flowRecCallTypes = {'callOutAUT', 'callUnknownTarget', 'callInAUT'}
    flowRecJumpTypes = {'jumpOutAUT', 'jumpUnknownTarget', 'exceptedJump', 'jumpInAUT'}
    if instType in flowRecCallTypes:
        imm.log("call")
        if thId not in flowRec:
            flowRec[thId] = {
                str(current): {'type': instType, 'targetBranch': targetBranch,
                               'targetCounter': targetCounter}}
        elif str(current) not in flowRec[thId]:
            flowRec[thId][str(current)] = {'type': instType,
                                           'targetBranch': targetBranch,
                                           'targetCounter': targetCounter}
    elif instType in flowRecJumpTypes:
        imm.log("jump")
        if thId not in flowRec:
            flowRec[thId] = {
                str(current): {'type': instType, 'targetBranch': targetBranch,
                               'targetCounter': targetCounter, 'otherBranch': otherBranch,
                               'otherCounter': otherCounter}}
        elif str(current) not in flowRec[thId]:
            flowRec[thId][str(current)] = {'type': instType, 'targetBranch': targetBranch,
                                           'targetCounter': targetCounter, 'otherBranch': otherBranch,
                                           'otherCounter': otherCounter}
    iFileList.append("flowRec[" + str(thId) + "][" + str(current) + "]: " + str(flowRec[thId][str(current)]))
    return flowRec


def getNextAddr(current):
    nextOpCode = imm.disasmForward(current)
    nextAddr = nextOpCode.getAddress()
    return nextAddr


# def funcStepOver(current, lastState, thId):
#     nextOpCode = imm.disasmForward(current)
#     nextAddress = nextOpCode.getAddress()
#     lastState[thId]['breakpoints'].append(nextAddress)
#     createBreakpoints(lastState, thId)
#     return "funcStepOver"


def verifyCallTarget(callTargetAddress, autModulesSet):
    nextOpCode = imm.disasm(callTargetAddress)
    if nextOpCode.isJmp() or nextOpCode.isConditionalJmp():
        jumpTarget = getModuleByAddr(nextOpCode.getJmpAddr(), autModulesSet)
        if jumpTarget['aut']:
            return {'module': jumpTarget['name'], 'flag': True}
        else:
            if jumpTarget['name'].lower() in moduleExceptedList:
                imm.log("excepted module allowed")
                iFileList.append("target_module_excepted\n")
                iFileList.append("target_module_true:" + jumpTarget['name'] + "\n")
                return {'module': jumpTarget['name'], 'flag': True}
            else:
                return {'module': jumpTarget['name'], 'flag': False}
    else:
        return {'module': '', 'flag': True}


#
# def loopCheck(current, target, lastState, currentModule):
#     # imm.log("loop check called")
#     # This function will check the current EIP, and evaluate if it is part of a loop
#     # this is done by recording every call/jump EIP and their respective targets and keep a counter for each hit
#     # if hit reaches 2, then the result will be true to start skipping
#     # if hit below 2, then the result will be false
#
#     # nonAUTLoops = {} objectives of nonAUTLoops nonAUTLoops = {'module-1': {'EIP': {'target':__,'counter':___},
#     # 'module-2': { 'EIP': {'target':__, 'counter':__}}}}
#     # autLoops = {} objectives of autLoops autLoops = { 'EIP_1':
#     # { 'target': ___, 'counter':___}, ' EIP_2': { 'target':___, 'counter':___}, } so search would be --> if EIP in
#     # autLoops then check autLoops['EIP_1']['target'] is it the same? it should be the same then add the counter. It
#     # should be added in the analyzeCurrentInst. All actions should be in the analyzeCurrentInst if counter >2,
#     # then we'll run instead of step.
#
#     index = len(lastState)
#     current = str(current)
#     if lastState[index - 1]['autModule']:
#         # placeholder for AUT actions
#         if current in lastState[index - 1]['autLoops']:
#             # imm.log("autLoop")
#             # this means that the current address was recorded before
#             if lastState[index - 1]['autLoops'][current]['counter'] > 1:
#                 # imm.log("counter > 1")
#                 return True
#             else:
#                 lastState[index - 1]['autLoops'][current]['counter'] += 1
#                 # imm.log("counter +=1")
#                 return False
#         else:
#             # this means that this is the first time to see this EIP
#             lastState[index - 1]['autLoops'][current] = {'target': target, 'counter': 1}
#             # imm.log("new address added")
#             # imm.log(str(lastState[index - 1]['autLoops'][current]))
#             return False
#     else:
#         # placeholder for non-AUT actions
#         if currentModule in lastState[index - 1]['nonAUTLoops']:
#             if current in lastState[index - 1]['nonAUTLoops'][currentModule]:
#                 if lastState[index - 1]['nonAUTLoops'][currentModule][current]['counter'] > 1:
#                     # imm.log("counter is more than 1")
#                     # loops that contain within them calling for system DLLs will be dropped by returning False here
#                     # return True
#                     return False
#                 else:
#                     lastState[index - 1]['nonAUTLoops'][currentModule][current]['counter'] += 1
#                     # imm.log("counter +=1")
#                     return False
#             else:
#                 lastState[index - 1]['nonAUTLoops'][currentModule][current] = {'target': target, 'counter': 1}
#                 # imm.log("new address added")
#                 # imm.log(str(lastState[index - 1]['nonAUTLoops'][currentModule]))
#                 return False
#         else:
#             lastState[index - 1]['nonAUTLoops'][currentModule] = {current: {'target': target, 'counter': 1}}
#             # imm.log("New module and new address added")
#             # imm.log(str(lastState[index - 1]['nonAUTLoops'][currentModule]))
#             return False


# def controlFlowEval(lastState, current, autModulesSet, command, opCode, regs, cmdType):
#     target = 0
#     index = len(lastState)
#     for eip in lastState[index - 1]['autLoops']:
#         if str(eip) == str(opCode.getAddress()):
#             target = lastState[index - 1]['autLoops'][eip]['target']
#     if target == 0:
#         for eip in lastState[index - 1]['nonAUTLoops']:
#             if str(eip) == str(opCode.getAddress()):
#                 target = lastState[index - 1]['nonAUTLoops'][eip]['target']
#     if target != 0:
#         iFileList.append("  call_target:" + hex(target) + "\n")
#         if target == current:
#             iFileList.append("  current address found\n")
#             return {'break': {'status': True, 'content': 'foundFlag'}, 'bp': {}, 'modifyAddr': {}}
#         else:
#             targetModule = getModuleByAddr(target, autModulesSet, imm)
#             if targetModule['aut'] and (cmdType == 'call' or cmdType == 'jump'):
#                 iFileList.append("  target_modified:" + hex(target) + "\n")
#                 return {'modifyAddr': {'status': True, 'content': target}, 'break': {}, 'bp': {}}
#             elif targetModule['aut'] and cmdType == 'condJump':
#                 return {'bp': {'status': True, 'content': target}, 'modifyAddr': {}, 'break': {}}
#             else:
#                 iFileList.append("  target:non-AUT\n")
#                 return {'modifyAddr': {}, 'break': {}, 'bp': {}}
#     else:
#         iFileList.append("  target wasn't recorded before\n")
#         result = re.search('EAX|ECX|EDX|EBX|ESP|EBP|ESI|EDI|EIP', command)
#         if result is None:
#             if cmdType == 'jump' or cmdType == 'condJump':
#                 if opCode.getJmpAddr() == 0:
#                     target = getFuncTarget(opCode, iFile, command, regs, cmdType)
#                 else:
#                     target = opCode.getJmpAddr()
#             elif cmdType == 'call':
#                 target = getFuncTarget(opCode, iFile, command, regs, cmdType)
#             iFileList.append("   target_addr:" + hex(target) + "\n")
#             imm.log("target_addr:" + hex(target) + "\n")
#             if target == current:
#                 iFileList.append("  current address found\n")
#                 return {'break': {'status': True, 'content': 'foundFlag'}, 'modifyTarget': {}, 'bp': {}}
#             else:
#                 targetModule = getModuleByAddr(target, autModulesSet, imm)
#                 iFileList.append("  target_module:" + str(targetModule['name']) + "\n")
#                 imm.log("target_module:" + str(targetModule['name']) + "\n")
#                 if targetModule['aut']:
#                     if cmdType == 'call':
#                         verifyVar = verifyCallTarget(target, autModulesSet, imm)
#                         if verifyVar['flag']:
#                             # this means that the target module is INDEED AN AUT module
#                             iFileList.append("  target_modified:" + hex(target) + "\n")
#                             return {'modifyAddr': {'status': True, 'content': target}, 'bp': {}, 'break': {}}
#                         else:
#                             return {'modifyAddr': {}, 'bp': {}, 'break': {}}
#                     elif cmdType == 'jump':
#                         # placeholder
#                         iFileList.append("  target_modified:" + hex(target) + "\n")
#                         return {'modifyAddr': {'status': True, 'content': target}, 'bp': {}, 'break': {}}
#                     elif cmdType == 'condJump':
#                         return {'bp': {'status': True, 'content': target}, 'modifyAddr': {}, 'break': {}}
#                     else:
#                         return {'bp': {}, 'break': {}, 'modifyAddr': {}}
#                 else:
#                     return {'bp': {}, 'break': {}, 'modifyAddr': {}}
#         else:
#             iFileList.append("can't identify call target because there is a registry value used\n")
#             return {'break': {'status': True, 'content': 'error'}, 'modifyAddr': {}, 'bp': {}}


# def getNextAddr(current, mode, lastState, target, command, regs, iFile, autModulesSet):
#     # Right now the number 50 is causing a lot more breakpoints to be used instead of the only required amount.
#     imm.log("getNextAddr")
#     nextOpCode = imm.disasmForward(current)
#     index = len(lastState)
#     lastState[index - 1]['breakpoints'].append(nextOpCode.getAddress())
#     foundFlag = False
#     if mode == 'loopCallInAUT' or mode == 'loopJumpInAUT' or mode == 'loopCallOutAUT' or mode == 'loopJumpOutAUT':
#         line = 1
#         iFileList.append("LOOP DUMP\n")
#         iFileList.append("mode:" + mode + "\n")
#         maxLine = 50
#         while not foundFlag:
#             if line >= maxLine:
#                 break
#             imm.log("line:" + str(line))
#             opCode = imm.disasmForward(target, nlines=line)
#             iFileList.append("L:" + str(line) + "  " + hex(opCode.getAddress()) + "  ")
#             iFileList.append(str(opCode.getDump()) + "  " + str(opCode.getResult()) + "\n")
#             imm.log(str(opCode.getDump()) + str(opCode.getResult()) + "\n")
#             result = {'bp': {}, 'modifyAddr': {}, 'break': {}}
#             if opCode.getAddress() == current:
#                 foundFlag = True
#                 iFileList.append("  current address found\n")
#                 break
#             # elif opCode.isRet() and line != 1:
#             #     iFileList.append("can't  trace commands within this loop\n")
#             #     break
#             elif opCode.isCall():
#                 imm.log("opCode.isCall:True")
#                 # search for previous call instructions
#                 result = controlFlowEval(lastState, current, autModulesSet, command, opCode, regs, 'call')
#             elif opCode.isJmp():
#                 imm.log("opCode.isJmp():True")
#                 result = controlFlowEval(lastState, current, autModulesSet, command, opCode, regs, 'jump')
#             elif opCode.isConditionalJmp():
#                 imm.log("ConditionalJmp:True")
#                 result = controlFlowEval(lastState, current, autModulesSet, command, opCode, regs, 'condJump')
#             if result['bp']:
#                 bpAddr = result['bp']['content']
#                 lastState[index - 1]['breakpoints'].append(bpAddr)
#             elif result['modifyAddr']:
#                 target = result['modifyAddr']['content']
#                 maxLine = maxLine - line
#                 line = 0
#             elif result['break']:
#                 if result['break']['content'] == 'foundFlag':
#                     foundFlag = True
#                     break
#                 elif result['break']['content'] == 'error':
#                     break
#             line += 1
#     if foundFlag:
#         lastState[index - 1]['bpFlag'] = True
#         iFileList.append("breakpoints created:\n")
#         imm.log("The following breakpoints will be created:\n")
#         for addr in lastState[index - 1]['breakpoints']:
#             imm.setBreakpoint(addr)
#             iFileList.append(hex(addr) + "-")
#             imm.log(hex(addr) + "-")
#         return True
#     else:
#         iFileList.append("LOOP DUMP NOT COMPLETE\n")
#         iFileList.append("no breakpoints created\n")
#         imm.log("no breakpoints created\n")
#         if lastState[index - 1]['breakpoints']:
#             del lastState[index - 1]['breakpoints'][0:len(lastState[index - 1]['breakpoints'])]
#         iFileList.append("BP validation:\n")
#         iFileList.append(str(lastState[index - 1]['breakpoints']))
#         return False


# def checkForLoops(opCode, lastState, current):
#     # loopCheck = {'flag': ___, 'nextAddrInt':____} loopCheck is the RETURN this will check if current address is
#     # part of a loop if yes, then it will return the address that is right after the loop - get last node opCode size
#     # and add it to address of last node address
#     index = len(lastState)
#     # imm.log(str(lastState))
#     if lastState[index - 1]['currentListOfLoops']:
#         for loop in lastState[index - 1]['currentListOfLoops']:
#             # each loop item [ start, end, nodes ]
#             # start : address of node receiving the back edge
#             # end : address of node which has the back edge
#             # nodes : list of node's addresses involved in this loop
#             if current == loop[0] or current == loop[1] or current in loop[2]:
#                 imm.log("Got into a loop")
#                 opCode = imm.disasm(loop[1])
#                 endOpCodeSize = opCode.getOpSize()
#                 nextAddrInt = loop[1] + endOpCodeSize + 1
#                 nextAddrOpCode = imm.disasm(nextAddrInt)
#                 if nextAddrOpCode.isCmd():
#                     imm.log("next addrInt is a cmd...success")
#                 else:
#                     imm.log("next addrInt is not a cmd..failure")
#                 return {'flag': True, 'nextAddrInt': nextAddrInt}
#         return {'flag': False, 'nextAddrInt': 0}
#     else:
#         return {'flag': False, 'nextAddrInt': 0}


def printRegs(thId, regs, current, opCode, command):
    iFileList.append("thId:" + str(thId) + "\n")
    iFileList.append(hex(current) + "__" + opCode.getDump() + "__" + command + "\n")
    mFileList.append(">" + hex(current) + "__" + opCode.getDump() + "__" + command + "\n")
    iFileList.append("EAX:" + hex(regs['EAX']).strip("L") + "__" + "ECX:" + hex(regs['ECX']).strip("L") + "__" + "EDX:"
                     + hex(regs['EDX']).strip("L") + "__" + "EBX:" + hex(regs['EBX']).strip("L") + "__" + "ESP:"
                     + hex(regs['ESP']).strip("L") + "__" + "EBP:" + hex(regs['EBP']).strip("L") + "__" + "ESI:" +
                     hex(regs['ESI']).strip("L") + "__" + "EDI:" + hex(regs['EDI']).strip("L") + "__" + "EIP:" + hex(
        regs['EIP']).strip("L"))
    iFileList.append("\n")
    iFileJson["thread_Id"] = str(thId)
    iFileJson["eax"] = str(regs['EAX']).rstrip("L")
    iFileJson["ecx"] = str(regs['ECX']).rstrip("L")
    iFileJson["edx"] = str(regs['EDX']).rstrip("L")
    iFileJson["ebx"] = str(regs['EBX']).rstrip("L")
    iFileJson["esp"] = str(regs['ESP']).rstrip("L")
    iFileJson["ebp"] = str(regs['EBP']).rstrip("L")
    iFileJson["esi"] = str(regs['ESI']).rstrip("L")
    iFileJson["edi"] = str(regs['EDI']).rstrip("L")
    iFileJson["eip"] = str(regs['EIP']).rstrip("L")
    iFileJson["opCode"] = str(opCode.getDump())
    iFileJson["command"] = str(command)
    return "printRegs SUCCESS"


def checkInstFile(fileHandle, result):
    for line in fileHandle:
        line = line.rstrip("\n")
        searchResult = re.search(line, result)
        if searchResult:
            return True
    return False


def identifyAddrEarlyCheck(command, regs, cmdType):
    result = re.search(r'\D\D:\[\S+\]', command)
    if result:
        # there is segment selector
        result = result.group(0)
        stringTuple = result.partition(':')
        segmentSelector = stringTuple[0]
        offset = stringTuple[2].lstrip('[').rstrip(']')
        bracketsFlag = True
    else:
        result = re.search(r'\[\S+\]', command)
        if result:
            # result contains a bracket (which should be the case)
            offset = result.group(0)
            offset = offset.lstrip('[').rstrip(']')
            segmentSelector = ''
            bracketsFlag = True
        else:
            result = re.search(r'EAX|ECX|EDX|EBX|EBP|ESP|ESI|EDI', command)
            if result:
                # direct call to content of registery
                # offset = regs[result.group(0)]
                offset = result.group(0)
                segmentSelector = ''
                bracketsFlag = False
            else:
                result = re.search(r'[0123456789abcdef]+', command, flags=re.I)
                if result:
                    offset = int(result.group(0), 16)
                    segmentSelector = ''
                    bracketsFlag = False
                else:
                    # imm.log("THIS INST DOESN'T AFFECT MEMORY")
                    return -1

    # THE REMAINDER OF THE FOLLOWING LINES - MY OBJECTIVE IS TO TRANSLATE OFFSET INTO AN INT ADDRESS.

    plusContainer = []
    negativeContainer = []
    offset = str(offset)
    iFileList.append("offset:" + offset + "\n")
    iFileJson["debug_messages"].append({"offset": str(offset)})
    # step1: identify if there is any arithmatic operations
    # step2: identify the nature of those operations, and enforce them

    if re.search('.+\+.+-|.+-.+\+', offset) or re.search('.+\+', offset) or re.search('.+-', offset):
        # If there is addition or subtraction or both
        # group 0: regex for any negative number/register : (?<=-)(\w+)
        # group 1: regex for any positive number/register (excluding first one): (?<=\+)(\w+)
        # group 2: regex for first item : ^\w+
        # group 3: regex for first item if it contains multiplication : ^\w+\*\d
        # group 4: regex for any positive register (excluding first one) that contains multiplication: (?<=\+)(\w+\*\d)
        # group 5: regex for any negative register that contains multiplication: (?<=-)(\w+\*\d)
        # below results for example: [ECX*4+4FC3CC]
        result0 = re.findall(r"(?<=-)(\w+)", offset)  # nothing
        result1 = re.findall(r"(?<=\+)(\w+)", offset)  # 4FC3CC
        result2 = re.findall(r"^\w+", offset.lstrip("["))  # ECX only !!
        result3 = re.findall(r"^\w+\*\d", offset.lstrip("["))  # ECX*4
        result4 = re.findall(r"(?<=\+)(\w+\*\d)", offset)
        result5 = re.findall(r"(?<=-)(\w+\*\d)", offset)
        if result5:
            for result in result5:
                negativeContainer.append(result)
        elif result0:
            for result in result0:
                negativeContainer.append(result)
        if result4:
            for result in result4:
                plusContainer.append(result)
        elif result1:
            for result in result1:
                plusContainer.append(result)
        if result3:
            for result in result3:
                plusContainer.append(result)
        elif result2:
            for result in result2:
                plusContainer.append(result)
        # imm.log("negativeContainer")
        # imm.log(str(negativeContainer))
        # imm.log("plusContainer")
        # imm.log(str(plusContainer))

        plusInt = arithmetic(plusContainer, regs)
        negativeInt = arithmetic(negativeContainer, regs)
        addr = plusInt - negativeInt
        iFileList.append("identifyEarlyAddressCheck result_line_2074: " + str(addr) + "\n")

    else:
        # that means that there is no arithmetic operations
        result = re.search(r'EAX|ECX|EDX|EBX|EBP|ESP|ESI|EDI', offset)
        if result:
            # direct call to content of registery
            offset = regs[result.group(0)]
            addr = int(offset)
            iFileList.append("identifyEarlyAddressCheck result_line_2083: " + str(addr) + "\n")
        else:
            addr = int(offset, 16)
            iFileList.append("identifyEarlyAddressCheck result_line_2086: " + str(addr) + "\n")

    if bracketsFlag and cmdType == 'call':
        if addr != 0:
            imm.log("[addr]:" + str(addr))
            addr = imm.readMemory(addr, 4)
            # imm.log("buffer: "+str(addr))
            addr = immutils.hexdump(addr)
            imm.log("addr after hexdump:" + str(addr))
            addr = addr[0][0]
            imm.log("addr[0][0]: " + str(addr))
            addr = str(addr).replace(" ", "")
            tempString = ''
            for s in range(len(addr) - 1, -1, -2):
                tempString = tempString + addr[s - 1] + addr[s]
            if addr:
                addr = int(tempString, 16)
            else:
                addr = 0
            iFileList.append("identifyEarlyAddressCheck result_line_2105: " + str(addr))

    if segmentSelector:
        if re.search(r'FS', segmentSelector):
            addr = addr + imm.getCurrentTEBAddress()
        elif re.search(r'CS', segmentSelector):
            imm.log("WARNING - CS segment selector was included and ignored in identifying call target")
            iFileList.append("WARNING - CS segment selector was included and ignored in identifying call target")
            iFileJson["debug_messages"].append(
                "WARNING - CS segment selector was included and ignored in identifying call target")
    return addr


def arithmetic(container, regs):
    intContainer = 0
    for c in container:
        cResult = re.search('EAX|ECX|EDX|EBX|ESP|EBP|ESI|EDI|EIP', c)
        if cResult:
            cMul = re.search('\*', c)
            if cMul:
                # this means that there is a multiplication
                mulParams = c.partition("*")
                intContainer = intContainer + (regs[mulParams[0]] * int(mulParams[2], 16))
            else:
                # there is no multiplication
                intContainer = intContainer + regs[cResult.group(0)]
            continue
        else:
            cResult = re.search(r'\w+', c)
            if cResult:
                # there is a hex number
                # I need to convert it from hex to int
                intContainer = intContainer + int(cResult.group(0), 16)
                continue
            else:
                imm.log("FATAL ERROR - LINE 1064")
                iFileList.append("Error: FATAL ERROR - LINE 1064")
                iFileJson["debug_messages"].append("Error: FATAL ERROR - LINE 1064")
                return -1
    return intContainer


def evaluateMemImpact(command, regs):
    result = re.search(r'^.+(?=,.+,)', command)
    if result:
        # this is a three operand instruction
        # imm.log("three operand Inst")
        result = result.group(0)  # this is the command + first operand
    else:
        result = re.search(r'^.+(?=,.+)', command)
        if result:
            # this is a two operand instruction
            # imm.log("two operand inst")
            result = result.group(0)  # this is the command + first operand
        else:
            # this is either a single or no operand instruction
            # command contains the actual instruction and if present the single operand
            # imm.log("single or no operand inst")
            result = command
    # the result I have now is for a instructions and potentially first operand.
    mFileList.append("result:" + result + "\n")
    destMemLocFlag = destMemLoc(result)
    mFileList.append("destMemLocFlag:" + str(destMemLocFlag) + "\n")
    if destMemLocFlag:
        lResult = result.partition(" ")
        list1 = checkInstFile(rFile1, lResult[0])
        list2 = checkInstFile(rFile2, lResult[0])
        if list1 or list2:
            addr = identifyAddrEarlyCheck(result, regs, 'general')
            mFileList.append("addr:" + hex(addr) + "\n")
            if addr != -1:
                return {'impact': True, 'address': addr, 'content': imm.readMemory(addr, 4)}
            else:
                return {'impact': True, 'address': 'unknown', 'content': 'unknown'}
        else:
            return {'impact': False, 'address': '', 'content': ''}
    else:
        return {'impact': False, 'address': '', 'content': ''}


def destMemLoc(parameter):
    # placeholder for checking if there is any brackets or not.
    result = re.search(r'\D\D:\[\S+\]', parameter)
    if result:
        # there is segment selector
        return True
    else:
        result = re.search(r'\[\S+\]', parameter)
        if result:
            # result contains a bracket (which should be the case)
            return True
    return False
