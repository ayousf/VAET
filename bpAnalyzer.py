import immlib
import immutils
import time
from datetime import datetime
import re

imm = immlib.Debugger()


def usage(imm):
    imm.log("bpAnalyzer script")
    imm.log("bpAnalyzer -d <number> <-a|-f|-s>")
    imm.log("-d : duration to run the script for. Must be in seconds -- mandatory item")
    imm.log("One switch only from the below must be selected")
    imm.log("-a: **2** used to identify bp after exploit **augmented mode: this is used in addition to some manual work to filter through the frequencies of "
            "different iterations of kernel symbols")
    imm.log("-f: **3** used to help breakout of loops **frequency mode: this has an objective of going in the first iteration to get the frequency of kernel "
            "symbols, no iterations required")
    imm.log("-s: **1** used to identify all breakpoints before exploit launch ** steady state mode: this has an objective of identifying all symbols triggered, regardless of "
            "frequency for a specific duration")


def main(args):
    imm.log("bpAnalyzer STARTED")
    imm.log("args:" + str(args))
    modKernel = imm.findModuleByName("kernel32.dll")
    kernelDict = {}
    # len         1   2          3
    # args        0   1          2
    # bpAnalyzer -d <number> -f/-a/-s
    # -f : frequency mode. Manual mode, that performs the first iteration of calculating the frequency of bps.
    # -a : augmented mode. reads a kernel file for breakpoints that should be disabled, disables them, and proceeds on
    # with more breakpoints. This steps requires some manual preparation of the file.
    # -s : steady state mode. Flow through the breakpoints, whenever one is hit, it records that breakpoint, disables
    # it and then moves on.
    if len(args) == 3:
        if args[0] == '-d':
            duration = int(args[1])
        else:
            return "PROGRAM ENDED BECAUSE OF WRONG ARGUMENT. PLEASE REVIEW USAGE()"
        if modKernel:
            # symbols is a dict
            # symbols = {int_addr: debugtypes.Symbol, int_addr: debugtypes.Symbol}
            symbols = modKernel.getSymbols()
            for sym in symbols:
                # imm.log(str(symbols[sym].getName()))
                tempName = symbols[sym].getName()
                result = re.search('\.', tempName)
                if result is None:
                    fullSymName = "Kernel32." + str(symbols[sym].getName())
                    kernelDict[fullSymName] = {'freq': 0, 'addr': int(sym), 'detected': False, 'order':0}
        for sym in kernelDict:
            imm.setBreakpoint(kernelDict[sym]['addr'])
        if args[2] == '-a':
            kernelPath = "C:\\Users\\testing\\Desktop\\symbols_before_exploit.txt"
            kernelFile = open(kernelPath, "r")
            for line in kernelFile:
                line = line.rstrip('\n')
                imm.deleteBreakpoint(int(line))
        if args[2] == '-a' or args[2] == '-f':
            imm.run()
            continueFlag = True
            now = datetime.now()
            order = 1
            while continueFlag:
                foundFlag = False
                status = imm.getStatus()
                if status == 1:
                    current = imm.getCurrentAddress()
                    for sym in kernelDict:
                        if kernelDict[sym]['addr'] == current:
                            imm.log("breakpoint found")
                            if not kernelDict[sym]['detected']:
                                kernelDict[sym]['detected'] = True
                                kernelDict[sym]['order'] = order
                                order += 1
                            kernelDict[sym]['freq'] += 1
                            foundFlag = True
                            break
                    if not foundFlag:
                        imm.log("anomaly")
                    current = datetime.now()
                    diffMin2Sec = (current.minute - now.minute)*60
                    diffSec = current.second - now.second
                    totalDiff = diffMin2Sec + diffSec
                    if totalDiff >= duration:
                        break
                    else:
                        imm.run()
            if args[2] == '-a':
                printPath = "C:\\Users\\testing\\Desktop\\symbols_after_exploit.txt"
            else:
                printPath = "C:\\Users\\testing\\Desktop\\symbols_freq.txt"
            fileLogHandle = open(printPath, "w")
            fileLogHandle.close()
            fileLogHandle = open(printPath, "a")
            fileLogHandle.write("Duration: " + str(duration) + "\n")
            if args[2] == '-a':
                for elem in kernelDict:
                    if kernelDict[elem]['detected']:
                        fileLogHandle.write(str(kernelDict[elem]['order'])+"."+str(elem))
                        fileLogHandle.write("\n")
                fileLogHandle.close()
                return "PROGRAM TERMINATED"
            else:
                combinedName = []
                freq = []
                for elem in kernelDict:
                    combinedName.append(elem + ":" + str(kernelDict[elem]['addr']))
                    freq.append(kernelDict[elem]['freq'])
                topElements = sorted(zip(freq, combinedName), reverse=True)[0:len(combinedName)]
                for elem in topElements:
                    fileLogHandle.write(str(elem))
                    fileLogHandle.write("\n")
                # for elem in kernelDict:
                #     fileLogHandle.write("{" + str(elem) + ":" + str(kernelDict[elem]) + "}\n")
                fileLogHandle.close()
                return "PROGRAM TERMINATED"
        if args[2] == '-s':
            imm.run()
            continueFlag = True
            now = datetime.now()
            symbolsBefore = []
            while continueFlag:
                status = imm.getStatus()
                if status == 1:
                    current = imm.getCurrentAddress()
                    for sym in kernelDict:
                        if kernelDict[sym]['addr'] == current:
                            imm.deleteBreakpoint(current)
                            imm.log("breakpoint found")
                            symbolsBefore.append(kernelDict[sym]['addr'])
                            break
                    current = datetime.now()
                    diffMin2Sec = (current.minute - now.minute) * 60
                    diffSec = current.second - now.second
                    totalDiff = diffMin2Sec + diffSec
                    if totalDiff >= duration:
                        break
                    else:
                        imm.run()
                else:
                    current = datetime.now()
                    diffMin2Sec = (current.minute - now.minute) * 60
                    diffSec = current.second - now.second
                    totalDiff = diffMin2Sec + diffSec
                    if totalDiff >= duration:
                        break
            printPath = "C:\\Users\\testing\\Desktop\\symbols_before_exploit.txt"
            fileLogHandle = open(printPath, "w")
            fileLogHandle.close()
            fileLogHandle = open(printPath, "a")
            for sym in symbolsBefore:
                fileLogHandle.write(str(sym))
                fileLogHandle.write("\n")
            fileLogHandle.close()
            return "PROGRAM TERMINATED"

    else:
        return "PROGRAM TERMINATED BECAUSE OF WRONG NUMBER OF ARGUMENTS. PLEASE RUN USAGE()"


