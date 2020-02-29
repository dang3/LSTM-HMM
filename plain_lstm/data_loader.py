import os

# get all files in the given directory
def getListOfFiles(dir):
    subDirs = os.listdir(dir)
    allFilesSub = list()

    for subDir in subDirs:
        fullPath = os.path.join(dir, subDir)
        if os.path.isdir(fullPath):
            allFilesSub = allFilesSub + getListOfFiles(fullPath)
        else:
            allFilesSub.append(fullPath)
    
    return allFilesSub

# directory passed in should include ALL files (all malware and all benign)
def countOpcodes(dir):
    opcodesList = dict()
    allFiles = getListOfFiles(dir)

    for file in allFiles:
        with open(file, 'r') as f:
            opcodes = f.readlines()
        
        for opcode in opcodes:
            opcode = opcode.strip()

            if opcode in opcodesList:
                opcodesList[opcode] += 1
            else:
                opcodesList[opcode] = 1
    
    return opcodesList

# goes through list of all opcodes, find the most common ones and maps most common (the first 0 to keepAmt)
# opcodes with an int value, all other opcodes assigned a common number (lastKey)
def findMostCommonOpcodes(dir, keepAmt, lastKey):
    opcodesList = countOpcodes(dir)

    sortedOpcodes = sorted(opcodesList, key=opcodesList.get, reverse=True)

    mostCommonOpcodes = dict()

    for i in range(keepAmt):
        key = sortedOpcodes[i]
        mostCommonOpcodes[key] = i

    mostCommonOpcodes[lastKey] = keepAmt

    return mostCommonOpcodes

# return: list of all types of malware families from SQL file
# dir: directory of SQL file containing malware family labels for each malware file
def getMalwareFamList(dir):
    families = dict()

    with open(dir, 'r') as file:
        lines = file.readlines()
    
    for line in lines:
        line = line.split(',')
        fileName = line[1].strip().replace('\'', '')
        family = line[9].strip().replace('\'', '')

        if family == "NULL":
            continue

        if family not in families:
            families[family] = []

        families[family].append(fileName)

    return families


# return: list of files in order of the n most common malware
# n: look for the first n most common malware family
# malwareFamList: list containing all malware families with corresponding opcode files
def getMostCommonFamilies(dir, n):
    malwareFamList = getMalwareFamList(dir)
    sortedNamesList = sorted(malwareFamList, key = lambda k: len(malwareFamList[k]), reverse=True)
    listOfFiles = dict()

    for i in range(n):
        familyName = sortedNamesList[i]
        listOfFiles[familyName] = malwareFamList[familyName]

    return listOfFiles

# return trainset from given file directory
def getTrainData_benMal(filesDir, commonOpcodes, maxOpcodeLen, lastKey):
    trainFiles = getListOfFiles(filesDir)
    return getTrainData(trainFiles, commonOpcodes, maxOpcodeLen, lastKey)


def getTrainData(files, mostCommonOpcodes, maxOpcodeLen, lastKey):
    trainSet = list()

    for file in files:
        opcodeCounter = 0
        with open(file, 'r') as f:
            fileOpcodes = list()
            opcode = f.readline()

            while opcode and opcodeCounter < maxOpcodeLen:
                opcode = opcode.strip()

                if opcode in mostCommonOpcodes:
                    opcodeVal = mostCommonOpcodes[opcode]
                else:
                    opcodeVal = mostCommonOpcodes[lastKey]
                
                fileOpcodes.append(opcodeVal)
                opcodeCounter += 1
                
                opcode = f.readline()
        
        trainSet.append(fileOpcodes)

    return trainSet

# returns the most file names containing the opcode data that the model is to be trained on
# lengths of files corresponding to each malware family are the same to prevent the model
# from being trained too much on one family of malware
def getFileNames(mostCommonFams, malwareDir):
    trainSet = list()
    trainFilesTemp = list()
    trainFiles = list()

    zbotLen = 0

    for (key, value) in mostCommonFams.items():
        for v in value:
            path = malwareDir + key + "/" + v + ".asm.txt"
            if os.path.exists(path):
                trainFilesTemp.append(path)

                if "zbot" in path:
                    zbotLen += 1

    counter = 0
    for trainFile in trainFilesTemp:
        if ('winwebsec' in trainFile and counter < zbotLen) or ('zbot' in trainFile):
            trainFiles.append(trainFile)
            if 'winwebsec' in trainFile:
                counter += 1

    return trainFiles, zbotLen


# retrieves training data for binary classification on 2 families of malware
def getTrainData_malware(sqlDir, allFilesDir, malwareDir, maxOpcodeLen, lastKey, n, keepAmt):
    commonFams = getMostCommonFamilies(sqlDir, n)
    trainFiles, numLabels = getFileNames(commonFams, malwareDir)
    commonOpcodes = findMostCommonOpcodes(allFilesDir, keepAmt, lastKey)

    return getTrainData(trainFiles, commonOpcodes, maxOpcodeLen, lastKey), numLabels


