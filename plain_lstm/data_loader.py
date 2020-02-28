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
def findMostCommonOpcodes(dir, opcodesList, keepAmt, lastKey):
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
def getTrainData(filesDir, mostCommonOpcodes, maxOpcodeLen, lastKey):
    files = getListOfFiles(filesDir)

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

def getTrainData_malware(sqlDir, mostCommonOpcodes, maxOpcodeLen, lastKey, n):
    mostCommonFams = getMostCommonFamilies(sqlDir, n)






allFilesDir = '../data/samples/'
malFamFileDir = '../data/DB_RELEASE1.0.sql'
malwareDir = "../data/malware/"
benignDir = "../data/benign"

# allFiles = getListOfFiles(allFilesDir)
# opcodesList = countOpcodes(allFiles)
# mostCommonOpcodes = findMostCommonOpcodes(opcodesList, 29, 'other')
malwareFamList = getMalwareFamList(malFamFileDir)

getMalwareFiles(malwareFamList, 2)



