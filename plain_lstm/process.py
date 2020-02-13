import os

def get_list_of_files(dir):
	subDirs = os.listdir(dir)
	all_files_sub = list()

	for subDir in subDirs:
		full_path = os.path.join(dir, subDir)
		if os.path.isdir(full_path):
			all_files_sub = all_files_sub + get_list_of_files(full_path)
		else:
			all_files_sub.append(full_path)
	
	return all_files_sub

def get_most_common_opcodes(keep_amt, last_key, malware_path, benign_path):
	# get opcodes for malware and benign samples
	malware_files = get_list_of_files(malware_path)
	benign_files = get_list_of_files(benign_path)

	list_of_files = malware_files + benign_files

	opcodes = dict()

	# count opcode instances
	for file in list_of_files:
		with open(file, 'r') as f:
			opcode = f.readline()
			while opcode:
				opcode = opcode.strip()
				if opcode in opcodes:
					opcodes[opcode] += 1
				else:
					opcodes[opcode] = 1

				opcode = f.readline()
	
	# sort opcodes in order of frequency (greatest to least)
	sort_opcodes = sorted(opcodes, key=opcodes.get, reverse=True)

	# find most common opcodes
	most_common_opcodes = dict()

	for i in range(keep_amt):
		key = sort_opcodes[i]
		most_common_opcodes[key] = i
	
	# insert last key for all other opcodes that are not most common
	most_common_opcodes[last_key] = keep_amt

	return malware_files, benign_files, most_common_opcodes

def x():
	return 1, 2, 3