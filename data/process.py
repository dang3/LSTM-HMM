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

malware_path = "malware/"
opcodes = dict()
keep_amt = 29
counter = 0
most_common = dict()
last_key = "other"
observation = list()

list_of_files = get_list_of_files(malware_path)

for file in list_of_files:
	with open(file, 'r') as f:
		opcode = f.readline()

		while opcode:
			opcoded = opcode.strip()
			if opcode in opcodes:
				opcodes[opcode] += 1
			else:
				opcodes[opcode] = 1

			opcode = f.readline()

sort_opcodes = sorted(opcodes, key=opcodes.get, reverse=True)

for i in range(keep_amt):
	key = sort_opcodes[i]
	most_common[key] = i

most_common[last_key] = keep_amt+1










