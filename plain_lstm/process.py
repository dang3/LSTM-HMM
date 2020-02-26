import os
from file_handler import File_Handler

opcodes_list = dict()

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

# count opcode instance
def process_handler(file_handler):
	cur_opcode_len = 0

	for file in file_handler.get_all_files():
		with open(file, 'r') as f:
			opcode = f.readline()
			while opcode:
				cur_opcode_len += 1
				opcode = opcode.strip()
				if opcode in opcodes_list:
					opcodes_list[opcode] += 1
				else:
					opcodes_list[opcode] = 1

				opcode = f.readline()
		
				
		if cur_opcode_len > file_handler.get_longest_opcode_seq():
			file_handler.set_longest_opcode_seq(cur_opcode_len)

		cur_opcode_len = 0


def get_most_common_opcodes(keep_amt, last_key, malware_path, benign_path):
	mal_handler = File_Handler(malware_path)
	ben_handler = File_Handler(benign_path)

	mal_handler.set_all_files(get_list_of_files(malware_path))
	ben_handler.set_all_files(get_list_of_files(benign_path))

	process_handler(mal_handler)
	process_handler(ben_handler)
	
	# sort opcodes in order of frequency (greatest to least)
	sort_opcodes = sorted(opcodes_list, key=opcodes_list.get, reverse=True)

	# find most common opcodes
	most_common_opcodes = dict()

	for i in range(keep_amt):
		key = sort_opcodes[i]
		most_common_opcodes[key] = i
	
	# insert last key for all other opcodes that are not most common
	most_common_opcodes[last_key] = keep_amt

	return mal_handler, ben_handler, most_common_opcodes

def find_malware_families(dir):
	families = dict()

	with open(dir, 'r') as file:
		lines = file.readlines()
	
	for line in lines:
		line = line.split(',')
		fileName = line[1].strip()
		family = line[9].strip()

		family = family.replace('\'', '')
		fileName = fileName.replace('\'', '')

		if family == "NULL":
			continue

		if family not in families:
			families[family] = []
		else:
			families[family].append(fileName)


	for key in families.keys():
		print("family: {}  num: {}".format(key, len(families[key])))

	return families



path = "../data/DB_RELEASE1.0.sql"

families = find_malware_families(path)


