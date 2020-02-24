class File_Handler:
	def __init__(self, file_path):
		self.file_path = file_path
		self.all_files = list()
		self.valid_files = list()
		self.longest_opcode_seq = -1

	def append_file(self, name):
		self.valid_files.append(name)

	def get_num_files(self):
		return len(self.valid_files)

	def set_longest_opcode_seq(self, val):
		self.longest_opcode_seq = val

	def get_longest_opcode_seq(self):
		return self.longest_opcode_seq

	def set_all_files(self, l):
		self.all_files = l

	def get_all_files(self):
		return self.all_files

	def get_files(self):
		return self.all_files