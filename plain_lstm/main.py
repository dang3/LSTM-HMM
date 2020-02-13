import process

malware_path = "../data/malware/"
benign_path = "../data/benign/"
keep_amt = 29
last_key = "other"



list_of_files, most_common_codes = process.get_most_common_opcodes(keep_amt=keep_amt, 
                                                                last_key = last_key, 
                                                                malware_path = malware_path,
                                                                benign_path = benign_path)

print(list_of_files)
print(most_common_codes)