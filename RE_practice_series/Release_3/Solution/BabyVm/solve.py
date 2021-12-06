vmdump = open('vm_dump.vm', 'rb')
data = vmdump.read()
ops = ['mov reg val', 'mov reg reg', 'mov reg [mem]', 'mov [reg] val', 'mov reg [reg]', 
'mov [mem] val', 'mov [mem] reg', 'push val', 'push reg', 'push [reg]', 'pop reg', 
'pop [reg]', 'pop [mem]', 'add reg reg', 'add reg val', 'add reg [mem]', 'add [reg] val', 
'add [reg] reg', 'sub reg reg', 'sub reg val', 'sub reg [mem]', 'sub [reg] val', 
'sub [reg] reg', 'mul reg reg', 'mul reg val', 'mul reg [mem]', 'mul [reg] val', 
'mul [reg] reg', 'xor reg reg', 'xor reg val', 'xor reg [mem]', 'xor [reg] val', 
'xor [reg] reg', 'and reg reg', 'and reg val', 'and reg [mem]', 'and [reg] val', 
'and [reg] reg', '', '', '', '', '', 'not reg', 'not [reg]', 'not [mem]', 'cmp reg reg', 
'cmp reg val', 'cmp reg [mem]', 'cmp [reg] val', '', 'save_return_address (unk_7E9090[13] = unk_7E9090[12])', 
'make_label_tojump val (unk_7E9090[14] = unk_7E9090[12] + 12 * val)', 
'delete_save_return_address (unk_7E9090[13] = 0)', 'jmp return_address (unk_7E9090[12] = unk_7E9090[13])', 
'jmp label (unk_7E9090[12] = unk_7E9090[14])', 'jz return_address (unk_7E9090[12] = unk_7E9090[13])', 
'jz label (unk_7E9090[12] = unk_7E9090[14])', 'jnz return_address (unk_7E9090[12] = unk_7E9090[13])', 
'jnz label (unk_7E9090[12] = unk_7E9090[14])', 'putchar reg', 'getchar']
j = 0
for i in range(8, len(data), 12):
	op = data[i]
	val1 = int.from_bytes(data[i + 4:i + 8], byteorder='little', signed=False)
	val2 = int.from_bytes(data[i + 8:i + 12], byteorder='little', signed=False)
	print(str(j), end=' ')
	j += 1
	if (op >= len(ops)):
		print("nop")
	else:
		print(ops[op] + " " + str(val1) + " " + str(val2))
