encrypted = 'arln_pra_dfgafcchsrb_l{ieeye_ea}'

v19 = encrypted[:10]
v17 = encrypted[10:21]
v18 = encrypted[21:]

flag = [0] * 32

for i in range(len(v17)):
	flag[i * 3] = v17[i]

for i in range(len(v18)):
	flag[i * 3 + 1] = v18[i]

for i in range(len(v19)):
	flag[i * 3 + 2] = v19[i]

print(''.join(flag))
