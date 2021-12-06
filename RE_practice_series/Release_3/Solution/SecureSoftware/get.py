s = input().strip()
d = ''
for i in s:
	d += chr(ord(i) - 1)

print(d)
