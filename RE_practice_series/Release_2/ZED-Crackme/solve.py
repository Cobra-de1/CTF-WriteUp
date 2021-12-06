v6 = 'AHi23DEADBEEFCOFFEE'

s1 = chr(ord(v6[0]) ^ 2) + chr(ord(v6[3]) - 10) + chr(ord(v6[2]) + 12) + v6[2] + chr(ord(v6[1]) + 1)

for i in range(5, 19):
	s1 += chr(ord(v6[i]) - 1)

print(s1)