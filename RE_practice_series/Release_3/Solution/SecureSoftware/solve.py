username = 'BILL'
computername = 'DESKTOP-6TCCJEL'
a = [ord(i) % 16 for i in username + computername]
for i in a:
	print("%X" % i, end='')
