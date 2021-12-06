import os
import time
user = os.getenv('USER')
time = time.localtime(time.time())
s = 'Wait, your name is' + user
s = [ord(i) for i in s]
for i in s:
	i ^= (time.tm_min >> time.tm_mday)
print(''.join([chr(i) for i in s]))