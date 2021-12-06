import time
c = int(time.time())
f = (c % 50) / 50
for _ in range(5):
	f = f * 3.8 * (1 - f)
print(int(f * 10000))
