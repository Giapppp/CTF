import binascii

def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)
		return (g, x - (b // a) * y, y)

def modinv(a, m):
	g, x, y = egcd(a, m)
	if g != 1:
		raise Exception('modular inverse does not exist')
	else:
		return x % m

def gcd(a, b): 
	if a == 0: 
		return b 
	return gcd(b % a, a) 
dp = [[]]
def display(v):
	print(v)


def printSubsetsRec(arr, i, sum, p):

	if (i == 0 and sum != 0 and dp[0][sum]):
		p.append(arr[i])
		display(p)
		p = []
		return

	if (i == 0 and sum == 0):
		display(p)
		p = []
		return

	if (dp[i-1][sum]):
		b = []
		b.extend(p)
		printSubsetsRec(arr, i-1, sum, b)

	if (sum >= arr[i] and dp[i-1][sum-arr[i]]):
		p.append(arr[i])
		printSubsetsRec(arr, i-1, sum-arr[i], p)


def printAllSubsets(arr, n, sum):
	if (n == 0 or sum < 0):
		return

	global dp
	dp = [[False for i in range(sum+1)] for j in range(n)]

	for i in range(n):
		dp[i][0] = True
	if (arr[0] <= sum):
		dp[0][arr[0]] = True
	for i in range(1, n):
		for j in range(0, sum + 1):
			if (arr[i] <= j):
				dp[i][j] = (dp[i-1][j] or dp[i-1][j-arr[i]])
			else:
				dp[i][j] = dp[i - 1][j]
	if (dp[n-1][sum] == False):
		print("There are no subsets with sum ", sum)
		return
	p = []
	printSubsetsRec(arr, n-1, sum, p)





public_key = [7352, 2356, 7579, 19235, 1944, 14029, 1084]

w = [184, 332, 713, 1255, 2688, 5243, 10448]

q = 20910

ciphertext = [8436, 22465, 30044, 22465, 51635, 10380, 11879, 50551, 35250, 51223, 14931, 25048, 7352, 50551, 37606, 39550]



#Find r

"""
w[i] * r % q = public_key[i]
184 * r = 7352 (mod 20910)
92 * r = 3676 (mod 10455)
=> r = 7313
"""

r = 7313
r_ = modinv(r, q)
for c in ciphertext:
	c_ = (c * r_) % q
	printAllSubsets(w, 7, c_)
	print("---")

""" 
[10448, 184] 
---7 1
[10448, 5243, 184]
---7 6 1
[10448, 5243, 713, 184]
---7 6 3 1
[10448, 5243, 184]
---7 6 1
[10448, 5243, 1255, 713, 332, 184]
---7 6 4 3 2 1
[10448, 2688, 184]
---7 5 1
[2688, 713, 332]
---5 3 2
[5243, 1255, 713, 332, 184]
---6 4 3 2 1
[10448, 1255, 713, 184]
---7 4 3 1
[10448, 5243, 2688, 1255, 713, 184]
---7 6 5 4 3 1
[713, 184]
---3 1
[10448, 5243, 713, 332]
---7 6 3 2
[184]
---1
[5243, 1255, 713, 332, 184]
---6 4 3 2 1
[10448, 1255, 713, 332, 184]
---7 4 3 2 1
[10448, 2688, 1255, 713, 332, 184]
---7 5 4 3 2 1
"""
knapsacks = [[7, 1], [7, 6, 1], [7, 6, 3, 1], [7, 6, 1], [7, 6, 4, 3, 2, 1], [7, 5, 1], [5, 3, 2], [6, 4, 3, 2, 1], [7, 4, 3, 1], [7, 6, 5, 4, 3, 1], [3, 1], [7, 6, 3, 2], [1], [6, 4, 3, 2, 1], [7, 4, 3, 2, 1], [7, 5, 4, 3, 2, 1]]
for knapsack in knapsacks:
	temp = 0
	for c in knapsack:
		temp += pow(2, 7-c)
	print(chr(temp), end = '')
