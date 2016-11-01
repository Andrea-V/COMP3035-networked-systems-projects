c=[]

def factorize(n):
	s=[]
	for j in range(n-1,1,-1):
		if n%j==0:
			s+=[j]
	return s

def fibonacci(n):
	a,b = 0,1
	while b<n:
		print b,
		a,b = b,a+b

#input part
while True:
	try:
		nMAX=int(raw_input("Insert a positive integer:"))
		if nMAX<=0:
			raise ValueError		
		break
	except ValueError:
		print "Bad input, plese try again..."


for i in range(2,nMAX):
	res=factorize(i)
	if not res:
		c+=[i]

for i in c:
	print i
print "prime numbers found:",len(c)

fibonacci(len(c))
