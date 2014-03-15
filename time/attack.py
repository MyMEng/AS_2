import sys, subprocess, random
from numpy import mean
from time import clock
# import numpy as np
from numpy import mean

############# code from Internet
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
############# code from Internet


# number of attacks
AttacksNo = 128
wordSize = 64
base = 2 ** wordSize
# input is 1024 bits that is 16 limbs in base 2 ** 64
bits = 1024
inputSize = 16

####
# Define parameters to distinguish attacks --- tuning-in
#
####

def interact( G ) :

  # start recovering by testing key {1,0,-,-,-,-,-,-}
  #                                 {1,1,-,-,-,-,-,-}
  #   and so on for each cypher-text and remember whether reduction occur or not
  # and measuring time for decryption of each cypher-text i

  t = []
  # Send      G      to   attack target.
  for i in G :
    target_in.write( "%X\n" % ( i ) ) ; target_in.flush()
    # Receive time from attack target.
    t.append( int( target_out.readline().strip() ) )
    target_out.readline().strip()
    # print "Timing: ", i, " done."
  
  return t

def interactR( G, N, d ) :
  t = []
  # Send      G      to   attack target.
  for i in G :
    target_in.write( "%X\n" % ( i ) ) ; target_in.flush()
    target_in.write( "%X\n" % ( N ) ) ; target_in.flush()
    target_in.write( "%X\n" % ( long(d, 2) ) ) ; target_in.flush()
    # Receive time from attack target.
    t.append( int( target_out.readline().strip() ) )
    target_out.readline().strip()
  return t

def encrypt( base, exponent, modulus ) :
  a = 1
  for i in exponent :
    a *= a
    if i == '1' :
      a *= base
    a = a % modulus
  return a




# d is assumed to have 64 bits
def attack( guess, N, exp ) :

  print guess

  # interact
  # time = interact(guess)
  time = interactR(guess, N, exp)
  print "Timing done!"
  # myTime = []

  # print "r = %d" % ( r )
  reductionTable1 = []
  reductionTable2 = []
  # for now on attack only first bit
  for j in range(1,len(exp)-1) : # last bit must be guessed
    for i in guess :
      # t0 = clock()
      reductionTable1.append( binExp( i, '11', N, j ) )
      reductionTable2.append( binExp( i, '10', N, j ) )
      # myTime.append(t0-clock())
    # print zip(reductionTable, time)
    # tuples = zip(reductionTable, myTime, time)
    tuples1 = zip(reductionTable1, time)
    tuples2 = zip(reductionTable2, time)
    P, M = [], []
    PT, MT = [], []
    for k in tuples1:
      if k[0] : # with reduction
        P.append(k[1])
        # PT.append(k[2])
      else : # with reduction
        M.append(k[1])
        # MT.append(k[2])
    for k in tuples2:
      if k[0] : # with reduction
        PT.append(k[1])
        # PT.append(k[2])
      else : # with reduction
        MT.append(k[1])
        # MT.append(k[2])
    # print mean(P)
    # print mean(M)
    # print time
    # print "goog"
    # print abs(mean(P)-mean(M))
    # print abs(mean(PT)-mean(MT))
      # print np.corrcoef(P,PT)[0][1]
      # print np.corrcoef(M,MT)[0][1]
    # print reductionTable

    print "M1:",mean(P)
    print "M2:",mean(M)
    # print abs(mean(P)-mean(M))
    print "M3:",mean(PT)
    print "M4:",mean(MT)
    # print abs(mean(PT)-mean(MT))

    print "\n"
    reductionTable1=[]
    reductionTable2=[]
    # myTime = []







    # for i in guess :
    #   reductionTable.append( binExp( i, '1000'+60*'0', N, j ) )
    # # print zip(reductionTable, time)
    # tuples = zip(reductionTable, time)
    # P, M = [], []
    # for k in tuples:
    #   if k[0] :
    #     P.append(k[1])
    #   else :
    #     M.append(k[1])
    # # print mean(P)
    # # print mean(M)
    # # print time
    # print "nogoo"
    # print abs(mean(P)-mean(M))
    # average.append(abs(mean(P)-mean(M)))
    # print reductionTable
    # reductionTable=[]









    # time = []
  # print mean(average)
  # return "NO Key!"


# perform limb operation with rest
def rest( x ) :
  # carry
  C = x%base
  i = (x-C)/base
  return(i, C)

# create limb with 0's for given length
def nullLimb( size ) :
  t = []
  for i in range( size ) :
    t.append(0)
  return t

# compute np
def nprime( N ) :
  t = 1
  for i in range( wordSize - 1 ) :
    t = ( t * t * N ) % base
  return ( -1 * t ) % base

# create limb representation of given number
# index 0 is least significant
def limb( a ) :
  b = "{0:b}".format(a)

  # padding
  if len(b) != bits :
    b = (bits-len(b))*'0' + b

  t = []
  for i in range(inputSize) :
    t.append(int(b[i*wordSize : (i+1)*wordSize], 2))
  return t

# calculate rho^2 to change into Montgomery
def rhosq(N) :
    t = 1
    for i in range(2*inputSize*wordSize):
        t = (t+t)%N
    return t

# Section 2.1 binary exponentiation | g ** r
#   *j* denote bit that we are attacking
def binExp( gr, r, N, j ) :
  # compute mot representation of 1
  # result = (1* base**inputSize)%N
  (null, result) = CIOSMM(1, rhosq(N), N)

  # compute mot representation of base
  # g = (gr* base**inputSize)%N
  (null, g) = CIOSMM(gr, rhosq(N), N)

  for n, i in enumerate( r ) : # --- start from most significant bit --- r[::-1]
    (null, result) = CIOSMM( result, result, N )#result *= result % N
    if i == '1' :
      (null, result) = CIOSMM( result, g, N )#result *= g % N
    # attack square
    if j == n :
      # return whether reduction was done or not
      (bol, null) = CIOSMM( result, result, N )
      return bol
  return -1


# mock the CIOS Montgomery Multiplication with w= 64 | b =  2 ** 64
#   return whether reduction was done or not
def CIOSMM( x, y, N ) :
  # *s* is the number of words in *x* and *y*
  # r = base ** inputSize
  a = limb( x )[::-1]
  b = limb( y )[::-1]
  n = limb(N)[::-1]
  t = nullLimb(inputSize+2)
  np0 = limb(nprime(N))[-1]

  for i in range( inputSize ) :
    C = 0
    for j in range( inputSize ) :
      (C, S) = rest( t[j] + a[j]*b[i] + C )
      t[j] = S
    (C, S) = rest( t[inputSize] + C )
    t[inputSize] = S
    t[inputSize + 1] = C
    C = 0
    m = ( t[0]*np0 ) % base
    for j in range( inputSize ) :
      (C, S) = rest( t[j] + m*n[j] + C )
      t[j] = S
    (C, S) = rest( t[inputSize] + C )
    t[inputSize] = S
    t[inputSize+1] = t[inputSize+1] + C

    if t[0] != 0:
      print "Monti error!"

    for j in range(inputSize+1) :
      t[j] = t[j+1]
  # REDUCTION
  out = 0
  for i in range(inputSize) :
    out += t[i]* base**i

  if out > N :
    return (True,out-N)
  else :
    return (False,out)


if ( __name__ == "__main__" ) :

  # Get the public key parameters
  publicKey = []
  with open( sys.argv[ 2 ] ) as f:
    for line in f:
        publicKey.append( line[:-1] )

  # change hex strings into int
  for i, k in enumerate( publicKey ) :
    publicKey[i] = long( k, 16 )

  # put exponent to binary string
  exp = "{0:b}".format( publicKey[1] )

  # generate 1024-bit strings for attacks --- #64
  i = 0
  attacksE = []
  while( i < AttacksNo ) :
    rr = random.getrandbits( 1024 )
    # check whether are less than N
    if rr < publicKey[0] :
      attacksE.append( rr )
      i += 1

  # encrypt them with e and N
  attacks =[]
  for i in attacksE :
    attacks.append( encrypt( i, exp, publicKey[0] ) )

  print "Attacks calculated.\nStarting interaction."

  # implement algorithm from paper

  # Produce a sub-process representing the attack target.
  target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE, 
                             stdin  = subprocess.PIPE )

  # Construct handles to attack target standard input and output.
  target_out = target.stdout
  target_in  = target.stdin

  # attack
  # assume exponent is all 1's
  # d is assumed to have 64 bits
  attackExp = '1111'+20*'1'+20*'0'+20*'1'

  # secretKey = 
  attack( attacks, publicKey[0], attackExp )
  # print "%X" % ( secretKey )
