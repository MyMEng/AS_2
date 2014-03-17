import sys, subprocess, random
from numpy import mean
# from time import clock
import numpy as np
from numpy import mean
from itertools import imap

def pearsonr(x, y):
  # Assume len(x) == len(y)
  n = len(x)
  sum_x = float(sum(x))
  sum_y = float(sum(y))
  sum_x_sq = sum(map(lambda x: pow(x, 2), x))
  sum_y_sq = sum(map(lambda x: pow(x, 2), y))
  psum = sum(imap(lambda x, y: x * y, x, y))
  num = psum - (sum_x * sum_y/n)
  den = pow((sum_x_sq - pow(sum_x, 2) / n) * (sum_y_sq - pow(sum_y, 2) / n), 0.5)
  if den == 0: return 0
  return num / den


def variance(li):
    avg = mean(li)
    sq_diff=0
    for elem in li:
        sq_diff += (elem - avg)**2
    return float(sq_diff) / float(len(li))



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
AttacksNo = 1000
wordSize = 64
base = 2 ** wordSize
# input is 1024 bits that is 16 limbs in base 2 ** 64
bits = 1024
inputSize = 16
keySize = 64

####
# Define parameters to distinguish attacks --- tuning-in
#    1024 cycles for 0 exp
#    1536 cycles for 1 exp
# 302EC28F32A7DF954C9589136DE15B1E5DD036E86DDD4AA0F5076F152C0D3A74F2508E1987EF4AF883A3C3FD2E4E04AC1512888126BAA8EA0537A12F195F5A96FC6B64D035FDA06BD42E5F0DC61EA5DC04FA141C0A95F1615F71316356F9F255648FE60FAA7E81069C3892E50C0CF387DF15CEACA0130ED1CB9852952E65CAC1
# EB3D0F3F6FE93288C441C49D9F2C16088E95FCABF7A42FC60DE0A01F4016D1FE10BBA25DC21F6843406A723E65E5562B510DA88E73C9CBE62C2594333897F902047096FB0020BFF20F9783F030A14399B20A1D464AA4B7AC928F6784A3A124C610512A9A0EB83B94C30ADEF06309A1205C6B9DC3442E5138E4F2F7AB5EC547CB
# 3 / 2 / 1
#
#  multiply step has 1536-1024=512 cycles
CoreT = 512
MultiplicationT = 512
ReductionT = 16#32
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
    # time that is left is reductions in multiplications + squares + reductions in squares
    t.append( int( target_out.readline().strip() )  )
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

  # print guess
  # baseline = interact([1])
  # print baseline

  # interact
  # time = interact(guess)

  baseline = interactR([1], N, exp)
  time = interactR(guess, N, exp)
  time[:] = [x - baseline[0] for x in time]
  # Et = mean(time)
  # delete = []
  # for i, t in enumerate(time) :
    # if abs(t-Et) > 33 :
    # if t < (ReductionT*keySize)/2  :
    # if abs(t-Et) > 15 :
    # if abs( t - ReductionT*(keySize/2) )  > 15 :
      # delete.append(i)

  # for i in delete[::-1] :
    # del time[i]
    # del guess[i]

  # give number of reductions
  time[:] = [x / ReductionT for x in time]

  print time
  
  print "Timing done!"

  # print "r = %d" % ( r )
  reductionTable1 = []
  reductionTable2 = []
  timingme1=[]
  timingme2=[]
  # as we know that first bit is 1 the multiplication step will take place
  # keyGuess = '1'
  # time[:] = [x - MultiplicationT for x in time]
  # but we still don't know whether reduction occurred there
  # ?
  # for now on attack only first bit

  # general timing
  # T = CoreT + keySize*MultiplicationT + MultiplicationT


  for j in range(3,len(exp)-1) : # last bit must be guessed
    for i in guess :

      # a[:] = [x - 13 for x in a]
      tupl = binExp( i, '1011', N, j )
      # print "tupl: ", tupl
      reductionTable1.append( tupl[0] )
      timingme1.append(tupl[1])

      # should we substract multiplication time

      tupl = binExp( i, '1010', N, j )
      reductionTable2.append( tupl[0] )
      timingme2.append(tupl[1])

      # shouldn we becous didnt occur

    print timingme1
    print "\n"
    print timingme2

    tuples1 = zip(reductionTable1, time, timingme1)
    tuples2 = zip(reductionTable2, time, timingme2)
    P, M = [], []
    PT, MT = [], []

    A, B, C, D = [], [], [], []
    E, F = [], []

    # T1r = T + 2*MultiplicationT + ReductionT
    # T1nr = T + 2*MultiplicationT
    for k in tuples1:
      A.append(k[1])
      E.append(k[2])
      # B.append(k[1]-k[2])
      if k[0] : # with reduction
        P.append(k[1])
        B.append(k[2])
        # B.append(T1r)
        # PT.append(k[2])
      else : # with reduction
        M.append(k[1])
        # B.append(T1nr)
        # MT.append(k[2])

    # T2r = T + MultiplicationT + ReductionT
    # T2nr = T + MultiplicationT
    for k in tuples2:
      C.append(k[1])
      F.append(k[2])
      # D.append(k[1]-k[2])
      if k[0] : # with reduction
        PT.append(k[1])
        D.append(k[2])
        # D.append(T2r)
        # PT.append(k[2])
      else : # with reduction
        MT.append(k[1])
        # D.append(T2nr)
        # MT.append(k[2])
    # print mean(P)
    # print mean(M)
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
    print "lower better"
    print variance([P[x] - B[x] for x in range(len(P))]) / variance(P)
    # print variance([P[x] - B[x] for x in range(len(P))])

    print variance([PT[x] - D[x] for x in range(len(D))]) / variance(PT)
    # print variance([PT[x] - D[x] for x in range(len(D))])
    print "\n"
    # print variance(P)/variance(B)
    # print variance(PT)/variance(D)
    print "higher better"
    print pearsonr (A,E)
    print pearsonr (C,F)
    # print np.corrcoef(A,B)[0][0]
    # print np.corrcoef(A,B)[1][1]
    # print np.corrcoef(C,D)[0][0]
    # print np.corrcoef(C,D)[1][1]

    # print P
    # print B
    # print PT
    # print D

    print "\n"
    # print reductionTable1
    # print reductionTable2
    reductionTable1=[]
    reductionTable2=[]
    timingme1=[]
    timingme2=[]
    # myTime = []
    # myTime1 = []
    # myTime2 = []







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
  # print "Cary in: ", x
  # carry
  C = x%base
  i = (x-C)/base
  if (x-C) % base != 0 :
    print "Carrying"
  # print "Cary out: ", i, "    ", C
  if i*2**64 + C != x or i >= 2**64 :
    print "goczja"
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

  if len(b) != bits :
    print "Limbing error"

  t = []
  for i in range(inputSize) :
    t.append(long(b[i*wordSize : (i+1)*wordSize], 2))


  # print "Limbo: ", t
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
  redno = 0
  # compute mot representation of 1
  # result = (1* base**inputSize)%N
  (red, result) = CIOSMM(1, rhosq(N), N)
  # print red

  # compute mot representation of base
  # g = (gr* base**inputSize)%N
  (red, g) = CIOSMM(gr, rhosq(N), N)
  # print red

  for n, i in enumerate( r ) : # --- start from most significant bit --- r[::-1]

    # print "Round: ", n

    # print "Comp1: ", result
    (red, result) = CIOSMM( result, result, N )#result *= result % N
    if red :
      redno +=1
    # print "Result: ", result

    if i == '1' :
      (red, result) = CIOSMM( result, g, N )#result *= g % N
      if red :
        redno +=1

    # attack square
    if j == n :
      # return whether reduction was done or not
      (bol, null) = CIOSMM( result, result, N )
      if bol :
        redno +=1
      return (bol,redno)

  # print result
  (red, result) = CIOSMM( result, 1, N )#result *= g % N
  if red :
    redno +=1
  # print result

  return (red, redno)


# mock the CIOS Montgomery Multiplication with w= 64 | b =  2 ** 64
#   return whether reduction was done or not
def CIOSMM( x, y, N ) :
  # *s* is the number of words in *x* and *y*
  if x >= 2**1024-1 or y >= 2**1024-1:
    print "SHOUT"
  # r = base ** inputSize
  a = limb( x )[::-1]
  b = limb( y )[::-1]
  n = limb( N )[::-1]
  t = nullLimb(inputSize+2)
  np0 = limb(nprime(N))[-1]

  for i in range( inputSize ) :
    C = 0
    
    # print t
    # print b
    # print "\n\n"

    for j in range( inputSize ) :
      (C, S) = rest( t[j] + a[j]*b[i] + C )
      t[j] = S
    (C, S) = rest( t[inputSize] + C )
    t[inputSize] = S
    t[inputSize + 1] = C


    C = 0
    m = ( t[0]*np0 ) % base


    # for j in range( inputSize ) :
    #   (C, S) = rest( t[j] + m*n[j] + C )
    #   t[j] = S
    # (C, S) = rest( t[inputSize] + C )
    # t[inputSize] = S
    # t[inputSize+1] = t[inputSize+1] + C

    # if t[0] != 0:
    #   print "Monti error!"

    # for j in range(inputSize+1) :
    #   t[j] = t[j+1]
    # print t
    # improvement
    (C,S) = rest( t[0] + m*n[0] )
    for j in range(1,inputSize) :
      (C,S) = rest( t[j] + m*n[j] + C )
      t[j-1] = S
    (C,S) = rest( t[inputSize] + C )
    t[inputSize-1] = S
    t[inputSize] = t[inputSize+1] + C
    # print t
    # print "-----"

  # REDUCTION
  # print t
  out = 0
  for i in range(inputSize+1) :
    out += t[i]* base**i

  if out >= N :
    return (True, out-N)
  else :
    return (False, out)


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
    # take first 512 bits from modulus
    # rr = long("{0:b}".format(publicKey[0])[:bits/2]+"{0:b}".format(random.getrandbits( bits/2 )), 2)
    # rr = long("{0:b}".format(publicKey[0])[:bits*63/64]+"{0:b}".format(random.getrandbits( bits/64 )), 2)
    # rr = random.getrandbits( 1 )

    # check whether are less than N
    if rr < publicKey[0] and rr%2==0 :
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
  attackExp = '1010'+20*'0'+20*'1'+20*'0'

  # secretKey = 
  attack( attacks, publicKey[0], attackExp )
  # print "%X" % ( secretKey )
