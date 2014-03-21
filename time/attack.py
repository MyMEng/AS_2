#! /usr/bin/python
import sys, subprocess, random
from numpy import mean

# CONSTANTS
#   number of attacks
AttacksNo = 10000
#
wordSize = 64
base = 2 ** wordSize
# input is 1024 bits that is 16 limbs in base 2 ** 64
bits = 1024
inputSize = 16

# interact with real device
def interact( G ) :
  t = []
  # Send      G      to   attack target.
  for i in G :
    target_in.write( "%X\n" % ( i ) ) ; target_in.flush()
    # Receive time from attack target.
    t.append( int( target_out.readline().strip() ) )
    target_out.readline().strip()
  return t

# interact with altered device --- testing stage
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

# modular exponentiation --- testing stage
def encrypt( base, exponent, modulus ) :
  return pow(base, int(exponent, 2), modulus)

# attack given device
#   start recovering by testing key {1,0,-,-,-,-,-,-}
#                                   {1,1,-,-,-,-,-,-}
#   and so on for each cypher-text and remember whether reduction occurred
#   measuring time for decryption of each cypher-text
def attack( guess, N, exp ) :
  # interact --- get time measurements
  print "Timing..."
  time = interact(guess)
  print "Timing done!"

  print "Pre-computing constants..."
  global np0
  np0 = limb(nprime(N))[-1]
  # pre-compute 1 in Montgomery representation
  rsq = limb( rhosq(N) )[::-1]
  one = limb( 1 )[::-1]
  (red, result) = CIOSMM(one, rsq)
  results = [result for i in range(AttacksNo)]
  # prepare space for guess
  exps = []
  # change guess to limbs
  guess[:] =  [limb(x)[::-1] for x in guess]
  # change into Montgomery form
  for g in guess :
    (red, mg) = CIOSMM(g, rsq)
    exps.append(mg)
  print "All needed values precomputed!"
  
  # define needed variables
  resulting0 = []
  resulting1 = []
  count1Red = [0.0, 0]
  count1NoRed = [0.0, 0]
  count0Red = [0.0, 0]
  count0NoRed = [0.0, 0]

  # as we know that first bit is 1 the multiplication step will take place
  keyGuess = '1'
  # time[:] = [x - MultiplicationT for x in time]
  for x in range(AttacksNo) :
    (red, results[x]) = CIOSMM(results[x], results[x])
    (red, results[x]) = CIOSMM(results[x], exps[x])

  print "Start knocking!"
  while True :
    for x in range(AttacksNo) :
      # try guess (1, 1, 0, 0)
      # print "binexping"
      (one, Rone, zero, Rzero) = binExp( results[x], exps[x] )
      # for 1 in exp
      if one:
        count1Red[0] += time[x]
        count1Red[1] += 1
      else :
        count1NoRed[0] += time[x]
        count1NoRed[1] += 1
      # for 0 in exp
      if zero :
        count0Red[0] += time[x]
        count0Red[1] += 1
      else :
        count0NoRed[0] += time[x]
        count0NoRed[1] += 1

      # Remember results for future
      resulting1.append(Rone)
      resulting0.append(Rzero)

    # calculate average
    count1Red[0] /=  count1Red[1]
    count1NoRed[0] /=  count1NoRed[1]
    count0Red[0] /=  count0Red[1]
    count0NoRed[0] /=  count0NoRed[1]

    print "Averages for bit=1"
    print "Red:", count1Red[0]
    print "NRe:", count1NoRed[0]
    print "Averages for bit=0"
    print "Red:", count0Red[0]
    print "NRe:", count0NoRed[0]

    pm = count1Red[0] - count1NoRed[0]
    ptmt = count0Red[0] - count0NoRed[0]

    if pm > ptmt :
      keyGuess += '1'
      results = resulting1
    else :
      keyGuess += '0'
      results = resulting0
    print "Partial key: ", keyGuess
    print "\n"

    resulting0 = []
    resulting1 = []
    count1Red = [0.0, 0]
    count1NoRed = [0.0, 0]
    count0Red = [0.0, 0]
    count0NoRed = [0.0, 0]

    # if time with reductions are less than time without than we are done
    if keyGuess[-1] == '1' and pm < 0 :
      break
    elif keyGuess[-1] == '0' and ptmt < 0 :
      break

  # return key guess without last bit which must be guessed
  return keyGuess[:-1]


# perform limb operation with rest --- carry
def rest( x ) :
  (quotient, reminder) = divmod(x, base)
  # carry
    # if x >= base :
    #   print base -x
    #   return (1, base -x)
    # else :
    #   return (0, x)
  # C = x%base
  # i = (x-C)/base
  # if (x-C) % base != 0 :
  #   print "Carrying error!"
  # if i*2**64 + C != x or i >= 2**64 :
  #   print "Base error!"
  # return(i, C)
  return(quotient, reminder)

# define borrow operation
def borrow( x ) :
  if x < 0 :
    if base+x < 0 or base+x >= base :
      print base+x
    return (1, base+x)
  else :
    return (0, x)

# create limb filled with 0s of given length
def nullLimb( size ) :
  t = []
  for i in range( size ) :
    t.append(0)
  return t

# compute N'
def nprime( N ) :
  t = 1
  for i in range( wordSize - 1 ) :
    t = ( t * t * N ) % base
  return ( -1 * t ) % base

# create limb representation of given number --- index 0 is least significant
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
  return t

# calculate rho^2 to change into Montgomery
def rhosq(N) :
    t = 1
    for i in range(2*inputSize*wordSize):
        t = (t+t)%N
    return t

# Section 2.1 binary exponentiation | g ** r
#   *j* denote bit that we are attacking
def binExp( result, g  ) :
  # Square step --- already done
  # (red, result) = CIOSMM( result, result)#, N )#result *= result % N

  # Multiplication step if bit is '1'
  resultR = result
  (red, resultR) = CIOSMM( resultR, g)

  # Attack square in next round
  (bol, result) = CIOSMM( result, result)
  (bolR, resultR) = CIOSMM( resultR, resultR)
  # return whether reduction was done or not --- ('1', '1', '0', '0')
  return (bolR, resultR, bol, result)


# mock the CIOS Montgomery Multiplication with w= 64 | b =  2 ** 64
#   return whether reduction was done or not
# def CIOSMM( x, y, N ) :
def CIOSMM( a, b ) :
  # *s* is the number of words in *x* and *y*
    # if x >= 2**1024-1 or y >= 2**1024-1:
      # print "CIOS-MM: operand out of range!"
    # a = limb( x )[::-1]
    # b = limb( y )[::-1]
    # n = limb( N )[::-1]
    # np0 = limb(nprime(N))[-1]
  t = zeroArray
  # print t

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

    # for j in range( inputSize ) :
    #   (C, S) = rest( t[j] + m*n[j] + C )
    #   t[j] = S
    # (C, S) = rest( t[inputSize] + C )
    # t[inputSize] = S
    # t[inputSize+1] = t[inputSize+1] + C
    # for j in range(inputSize+1) :
    #   t[j] = t[j+1]

    # improvement ^|^
    (C,S) = rest( t[0] + m*n[0] )
    for j in range(1,inputSize) :
      (C,S) = rest( t[j] + m*n[j] + C )
      t[j-1] = S
    (C,S) = rest( t[inputSize] + C )
    t[inputSize-1] = S
    t[inputSize] = t[inputSize+1] + C

  # REDUCTION
  # B = 0
  # u = zeroArray
  # for i in range( inputSize ) :
  #   (B,D) = borrow( t[i] - n[i] - B )
  #   u[i] = D
  # (B, D) = borrow ( t[inputSize] - B )
  # u[inputSize] = D
  # if B == 0 :
  #   return (True, u[:-1])
  # else :
  #   return (False, t[:-1])
  out = 0
  for i in range(inputSize+1) :
    out += t[i]* base**i
  # Reduction ?
  if out >= N :
    return (True, limb(out-N)[::-1])
  else :
    return (False, limb(out)[::-1])

# add increased number of plaintext
if ( __name__ == "__main__" ) :
  # Globals
  np0, N, n, zeroArray = 0, 0, [], []

  # Get the public key parameters
  publicKey = []
  with open( sys.argv[ 2 ] ) as f:
    for line in f:
        publicKey.append( line[:-1] )

  # change hex strings into int
  for i, k in enumerate( publicKey ) :
    publicKey[i] = long( k, 16 )

  # get modulus
  modul = publicKey[0]
  N = modul
  n = limb( N )[::-1]

  # generate zero array of given length for Montgomery multiplication output
  zeroArray = nullLimb(inputSize+2)

  # put exponent to binary string
  exp = "{0:b}".format( publicKey[1] )

  # generate 1024-bit strings for attacks
  i = 0
  attacksE = []
  while( i < AttacksNo ) :
    rr = random.getrandbits( 1024 )
    # check whether are less than N
    if rr < modul :
      attacksE.append( rr )
      i += 1

  # encrypt them with e and N --- testing
  attacks =[]
  # for i in attacksE :
    # attacks.append( encrypt( i, exp, modul ) )
  attacks = attacksE

  print "Attacks Generated.\nStarting interaction."

  # implement algorithm from paper

  # Produce a sub-process representing the attack target.
  target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE, 
                             stdin  = subprocess.PIPE )

  # Construct handles to attack target standard input and output.
  target_out = target.stdout
  target_in  = target.stdin

  # d exponent for testing purposes --- testing
  attackExp = '1010'+20*'0'+20*'1'+19*'0'+'1'

  # generate random message --- encrypt --- decrypt --- comparison purpose
  while True :
    mess = random.getrandbits( 1024 )
    if mess < modul :
      break
  # encrypt
  cipher = encrypt(mess, exp, modul)
  # decrypt with device for comparison
  target_in.write( "%X\n" % ( cipher ) ) ; target_in.flush()
  # Receive time from attack target.
  ignore = int( target_out.readline().strip() )
  # Receive decyphered message from attack target.
  decipher = long( target_out.readline().strip(), 16)

  # attack until good key is found
  while True :
    secretKey = attack( attacks, modul, attackExp )
    if decipher == encrypt(cipher, secretKey+'1', modul):
      LSB = '1'
      break
    elif decipher == encrypt(cipher, secretKey+'0', modul):
      LSB = '0'
      break
    else : # if does not fit --- try again
      print "Failed to recover key --- trying again!"
  print "Secret key in bin format: ", secretKey+LSB    
  print "Secret key in hex format: %X" % ( long(secretKey+LSB, 2) )
