#! /usr/bin/python

import sys, subprocess, random
from numpy import mean

# number of attacks
AttacksNo = 8000
wordSize = 64
base = 2 ** wordSize
# input is 1024 bits that is 16 limbs in base 2 ** 64
bits = 1024
inputSize = 16

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
ReductionT = 16
####

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

# binary modular exponentiation
def encrypt( base, exponent, modulus ) :
  a = 1
  for i in exponent :
    a *= a
    if i == '1' :
      a *= base
    a = a % modulus
  return a

# attack given device
#   start recovering by testing key {1,0,-,-,-,-,-,-}
#                                   {1,1,-,-,-,-,-,-}
#   and so on for each cypher-text and remember whether reduction occurred
#   measuring time for decryption of each cypher-text
def attack( guess, N, exp ) :
  baseline = interact([1])
  # interact --- get time measurements
  time = interact(guess)
  print "Timing done!"

  # testing stage --- tuning parameters
  # baseline = interactR([1], N, exp)
  # time = interactR(guess, N, exp)
  # time[:] = [x - baseline[0] for x in time]
  # give number of reductions
  # time[:] = [x / ReductionT for x in time]

  # pre-compute 1 in Montgomery representation
  rsq = rhosq(N)
  (red, result) = CIOSMM(1, rsq, N)
  results = [result for i in range(AttacksNo)]
  reductionNo = [0 for i in range(AttacksNo)]
  exps = []
  for g in guess :
    (red, mg) = CIOSMM(g, rsq, N)
    exps.append(mg)

  print "All needed values precomputed!"
  
  # define needed variables
  reductionTable1 = []
  reductionTable2 = []
  timingme1=[]
  timingme2=[]
  results1 = []
  results2 = []

  # as we know that first bit is 1 the multiplication step will take place
  keyGuess = '1'
  # time[:] = [x - MultiplicationT for x in time]
  for x, i in enumerate(guess) :
    (nm,reductionNo[x],results[x], Non, Non, Non ) = binExp( i, '1', N, 0, results[x], exps[x], reductionNo[x] )

  print "Start knocking!"

  for j in range(1,len(exp)-1) : # last bit must be guessed
    for x, i in enumerate(guess) :
      # try guess 1
      tupl = binExp( i, '1', N, 0, results[x], exps[x], reductionNo[x] )
      reductionTable1.append( tupl[0] )
      if tupl[0]:
        niu = tupl[1] + 1
      else :
        niu = tupl[1]
      timingme1.append(niu)
      results1.append(tupl[2])

      # try guess 0
      # tupl = binExp( i, '0', N, 0, results[x], exps[x], reductionNo[x] )
      reductionTable2.append( tupl[3] )
      if tupl[3]:
        niu = tupl[4] + 1
      else :
        niu = tupl[4]
      timingme2.append(niu)
      results2.append(tupl[5])

    # create tuples for easier handling
    tuples1 = zip(reductionTable1, time, timingme1)
    tuples2 = zip(reductionTable2, time, timingme2)
    P, M = [], []
    PT, MT = [], []

    # testing variables --- testing
    # A, B, C, D, E, F, G, H = [], [], [], [], [], [], [], []

    # divide samples into two groups - 0:red/noRed | 1:red/noRed
    for k in tuples1:
      # A.append(k[1])
      # E.append(k[2])
      # B.append(k[1]-k[2])
      if k[0] : # with reduction
        P.append(k[1])
        # B.append(k[2])
      else : # withOUT reduction
        M.append(k[1])
        # G.append(k[2])
        # MT.append(k[2])
    for k in tuples2:
      # C.append(k[1])
      # F.append(k[2])
      # D.append(k[1]-k[2])
      if k[0] : # with reduction
        PT.append(k[1])
        # D.append(k[2])
        # PT.append(k[2])
      else : # withOUT reduction
        MT.append(k[1])
        # H.append(k[2])

    print "Averages for bit=1"
    print "Red:",mean(P)
    print "NRe:",mean(M)
    print "Averages for bit=0"
    print "Red:",mean(PT)
    print "NRe:",mean(MT)

    pm = mean(P) - mean(M)
    ptmt = mean(PT) - mean(MT)

    if pm > ptmt :
      keyGuess += '1'
      results = results1
      reductionNo = timingme1
    else :
      keyGuess += '0'
      results = results2
      reductionNo = timingme2
    print "Partial key: ", keyGuess
    print "\n"

    reductionTable1=[]
    reductionTable2=[]
    timingme1=[]
    timingme2=[]
    results1 = []
    results2 = []

    # if time with reductions are less than time without than we are done
    if keyGuess[-1] == '1' and pm < 0 :
      break
    elif keyGuess[-1] == '0' and ptmt < 0 :
      break

  # return key guess without last bit which must be guessed
  return keyGuess[:-1]


# perform limb operation with rest --- carry
def rest( x ) :
  # carry
  C = x%base
  i = (x-C)/base
  if (x-C) % base != 0 :
    print "Carrying error!"
  if i*2**64 + C != x or i >= 2**64 :
    print "Base error!"
  return(i, C)

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
def binExp( gr, r, N, j, res, g, reno  ) :
  # make local copy of variables
  result = res
  redno = reno

  for n, i in enumerate( r ) : # --- start from most significant bit
    # Square step
    (red, result) = CIOSMM( result, result, N )#result *= result % N
    if red :
      redno +=1

    # result redno is without additional multiplication step
    # variables for reduction
    resultR, rednoR = result, redno

    # Multiplication step
    # if i == '1' :
    (red, resultR) = CIOSMM( resultR, g, N )#result *= g % N
    if red :
      rednoR +=1

    # Attack square in chosen round(chosen bit)
    # if j == n :
    (bol, null) = CIOSMM( result, result, N )
    (bolR, null) = CIOSMM( resultR, resultR, N )
    # return whether reduction was done or not
    return (bolR, rednoR, resultR, bol, redno, result)

  #If missed loop return error
  return (-1, -1)


# mock the CIOS Montgomery Multiplication with w= 64 | b =  2 ** 64
#   return whether reduction was done or not
def CIOSMM( x, y, N ) :
  # *s* is the number of words in *x* and *y*
  if x >= 2**1024-1 or y >= 2**1024-1:
    print "CIOS-MM: operand out of range!"
  a = limb( x )[::-1]
  b = limb( y )[::-1]
  n = limb( N )[::-1]
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
  out = 0
  for i in range(inputSize+1) :
    out += t[i]* base**i
  # Reduction ?
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

  # get modulus
  modul = publicKey[0]

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
    else :
      # if does not fit --- try again
      print "Failed to recover key --- trying again!"
      pass
  print "Secret key in bin format: ", secretKey+LSB    
  print "Secret key in hex format: %X" % ( long(secretKey+LSB, 2) )
