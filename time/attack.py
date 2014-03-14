import sys, subprocess, random

# number of attacks
AttacksNo = 64
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
  
  return t

def encrypt( base, exponent, modulus ) :
  a = 1
  for i in exponent :
    a *= a
    if i == '1' :
      a *= base
    a = a % modulus
  return a





def attack( guess, pk, exp, time ) :
  # print "r = %d" % ( r )
  reductionTable = []
  # for now on attack only first bit
  for i in guess :
    reductionTable.append( binExp( i, exp, pk, 1 ) )

  print reductionTable

  return "NO Key!"


# perform limb operation with rest
def rest( x, cb ) :
  # carry
  if cb :
    C = x - (base-1)
    if C > 0 :
      return (C, base-1)
    else :
      return (0, x)

  # borrow
  else :
    if x > 0 :
      return (0, x)
    else :
      return (abs(x), 0)

# create limb with 0's fo given length
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


# Section 2.1 binary exponentiation | g ** r
#   *j* denote bit that we are attacking
def binExp( g, r, N, j ) :
  result = 1

  for n, i in enumerate( r ) : # --- start from most significant bit --- r[::-1]
    result *= result % N
    if i == '1' :
      result *= g % N
    # attack square
    if j == n :
      # return whether reduction was done or not
      # last bit must be guessed

              # # compute mot representation of base
              # base = 1
              # # compute mot representation of 1
              # one = 1

      # check reduction
      return CIOSMM( result, result, N )
  return -1


# mock the CIOS Montgomery Multiplication with w= 64 | b =  2 ** 64
#   return whether reduction was done or not
def CIOSMM( x, y, N ) :
  # *s* is the number of words in *x* and *y*
  # r = base ** inputSize

  print x
  print y
  print N

  a = limb( (x* base**inputSize)%N )[::-1]
  b = limb( (y* base**inputSize)%N )[::-1]
  n = limb(N)[::-1]
  t = nullLimb(inputSize+2)
  np0 = limb(nprime(N))[-1]

  for i in range( inputSize ) :
    C = 0
    for j in range( inputSize ) :
      (C, S) = rest( t[j] + a[j]*b[i] + C, True )
      t[j] = S
    (C, S) = rest( t[inputSize] + C, True )
    t[inputSize] = S
    t[inputSize + 1] = C
    C = 0
    m = ( t[0]*np0 ) % base
    for j in range( inputSize ) :
      (C, S) = rest( t[j] + m*n[j] + C, True )
      t[j] = S
    (C, S) = rest( t[inputSize] + C, True )
    t[inputSize] = S
    t[inputSize+1] = t[inputSize+1] + C
    for j in range(inputSize+1) :
      t[j] = t[j+1]
  # REDUCTION
  # B = 0
  # for i in range( inputSize ) :
  #   (B, D) = rest( t[i] - n[i] - B, False )
  #   t[i] = D
  # (B, D) = rest( t[wordSize] - B, False )
  # t[wordSize] = D
  # if B == 0 :

  out = 0
  for i in range(inputSize) :
    out += t[i]* base**i

  print (out* base**inputSize)%N

  if out > N :
    return True
  else :
    return False










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

  # interact
  time = interact(attacks)
  # attack
  secretKey = attack( attacks, publicKey[0], exp, time )
  print "%X" % ( secretKey )
