import sys, subprocess

# number of attacks
AttacksNo = 64

####
# Define parameters to distinguish attacks --- tuning-in
#
####

def interact( G ) :
  # Send      G      to   attack target.
  target_in.write( "%s\n" % ( G ) ) ; target_in.flush()

  # Receive ( t, r ) from attack target.
  t = int( target_out.readline().strip() )
  r = int( target_out.readline().strip() )

  return ( t, r )

def attack() :
  # Select a hard-coded guess ...
  G = "guess"

  # ... then interact with the attack target.
  ( t, r ) = interact( G )

  # Print all of the inputs and outputs.
  print "G = %s" % ( G )
  print "t = %d" % ( t )
  print "r = %d" % ( r )

# Section 2.1 binary exponentiation | g ** r
#   *j* denote bit that we are attacking
def binExp( g, r, N, j ) :
  a = 1

  # compute mot representation of base
  # compute mot representation of 1

  for n, i in enumerate( r ) : # --- start from most significant bit --- r[::-1]
    a *= a # CIOSMM( a, a, N )

    if i == '1' :
      a *= g # CIOSMM( a, g, N )

    # attack square
    if j == n :
      a *= a # CIOSMM( a, a, N )
      # return whether reduction was done or not
      # last bit must be guessed

  return a

# mock the CIOS Montgomery Multiplication with w= 64 | b =  2 ** 64
#   return whether reduction was done or not
def CIOSMM( x, y, N ) :
  w = 64
  b = 2 ** 64
  # *s* is the number of words in *x* and *y*



if ( __name__ == "__main__" ) :

  # Get the public key parameters
  publicKey = []
  with open( sys.argv[ 2 ] ) as f:
    for line in f:
        publicKey.append( line[:-1] )

  # change hex strings into int
  for i, k in enumerate( publicKey ) :
    publicKey[i] = long( k, 16 )

  print publicKey

  # generate 1024-bit strings for attacks --- #64
  # i = 0
  # attacks = []
  # while( i < AttacksNo ) :
    # rr = random.getrandbits( 1024 )
    # if rr < 

  # Produce a sub-process representing the attack target.
  target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE, 
                             stdin  = subprocess.PIPE )

  # Construct handles to attack target standard input and output.
  target_out = target.stdout
  target_in  = target.stdin

  # Execute a function representing the attacker.
  # attack()




  # check whether are less than N
  # encrypt them with e and N

  # 

  # start recovering by testing key {1,0,-,-,-,-,-,-}
  #                                 {1,1,-,-,-,-,-,-}
  #   and so on for each cypher-text and remember whether reduction occur or not
  # and measuring time for decryption of each cypher-text in real device
  # calculate correlation coefficient and choose the proper version
