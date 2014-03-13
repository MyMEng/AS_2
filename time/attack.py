import sys, subprocess

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
def binExp( g, r, N ) :
  a = 1
  for i in r : # --- start from most significant bit --- r[::-1]
    a *= a # CIOSMM( a, a, N )
    if i == '1' :
      a *= g # CIOSMM( a, g, N )
  return a

# mock the CIOS Montgomery Multiplication with w= 64 | b =  2 ** 64
def CIOSMM( x, y, N ) :
  w = 64
  b = 2 ** 64



if ( __name__ == "__main__" ) :

  publicKey = []
  # Get the public key parameters
  with open( sys.argv[ 2 ] ) as f:
    for line in f:
        publicKey.append( line[:-1] )



  # Produce a sub-process representing the attack target.
  target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE, 
                             stdin  = subprocess.PIPE )

  # Construct handles to attack target standard input and output.
  target_out = target.stdout
  target_in  = target.stdin

  # Execute a function representing the attacker.
  attack()
