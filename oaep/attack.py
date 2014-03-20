#! /usr/bin/python
import sys, subprocess, random
# from math import floor
# from math import ceil

# Define constants
SUCCESS       = 0
ERROR1        = 1
ERROR2        = 2
P_OUTOFRANGE  = 3
C_OUTOFRANGE  = 4
M_LENGTH      = 5
C_LENGTH      = 6
CH_LENGTH     = 7
OTHER         = 8

# Define public key
modulus, public, cipher = None, None, None

wordSize = 64
base = 2 ** wordSize
inputSize = 256


# change integer into octet where *leng* is number of octets
def octets( strin, leng ) :
  binin = "{0:b}".format(strin)
  binin = binin.zfill(leng*8)[::-1] # little endian??
  octout = ""
  for i in range(leng*2) :
    octout += "%X" % ( int(binin[i*4 : (i+1)*4], 2) )
  return octout

def interact( G ) :
  # Send      G      to   attack target --- G must be 256 characters HEX.
  target_in.write( "%s\n" % ( "%X" % G ).zfill(inputSize) ) ; target_in.flush()
  # Receive time from attack target.
  err = int( target_out.readline().strip() )
  return err

def generateAttack( f ) :
  return ( pow( f, public, modulus ) * cipher ) % modulus

def manger1() :
  # 1.1
  f_1 = 2
  # 1.2
  response = interact( generateAttack( f_1 ) )

  # 1.3 a/b
  while response == ERROR2 :
    f_1 *= 2
    response = interact( generateAttack( f_1 ) )

  # do we get what we want?
  if response != ERROR1 :
    print "Manger1, couldn't find right value; error#: ", response, " f_1: ", f_1

  # if all good give back f_1
  return f_1

# division with floor
def longFloor(a, b) :
  t = a % b
  return (a- t)/b

# division with ceiling
def longCeil(a, b):
  t = a%b
  if t > 0 :
    return (a- t)/b +1
  else :
    return (a- t)/b

def manger2(f_1, B) :
  t = f_1 / 2
  # 2.1
  # f_2 = t * int( floor( ( modulus + B ) / B ) )
  f_2 = t * longFloor( ( modulus + B ), B )
  # 2.2
  response = interact( generateAttack( f_2 ) )
  # 2.3 a/b
  while response == ERROR1 :
    f_2 += t
    response = interact( generateAttack( f_2 ) )

  # do we get what we want?
  if response != ERROR2 :
    print "Manger2, couldn't find right value; error#: ", response, " f_2: ", f_2

  # if all good give back f_2
  return f_2

def manger3(f_2, k, B) :
  # 3.1
  m_min = longCeil(modulus, f_2)
  m_max = longFloor( (modulus+B), f_2)
  # 3.2
  while m_min != m_max :
    f_temp = longFloor( 2*B, (m_max-m_min) )
    # 3.3
    i = longFloor( f_temp*m_min, modulus )
    # 3.4
    f_3 = longCeil( i*modulus, m_min )
    response = interact( generateAttack( f_3 ) )
    # 3.5
    if response == ERROR1 :
      m_min = longCeil( (i*modulus + B), f_3 )
    elif response == ERROR2 :
      m_max = longFloor( i*modulus + B, f_3 )

    # check for error
    if m_max<m_min :
      print "Manger3, couldn't find right value; error#: ", response, " f_2: ",
        f_2, " m_min: ", m_min, " m_max: ", m_max

  return m_max

if ( __name__ == "__main__" ) :
  # give access to globals
  global modulus
  global public
  global cipher

  # Get the public key parameters
  publicKey = []
  with open( sys.argv[ 2 ] ) as f:
    for line in f:
        publicKey.append( line[:-1] )

  # change hex strings into int
  modulus = long( publicKey[0], 16 )
  public  = long( publicKey[1], 16 )
  cipher  = long( publicKey[2], 16 )

  # # Produce a sub-process representing the attack target.
  target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE, 
                             stdin  = subprocess.PIPE )

  # Construct handles to attack target standard input and output.
  target_out = target.stdout
  target_in  = target.stdin

  # Get UID for attak
  UIDcheck = "id -u "+ sys.argv[2][:-7]
  idcheck = subprocess.Popen( UIDcheck, stdout=subprocess.PIPE, shell=True)
  (out, err) = idcheck.communicate()
  if err!=None:
    print "Couldn't find UID."
    print err
    exit()
  UID = int(out)

  m = "" + octets(UID, 4) # ????

  # Calculate constants k and B
  # ceil( log_{256} N ) = # of octets in N = ( # of hex in N )/2 | N = public[0]
  k = len( publicKey[0] ) / 2
  B = 2 ** (8 * (k-1))

  # Step 1
  f1 = manger1()
  print "Progress check 1!"
  print "f_1: ", f1
  # Step 2
  f2 = manger2(f1, B)
  print "Progress check 2!"
  print "f_2: ", f2
  # Step 3
  f3 = manger3(f2, k, B)
  print "Progress check 3!"
  print "f_3: ", f3
