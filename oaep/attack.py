#! /usr/bin/python
import sys, subprocess, random
from hashlib import sha1

# Define error codes
SUCCESS       = 0
ERROR1        = 1
ERROR2        = 2
P_OUTOFRANGE  = 3
C_OUTOFRANGE  = 4
M_LENGTH      = 5
C_LENGTH      = 6
CH_LENGTH     = 7
OTHER         = 8
# Define constants
inputSize = 256
UIDnumber = 4

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
    print ( "Manger1, couldn't find right value; error#: ", response, " f_1: ",
      f_1 )

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
    print ( "Manger2, couldn't find right value; error#: ", response, " f_2: ",
      f_2 )

  # if all good give back f_2
  return f_2

def manger3(f_2, B) :
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
      print ("Manger3, couldn't find right value; error#: ", response, " f_2: ",
        f_2, " m_min: ", m_min, " m_max: ", m_max)

  return ( "%X" % m_min ).zfill( inputSize )

# EME-OAEP decoding
def magic(f_3, k) :
  # a)
  # Define null label
  label = ''
  # Get hash of empty label
  lHash = sha1(label).hexdigest()
  hLen = sha1(label).digest_size

  # b)
  Y, maskedSeed, maskedDB = f_3[:2], f_3[2:2*(hLen+1)], f_3[2*(hLen+1):]

  # c)
  seedMask = MGF1( maskedDB, hLen )

  # d)
  seed = '%X' % ( int(maskedSeed, 16) ^ int(seedMask, 16) )

  # e)
  dbMask = MGF1( seed, k-hLen-1 )

  # f)
  DB = '%X' % ( int(maskedDB, 16) ^ int(dbMask, 16) )

  # g)
  OxOI_n = DB.find('01', 2*hLen)
  lHash_p, PS, OxOI, M = ( DB[:2*hLen], DB[2*hLen:OxOI_n], DB[OxOI_n:OxOI_n+2],
    DB[OxOI_n+2:] )

  if OxOI != '01' or OxOI_n == -1 :
    print "Decryption error!"
    print "Serious issue with decoding message! ", OxOI, " is not 0x01 !"
    print "Actual value: ", OxOI
    exit()
  if int(lHash_p, 16) != int(lHash, 16) :
    print "Decryption error!"
    print "lHashes are not equal!"
    print "lHash: ", lHash, "\nlHash': ", lHash_p
    exit()
  if int(Y, 16) != 0 :
    print "Decryption error!"
    print "Y is not 0; Y is: ", Y

  return M

# Section 4.1
def I2OSP(x, xLen) :
  # 1
  if x >= xLen ** inputSize :
    print "Integer too large!"
    exit()
  # 2 --- 256 is 2^8 --- 8-bit --- change to HEX group by 2
  t = "%X" % x
  # 3 --- fill with leading zeros --- remember it's in pairs
  t = t.zfill(2*xLen)

  return t

# Appendix B.2.1
def MGF1(mgfSeed, maskLen) :
  # 1
  if maskLen >= 2**32 :
    print "Mask too long!"
    exit()

  # 2
  T = ''
  hLen = sha1(T).digest_size

  # 3
  for counter in range( longCeil(maskLen, hLen) ) :
    # 3.a
    C = I2OSP( counter, 4 )
    # 3.b
    hh = sha1( (str(mgfSeed)+C).decode('hex') ).hexdigest()
    T += hh

  # Check for error
  if len(T) < 2*maskLen :
    print "MGF1 error; T to short: ", T
    exit()

  # 4
  return T[:2*maskLen]

# change integer into octet where *leng* is number of octets
def UIDdecode( strin, leng ) :
  hexBig = ( "%X" % strin ).zfill(2*leng)
  t = ""
  for i in range(2*leng) :
    t = hexBig[2*i : 2*(i+1)] + t
  return t

if ( __name__ == "__main__" ) :
  # Define public key
  modulus, public, cipher = 0, 0, 0

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

  # Get UID for attack --- assume user name is of the form: ab1234
  UIDcheck = "id -u "+ sys.argv[2][:-7]
  idcheck = subprocess.Popen( UIDcheck, stdout=subprocess.PIPE, shell=True)
  (out, err) = idcheck.communicate()
  if err!=None:
    print "Couldn't find UID."
    print err
    exit()
  UID = int(out)
  begining = UIDdecode(UID, UIDnumber)

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
  f3 = manger3(f2, B)
  print "Progress check 3!"
  print "f_3: ", f3
  message = magic(f3, k)
  print "Recovered message: ", message

  # check validity of message for UID
  if begining.lower() != message[:2*UIDnumber].lower() :
    print "Validity check w.r.t UID: NOT OK"
  print "Validity check w.r.t UID: OK"
