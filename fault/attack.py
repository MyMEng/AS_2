#! /usr/bin/python
import sys, subprocess, random
from numpy import mean
from numpy import zeros
from numpy import matrix
from numpy import corrcoef # from scipy.stats.stats import pearsonr
from numpy import where
import struct, Crypto.Cipher.AES as AES
from struct import pack
from struct import unpack
from pprint import pprint
import multiprocessing

# CONSTANTS
#  *r* (represented as a decimal integer string) - round in which fault occurs
r          = 8
#  *f* specifies the round function in which the fault occurs
f          = 1
#  *p* specifies whether the fault occurs before or after execution
p          = 0
#  *i*, *j* specify the row and column of the state matrix which fault occurs
i, j       = 0, 0

# key testing rounds
testTrials = 5

# key size
keySize = 128

# Rijndael S-box
# taken from: http://anh.cs.luc.edu/331/code/aes.py
sbox =  [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
         0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
         0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
         0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
         0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
         0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
         0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
         0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
         0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
         0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
         0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
         0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
         0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
         0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
         0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
         0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
         0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
         0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
         0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
         0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
         0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
         0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
         0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
         0x54, 0xbb, 0x16]

SboxLookup = matrix([
  [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
  [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
  [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
  [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
  [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
  [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
  [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
  [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
  [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
  [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
  [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
  [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
  [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
  [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
  [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
  [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
  ])

# Rijndael Inverted S-box
# taken from: http://anh.cs.luc.edu/331/code/aes.py
rsbox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
         0x9e, 0x81, 0xf3, 0xd7, 0xfb , 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
         0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb , 0x54,
         0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
         0x42, 0xfa, 0xc3, 0x4e , 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
         0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 , 0x72, 0xf8,
         0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
         0x65, 0xb6, 0x92 , 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
         0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 , 0x90, 0xd8, 0xab,
         0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
         0x45, 0x06 , 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
         0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b , 0x3a, 0x91, 0x11, 0x41,
         0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
         0x73 , 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
         0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e , 0x47, 0xf1, 0x1a, 0x71, 0x1d,
         0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ,
         0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
         0xfe, 0x78, 0xcd, 0x5a, 0xf4 , 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
         0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f , 0x60,
         0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
         0x93, 0xc9, 0x9c, 0xef , 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
         0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 , 0x17, 0x2b,
         0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
         0x21, 0x0c, 0x7d]

RSboxLookup = matrix([
  [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
  [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
  [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
  [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
  [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
  [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
  [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
  [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
  [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
  [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
  [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
  [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
  [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
  [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
  [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
  [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
  ])

# test solution
def testSol( key ) :
  for t in range( testTrials ) :
    # Generate message
    rbs = random.getrandbits( keySize )
    while (rbs >= long(key, 16)) :
      rbs = random.getrandbits( keySize )
    message =  "%X" % rbs
    message = message.zfill( inputOctets )

    # Encrypt with the device
    ( trace, cipher ) = interact( long( message, 16 ), None )

    # transform message, encryption and key to list format
    m = splitPairs( message )
    k = splitPairs( key )
    c = splitPairs( cipher )

    k = pack( 16 * "B", *k )
    m = pack( 16 * "B", *m )
    c = pack( 16 * "B", *c )

    t = AES.new( k ).encrypt( m )

    tt = long(cipher, 16)
    cc = long( getHex( unpack( 16 * "B", t ) ), 16 )
    print tt
    print cc
    print c
    print t

    if( t == c or tt == cc ) :
      print "Key recovered correctly!"
      return 0
    else :
      print "Trial ", t

  print "Key recovery failed, trying again!" 
  return 1

# interact with real device
def interact( G, S ) :
  # Send G to attack target
  target_in.write( "%X\n" % ( G ) ) ; target_in.flush()
  # Send G to attack target
  target_in.write( "%s\n" % ( S ) ) ; target_in.flush()
  # Receive decryption from attack target
  dec = target_out.readline().strip()
  return int( dec, 16 )

# define SUbbytes function---Section 5.1.1
#  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
def SubBytes( x ) :
  hexStr = "%X" % x
  hexStr = hexStr.zfill( 2 )
  return SboxLookup[ int(hexStr[0], 16), int(hexStr[1], 16) ]

# define SUbbytes function---Section 5.1.1
#  http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
def RSubBytes( x ) :
  hexStr = "%X" % x
  hexStr = hexStr.zfill( 2 )
  return RSboxLookup[ int(hexStr[0], 16), int(hexStr[1], 16) ]

# Galois addition/ subtraction of 2 1-byte(8-bit) numbers---F_8 add
def add( x, y ) :
  return x ^ y
def sub( x, y ) :
  return x ^ y

# Galois multiplication of 2 1-byte(8-bit) numbers---F_8 mul
def mul( x, y ) :
  # initiate result
  res = 0

  # do the loop 8 times
  for i in range( 8 ):
    # If the rightmost bit of y is set
    #  exclusive OR the product res by the value of x...etc from wikipedia
    #  http://en.wikipedia.org/wiki/Finite_field_arithmetic#Multiplication
    if y & 1 :
      res ^= x

    y >>= 1

    carry = x & 0b10000000

    x <<= 1
    # remove leftover after shift
    x &= 0b11111111

    if carry :
      x ^= 0b00011011

  return res

# extract byte
def byte( strin, byte ) :
  bt = byte - 1
  return strin[bt*2 : bt*2+2]


# multi process first set
def mulprocset1( c, cf, pool ) :
  proc1 = multiprocessing.Process( target = eqn1, args=(c,cf,sol1,) )
  proc2 = multiprocessing.Process( target = eqn2, args=(c,cf,sol2,) )
  proc3 = multiprocessing.Process( target = eqn3, args=(c,cf,sol3,) )
  proc4 = multiprocessing.Process( target = eqn4, args=(c,cf,sol4,) )
  proc1.start()
  proc2.start()
  proc3.start()
  proc4.start()
  proc1.join()
  proc2.join()
  proc3.join()
  proc4.join()
  return ( sol1, sol2, sol3, sol4 )

# define set of equations
def eqn1( x, xp, sol ) :
  x1   = int( byte( x,  1  ), 16 )
  xp1  = int( byte( xp, 1  ), 16 )
  x8   = int( byte( x,  8  ), 16 )
  xp8  = int( byte( xp, 8  ), 16 )
  x11  = int( byte( x,  11 ), 16 )
  xp11 = int( byte( xp, 11 ), 16 )
  x14  = int( byte( x,  14 ), 16 )
  xp14 = int( byte( xp, 14 ), 16 )

  sol = []
  # first condition
  for fi in range( 256 ) :
    k1  = []
    k8  = []
    k11 = []
    k14 = []

    for k in range( 256 ) :
      if mul(2,fi) == add( RSubBytes( add(x1,k) ), RSubBytes( add(xp1,k) ) ) :
        k1.append(k)
    if k1 == [] : continue

    for k in range( 256 ) :
      if mul(3,fi) == add( RSubBytes( add(x8,k) ), RSubBytes( add(xp8,k) ) ) :
        k8.append(k)
    if k8 == [] : continue

    for k in range( 256 ) :
      if fi == add( RSubBytes( add(x11,k) ), RSubBytes( add(xp11,k) ) ) :
        k11.append(k)
    if k11 == [] : continue

    for k in range( 256 ) :
      if fi == add( RSubBytes( add(x14,k) ), RSubBytes( add(xp14,k) ) ) :
        k14.append(k)
    if k14 == [] : continue

    sol.append( ( fi, k1, k8, k11, k14 ) )

  return sol

# define set of equations no. 2
def eqn2( x, xp, sol ) :
  x2   = int( byte( x,  2  ), 16 )
  xp2  = int( byte( xp, 2  ), 16 )
  x5   = int( byte( x,  5  ), 16 )
  xp5  = int( byte( xp, 5  ), 16 )
  x12  = int( byte( x,  12 ), 16 )
  xp12 = int( byte( xp, 12 ), 16 )
  x15  = int( byte( x,  15 ), 16 )
  xp15 = int( byte( xp, 15 ), 16 )

  sol = []
  # first condition
  for fi in range( 256 ) :
    k2  = []
    k5  = []
    k12 = []
    k15 = []

    for k in range( 256 ) :
      if fi == add( RSubBytes( add(x2,k) ), RSubBytes( add(xp2,k) ) ) :
        k2.append(k)
    if k2 == [] : continue

    for k in range( 256 ) :
      if fi == add( RSubBytes( add(x5,k) ), RSubBytes( add(xp5,k) ) ) :
        k5.append(k)
    if k5 == [] : continue

    for k in range( 256 ) :
      if mul(2,fi) == add( RSubBytes( add(x12,k) ), RSubBytes( add(xp12,k) ) ) :
        k12.append(k)
    if k12 == [] : continue

    for k in range( 256 ) :
      if mul(3,fi) == add( RSubBytes( add(x15,k) ), RSubBytes( add(xp15,k) ) ) :
        k15.append(k)
    if k15 == [] : continue

    sol.append( ( fi, k2, k5, k12, k15 ) )

  return sol

# define set of equations no. 3
def eqn3( x, xp, sol ) :
  x3   = int( byte( x,  3  ), 16 )
  xp3  = int( byte( xp, 3  ), 16 )
  x6   = int( byte( x,  6  ), 16 )
  xp6  = int( byte( xp, 6  ), 16 )
  x9   = int( byte( x,  9  ), 16 )
  xp9  = int( byte( xp, 9  ), 16 )
  x16  = int( byte( x,  16 ), 16 )
  xp16 = int( byte( xp, 16 ), 16 )

  sol = []
  # first condition
  for fi in range( 256 ) :
    k3  = []
    k6  = []
    k9 = []
    k16 = []

    for k in range( 256 ) :
      if mul(2,fi) == add( RSubBytes( add(x3,k) ), RSubBytes( add(xp3,k) ) ) :
        k3.append(k)
    if k3 == [] : continue

    for k in range( 256 ) :
      if mul(3,fi) == add( RSubBytes( add(x6,k) ), RSubBytes( add(xp6,k) ) ) :
        k6.append(k)
    if k6 == [] : continue

    for k in range( 256 ) :
      if fi == add( RSubBytes( add(x9,k) ), RSubBytes( add(xp9,k) ) ) :
        k9.append(k)
    if k9 == [] : continue

    for k in range( 256 ) :
      if fi == add( RSubBytes( add(x16,k) ), RSubBytes( add(xp16,k) ) ) :
        k16.append(k)
    if k16 == [] : continue

    sol.append( ( fi, k3, k6, k9, k16 ) )

  return sol

# define set of equations no. 4
def eqn4( x, xp, sol ) :
  x4   = int( byte( x,  4  ), 16 )
  xp4  = int( byte( xp, 4  ), 16 )
  x7   = int( byte( x,  7  ), 16 )
  xp7  = int( byte( xp, 7  ), 16 )
  x10  = int( byte( x,  10 ), 16 )
  xp10 = int( byte( xp, 10 ), 16 )
  x13  = int( byte( x,  13 ), 16 )
  xp13 = int( byte( xp, 13 ), 16 )

  sol = []
  # first condition
  for fi in range( 256 ) :
    k4  = []
    k7  = []
    k10 = []
    k13 = []

    for k in range( 256 ) :
      if fi == add( RSubBytes( add(x4,k) ), RSubBytes( add(xp4,k) ) ) :
        k4.append(k)
    if k4 == [] : continue

    for k in range( 256 ) :
      if fi == add( RSubBytes( add(x7,k) ), RSubBytes( add(xp7,k) ) ) :
        k7.append(k)
    if k7 == [] : continue

    for k in range( 256 ) :
      if mul(2,fi) == add( RSubBytes( add(x10,k) ), RSubBytes( add(xp10,k) ) ) :
        k10.append(k)
    if k10 == [] : continue

    for k in range( 256 ) :
      if mul(3,fi) == add( RSubBytes( add(x13,k) ), RSubBytes( add(xp13,k) ) ) :
        k13.append(k)
    if k13 == [] : continue

    sol.append( ( fi, k4, k7, k10, k13 ) )

  return sol

# further reduction
def eqnf1( x, xp, tpl1_8_11_14, tpl2_5_12_15, tpl3_6_9_16, tpl4_7_10_13 ) :
  xx = (
    int( byte( x, 1  ), 16 ),
    int( byte( x, 2  ), 16 ),
    int( byte( x, 3  ), 16 ),
    int( byte( x, 4  ), 16 ),
    int( byte( x, 5  ), 16 ),
    int( byte( x, 6  ), 16 ),
    int( byte( x, 7  ), 16 ),
    int( byte( x, 8  ), 16 ),
    int( byte( x, 9  ), 16 ),
    int( byte( x, 10 ), 16 ),
    int( byte( x, 11 ), 16 ),
    int( byte( x, 12 ), 16 ),
    int( byte( x, 13 ), 16 ),
    int( byte( x, 14 ), 16 ),
    int( byte( x, 15 ), 16 ),
    int( byte( x, 16 ), 16 )
    )
  xxp = (
    int( byte( xp, 1  ), 16 ),
    int( byte( xp, 2  ), 16 ),
    int( byte( xp, 3  ), 16 ),
    int( byte( xp, 4  ), 16 ),
    int( byte( xp, 5  ), 16 ),
    int( byte( xp, 6  ), 16 ),
    int( byte( xp, 7  ), 16 ),
    int( byte( xp, 8  ), 16 ),
    int( byte( xp, 9  ), 16 ),
    int( byte( xp, 10 ), 16 ),
    int( byte( xp, 11 ), 16 ),
    int( byte( xp, 12 ), 16 ),
    int( byte( xp, 13 ), 16 ),
    int( byte( xp, 14 ), 16 ),
    int( byte( xp, 15 ), 16 ),
    int( byte( xp, 16 ), 16 )
    )
  sol = []
  for i in tpl1_8_11_14 :
    ( fi, i1, i8, i11, i14 ) = i
    for ii in tpl2_5_12_15 :
      ( fi, i2, i5, i12, i15 ) = ii
      for iii in tpl3_6_9_16 :
        ( fi, i3, i6, i9, i16 ) = iii 
        for iiii in tpl4_7_10_13 :
          ( fi, i4, i7, i10, i13 ) = iiii
          for j1 in i1 :
            for j2 in i2 :
              for j3 in i3 :
                for j4 in i4 :
                  for j5 in i5 :
                    for j6 in i6 :
                      for j7 in i7 :
                        for j8 in i8 :
                          for j9 in i9 :
                            for j10 in i10 :
                              for j11 in i11 :
                                for j12 in i12 :
                                  for j13 in i13 :
                                    for j14 in i14 :
                                      for j15 in i15 :
                                        for j16 in i16 :
                                          pr = eqnf2( xx, xxp, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15, j16 )
                                          if pr != -1 :
                                            sol.append( pr )
  return sol

def eqnf2N( coef, x, k1, k2, k3, k4, h ) :
  p1 = add( x, k1 )
  p1 = RSubBytes( p1 )

  p2 = add( k3, k4 )
  p2 = SubBytes( p2 )

  p3 = add( k2, p2 )
  p3 = add( p3, h )

  p = add( p1, p3 )
  return mul( coef, p )

def eqnf2O( coef, x, k1, k2, k3, k4 ) :
  p1 = add( x, k1 )
  p1 = RSubBytes( p1 )

  p2 = add( k3, k4 )
  p2 = SubBytes( p2 )

  p3 = add( k2, p2 )

  p = add( p1, p3 )
  return mul( coef, p )

def eqnf2P( coef, x, k1, k2, k3 ) :
  p1 = add( k2, k3 )
  p2 = add( x, k1 )
  p2 = RSubBytes( p2 )
  p = add( p1, p2 )
  return mul( coef, p )
def eqnf2Q( ab, c, d, ef, g, h ) :
  abc = add( ab, c )
  abcd = add( abc, d )
  abcdef = add( abcd, ef )
  abcdefg = add( abcdef, g )
  abcdefgh = add( abcdefg, h )
  return abcdefgh

# eqnf second part
def eqnf2( xx, xxp, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15, j16 ) :
  # eqn 1
  a = eqnf2N( 14, xx[0], j1, j1, j14, j10, h10 )
  b = eqnf2O( 11, xx[13], j14, j2, j15, j11 )
  c = eqnf2O( 13, xx[10], j11, j3, j16, j12 )
  d = eqnf2O( 9 , xx[7 ], j8 , j4, j13, j9  )
  ab = add( a, b )
  abc = add( ab, c )
  abcd = add( abc, d )
  part1 = RSubBytes( abcd )
  #####
  e = eqnf2N( 14, xxp[0], j1, j1, j14, j10, h10 )
  f = eqnf2O( 11, xxp[13], j14, j2, j15, j11 )
  g = eqnf2O( 13, xxp[10], j11, j3, j16, j12 )
  h = eqnf2O( 9 , xxp[7 ], j8 , j4, j13, j9  )
  ef = add( e, f )
  efg = add( ef, g )
  efgh = add( efg, h )
  part2 = RSubBytes( efgh )
  p2   = add( part1, part2 )
  # eqn 2
  a  = eqnf2P( 9, xx[12], j13 , j13, j9 )
  b  = eqnf2P( 14, xx[9 ], j10 , j10, j14 )
  ab = RSubBytes( add( a, b ) )
  c  = eqnf2P( 11, xx[6 ], j7 , j15, j11 )
  d  = eqnf2P( 13, xx[3], j4, j16, j12 )
  e  = eqnf2P( 9, xxp[12], j13, j13, j9 )
  f  = eqnf2P( 14, xxp[9 ], j10 , j10, j14 )
  ef = RSubBytes( add( e, f ) )
  g  = eqnf2P( 11, xxp[6 ], j7, j15, j11 )
  h  = eqnf2P( 13, xxp[3 ], j4, j16 , j12 )
  p1_  = eqnf2Q( ab, c, d, ef, g, h )
  # eqn 3
  a  = eqnf2P( 13, xx[8 ], j9 , j9 , j5 )
  b  = eqnf2P( 9 , xx[5 ], j6 , j10, j6 )
  ab = RSubBytes( add( a, b ) )
  c  = eqnf2P( 14, xx[2 ], j3 , j11, j7 )
  d  = eqnf2P( 11, xx[15], j16, j12, j8 )
  e  = eqnf2P( 13, xxp[8 ], j9, j9, j5 )
  f  = eqnf2P( 9 , xxp[5 ], j6 , j10, j6 )
  ef = RSubBytes( add( e, f ) )
  g  = eqnf2P( 14, xxp[2 ], j3, j11, j7 )
  h  = eqnf2P( 11, xxp[15], j16, j12 , j8 )
  p1__ = eqnf2Q( ab, c, d, ef, g, h )
  # eqn 4
  a  = eqnf2P( 11, xx[4 ], j5 , j5 , j1 )
  b  = eqnf2P( 13, xx[1 ], j2 , j6 , j2 )
  ab = RSubBytes( add( a, b ) )
  c  = eqnf2P( 9 , xx[14], j15, j7 , j3 )
  d  = eqnf2P( 14, xx[11], j12, j8 , j4 )
  e  = eqnf2P( 11, xxp[4], j5, j5, j1 )
  f  = eqnf2P( 13, xxp[1 ], j2 , j6 , j2 )
  ef = RSubBytes( add( e, f ) )
  g  = eqnf2P( 9 , xxp[14], j15, j7 , j3 )
  h  = eqnf2P( 14, xxp[11], j12, j8 , j4 )
  p3 = eqnf2Q( ab, c, d, ef, g, h )
  if mul(3,p2) == mul(6,p1_) == mul(6,p1__) == mul(2,p3) :
    return ( j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15, j16 )
  else :
    return -1


if ( __name__ == "__main__" ) :
  # is the guess correct?
  incorrect = 1

  # define multi-processing
  num_of_workers = multiprocessing.cpu_count()
  pool = multiprocessing.Pool(num_of_workers)

  while( incorrect ) :
    # generate 128-bit strings for attacks
    rb = random.getrandbits( keySize )
    print "Attacks Generated.\nStarting interaction."

    # Produce a sub-process representing the attack target.
    target = subprocess.Popen( args   = sys.argv[ 1 ],
                               stdout = subprocess.PIPE, 
                               stdin  = subprocess.PIPE )

    # Construct handles to attack target standard input and output.
    target_out = target.stdout
    target_in  = target.stdin

    # Get traces---take first 5%
    #  find the limit
    specifier = str(r) + ',' + str(f) + ',' + str(p) + ',' + str(i) + ',' + str(j)
    c = interact( rb, specifier )
    cf = interact( rb, '' )

    print "Recovering the key..."
    # perform first S-box
    print "1. First set of eqns"
    (s1,s2,s3,s4) = mulprocset1( c, cf, pool )
    print s1
    exit()
    print "2. Second set of eqns"
    #
    Ri = corParChunk( Hi, traces, pool ) # parallel chunk by chunk 2:02

    # Test solution, if not working redo
    incorrect = testSol( key )


print "Key: ", key
