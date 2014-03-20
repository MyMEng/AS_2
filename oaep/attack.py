#! /usr/bin/python
import sys, subprocess, random
# from math import log
# from numpy import mean
# from time import clock
# import numpy as np
# from numpy import mean
# from itertools import imap

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


# input is 1024 bits that is 16 limbs in base 2 ** 64
# bits = 1024
# inputSize = 16

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

# d is assumed to have 64 bits
def attack( guess, N, exp ) :

  # print guess
  baseline = interact([1])
  # print baseline

  # interact
  time = interact(guess)

  # baseline = interactR([1], N, exp)
  # time = interactR(guess, N, exp)
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

  (red, result) = CIOSMM(1, rhosq(N), N)
  results = [result for i in range(AttacksNo)]
  reductionNo = [0 for i in range(AttacksNo)]
  exps = []
  for gr in guess :
    (red, g) = CIOSMM(gr, rhosq(N), N)
    exps.append(g)


  # print time
  
  print "Timing done!"

  # print "r = %d" % ( r )
  reductionTable1 = []
  reductionTable2 = []
  timingme1=[]
  timingme2=[]
  results1 = []
  results2 = []
  # as we know that first bit is 1 the multiplication step will take place
  keyGuess = '1'
  # time[:] = [x - MultiplicationT for x in time]
  # but we still don't know whether reduction occurred there
  # ?
  # for now on attack only first bit

  # general timing
  # T = CoreT + keySize*MultiplicationT + MultiplicationT
  for x, i in enumerate(guess) :
    (nm,reductionNo[x],results[x] ) = binExp( i, '1', N, 0, results[x], exps[x], reductionNo[x] )



  # for j in range(5,len(exp)-1) : # last bit must be guessed
  for j in range(1,len(exp)-1) : # last bit must be guessed
    for x, i in enumerate(guess) :

      # a[:] = [x - 13 for x in a]
      # tupl = binExp( i, '1'+'1011'+keyGuess+'1', N, j )
      # tupl = binExp( i, '1'+keyGuess+'1', N, j )
      tupl = binExp( i, '1', N, 0, results[x], exps[x], reductionNo[x] )
      # print "tupl: ", tupl
      reductionTable1.append( tupl[0] )
      if tupl[0]:
        niu = tupl[1] + 1
      else :
        niu = tupl[1]
      timingme1.append(niu)
      results1.append(tupl[2])

      # should we substract multiplication time

      # tupl = binExp( i, '1'+'1011'+keyGuess+'0', N, j )
      # tupl = binExp( i, '1'+keyGuess+'0', N, j )
      tupl = binExp( i, '0', N, 0, results[x], exps[x], reductionNo[x] )
      reductionTable2.append( tupl[0] )
      if tupl[0]:
        niu = tupl[1] + 1
      else :
        niu = tupl[1]
      timingme2.append(niu)
      results2.append(tupl[2])

      # shouldn we becous didnt occur

    # print timingme1
    # print "\n"
    # print timingme2

    tuples1 = zip(reductionTable1, time, timingme1)
    tuples2 = zip(reductionTable2, time, timingme2)
    P, M = [], []
    PT, MT = [], []

    A, B, C, D = [], [], [], []
    E, F = [], []
    G, H = [], []

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
        G.append(k[2])
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
        H.append(k[2])
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
      # print "lower better"
      # print variance([P[x] - B[x] for x in range(len(P))]) / variance(P)
    # print variance([P[x] - B[x] for x in range(len(P))])

      # print variance([PT[x] - D[x] for x in range(len(D))]) / variance(PT)
    # print variance([PT[x] - D[x] for x in range(len(D))])
    # print "\n"
    # print variance(P)/variance(B)
    # print variance(PT)/variance(D)


    print "My1:",mean(B)
    print "My2:",mean(G)
    print "My3:",mean(D)
    print "My4:",mean(H)


    print "higher better"
        # print pearsonr (A,E)
        # print pearsonr (C,F)
    print pearsonr (P,B)
    print pearsonr (PT,D)
    # print np.corrcoef(A,B)[0][0]
    # print np.corrcoef(A,B)[1][1]
    # print np.corrcoef(C,D)[0][0]
    # print np.corrcoef(C,D)[1][1]

    if mean(P) - mean(M) > mean(PT) - mean(MT) :
    # if mean(B) + mean(P) - mean(G) - mean(M) > mean(D) + mean(PT) - mean(H) - mean(MT) :
      keyGuess += '1'
      results = results1
      reductionNo = timingme1
    else :
      keyGuess += '0'
      results = results2
      reductionNo = timingme2
    # print '1'+'1011'+keyGuess
    print keyGuess


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
    results1 = []
    results2 = []
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

  # 1.3a
  while response == ERROR2 :
    f_1 *= 2
    response = interact( generateAttack( f_1 ) )

  # do we get what we want?
  if response != ERROR1 :
    print "Manger1, couldn't find right value; error#: ", response, " f_1: ", f_1

  # if all good give back f_1
  return f_1

def manger2(f_1, k, B) :
  # 2.1
  f_2 = ( f_1 / 2 ) * 


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
  print "Progress check!"
  print "f_1: ", f1
  # Step 2
  f2 = manger2(f1, k, B)
  print "Progress check!"
  print "f_2: ", f2
