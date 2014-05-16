#! /usr/bin/python
import sys, subprocess, random
from numpy import mean

# CONSTANTS
#   number of attacks
AttacksNo   = 1000
#
# Input size in octets
inputOctets = 32
# Key size in bits
keySize     = 128



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
def attack( guess, exp ) :
  # interact --- get time measurements
  print "Timing..."
  time = interact(guess)
  print "Timing done!"

  print "Pre-computing constants..."

  # pre-compute 1 in Montgomery representation
  # one = limb( 1 )[::-1]
  one = 1
  (red, result) = CIOSMM(one, rsq)
  results = [result for i in range(AttacksNo)]
  # prepare space for guess
  exps = []
  # change guess to limbs
    # guess[:] =  [limb(x)[::-1] for x in guess]
  # change into Montgomery form
  for g in guess :
    (red, mg) = CIOSMM(g, rsq)
    exps.append(mg)
  
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
    (red, results[x]) = CIOSMM(results[x], results[x])
  print "All needed values precomputed!"

  print "Start knocking!"
  while True :
    for x in range(AttacksNo) :
      # try guess (1, 1, 0, 0)
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
      results = list(resulting1)
    else :
      keyGuess += '0'
      results = list(resulting0)
    print "Partial key: ", keyGuess
    print "\n"

    resulting0 = []
    resulting1 = []
    count1Red = [0.0, 0]
    count1NoRed = [0.0, 0]
    count0Red = [0.0, 0]
    count0NoRed = [0.0, 0]

    # if time with reductions are less than time without than we are done
    if keyGuess[-1] == '1' and pm < threshold :
      break
    elif keyGuess[-1] == '0' and ptmt < threshold :
      break

  # return key guess without last bit which must be guessed
  return keyGuess[:-1]






# Create mask set --- testing stage
def createMasks( masks ) :
  mask = int(wordSize*'1', 2)
  for i in range(inputSize) :
    masks.append(  mask )
    mask = mask << 64




# interact with real device
def interact( G ) :
  t = []
  # Send G to attack target
  target_in.write( "%X\n" % ( G ) ) ; target_in.flush()
  # Receive power trace from attack target
  _traces = target_out.readline().strip()
  __traces = _traces.split(',')
  traces = []
  for i in __traces :
    traces.append( int( i ) )
  # Receive decryption from attack target
  dec = target_out.readline().strip()
  return (traces, dec)

if ( __name__ == "__main__" ) :

  # generate 128-bit strings for attacks
  plainTexts = []
  for i in range(AttacksNo) :
    rb = random.getrandbits( keySize )
    plainTexts.append( rb )
  print "Attacks Generated.\nStarting interaction."

  # Produce a sub-process representing the attack target.
  target = subprocess.Popen( args   = sys.argv[ 1 ],
                             stdout = subprocess.PIPE, 
                             stdin  = subprocess.PIPE )

  # Construct handles to attack target standard input and output.
  target_out = target.stdout
  target_in  = target.stdin

  (A, B) = interact(plainTexts[0])
  print A
  print B

  # create sampling vector to select trace entries

  # extract trace entries



  # attack until good key is found
  # while True :
  #   secretKey = attack( attacks, attackExp )
  #   if decipher == encrypt(cipher, secretKey+'1', N):
  #     LSB = '1'
  #     break
  #   elif decipher == encrypt(cipher, secretKey+'0', N):
  #     LSB = '0'
  #     break
  #   else : # if does not fit --- try again
  #     print "Failed to recover key --- trying again!"
  #     print "Increasing sample space"
  #     AttacksNo += 1000
  #     # generate 1024-bit strings for attacks
  #     i = 0
  #     plainTexts = []
  #     while( i < AttacksNo ) :
  #       rr = random.getrandbits( 1024 )
  #       # check whether are less than N
  #       if rr < N :
  #         plainTexts.append( rr )
  #         i += 1
  #     attacks = plainTexts

  # print "Secret key in bin format: ", secretKey+LSB    
  # print "Secret key in hex format: %X" % ( long(secretKey+LSB, 2) )






  # Globals
  # np0, N, rsq = 0, 0, 0
  # publicKey[i] = long( k, 16 )
  # exp = "{0:b}".format( publicKey[1] )

