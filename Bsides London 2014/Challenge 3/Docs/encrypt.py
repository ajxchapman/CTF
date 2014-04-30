import hashlib
import sys
import base64

if(len(sys.argv)!=3):
  print "Usage:\n gencode.py password coordfile.txt"
  exit(1)



pin=sys.argv[1]
code=open(sys.argv[2]).read().strip()
#print code

hashofpass=hashlib.sha1(pin).hexdigest()[:16]
#print hashofpass


previous=''
result=""
for i in range(0,len(code)):
  nexta=''
  if(previous==''):
    nexta=chr(ord(code[i])^ord(hashofpass[i%len(hashofpass)]))
  else:
    nexta=chr(ord(code[i])^ord(hashofpass[i%len(hashofpass)])^ord(previous)) 
  previous=nexta
  result=result+nexta

print base64.b64encode(result)
