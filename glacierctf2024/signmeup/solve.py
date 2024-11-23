from pwn import *
from sage.all import *
import hashlib

order = 2**252 + 27742317777372353535851937790883648493 #order of the curve

re = remote('challs.glacierctf.com', 13373)

public_key = re.recvuntil(b'msg> ')
public_key = bytes.fromhex(public_key.split(b'\n')[0].split(b': ')[1].decode())


all_values = []
result = None
dim = 10
for i in range(dim):
    msg = str(i).encode()
    re.sendline(msg)
    result = re.recvuntil(b'msg>').split(b'\n')[0].split(b': ')[1].split(b' ')
    rhash = bytes.fromhex(result[0].decode())
    s = bytes.fromhex(result[1].decode())
    s = int.from_bytes(s, 'little')
    hash = hashlib.sha1()
    hash.update(rhash)
    hash.update(public_key)
    hash.update(msg)

    h = int.from_bytes(hash.digest(), 'little') % order

    all_values.append((h, s))

# s = h*x + r or r < 2**160 donc LLL
# s - h*x = r mod order
#test with s = h*x

B = 1 << 160
M = Matrix(QQ, dim + 2, dim + 2, 0)
for i in range(dim):
    M[i,i] = order
for i in range(dim):
    M[dim,i] = all_values[i][0]
    M[dim + 1,i] = -all_values[i][1]
M[dim,dim] = QQ(B)/QQ(order)
M[dim + 1,dim + 1] = B
for v in M.LLL():
    if v[dim+1] == B:
        if v[0] < 0:
            v = -v
        scalar_find = v[dim] * QQ(order) / QQ(B)
        print("Find", scalar_find - 1)
        scalar_find = scalar_find - 1
        break

#sign with the secret
re.sendline()
needtosign = re.recvuntil(b'signature> ')
needtosign = needtosign.split(b'\n')[0].split(b': ')[1]
r_scalar = 0
r = 1
r_signature = r.to_bytes(32, 'little')
hash = hashlib.sha1()
hash.update(r_signature)
hash.update(public_key)
hash.update(needtosign)
h = int.from_bytes(hash.digest(), 'little') % order

s = (h*(scalar_find) + r_scalar) % order
s_signature = s.to_bytes(32, 'little')
re.sendline(r_signature.hex() + ' ' + s_signature.hex())
print(re.recvall())
