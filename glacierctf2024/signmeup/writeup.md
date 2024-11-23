# Writeup for GlacierCTF Challenge: **SignMeUp**

Code from the challenge : 
```rust
pub fn sign(
        &self,
        message: &[u8],
    ) -> (CompressedEdwardsY, Scalar)
    {
        let mut h = HashType::new();
        h.update(&self.hash_prefix);
        h.update(message);
        let mut hash_val = [0u8; 64];
        hash_val[0..HASH_LEN].copy_from_slice(h.finalize().as_slice());
        let r_scalar = Scalar::from_bytes_mod_order_wide(&hash_val); // r = H(prefix || m)
        let r: CompressedEdwardsY = EdwardsPoint::mul_base(&r_scalar).compress(); // R = H(prefix || m)*B

        let mut h = HashType::new();
        h.update(r.as_bytes()); // H(R)
        h.update(self.public_key.compressed.as_bytes()); // H(R || A)
        h.update(message); // H(R || A || m)

        let mut hash_val = [0u8; 64];
        hash_val[0..HASH_LEN].copy_from_slice(h.finalize().as_slice()); // H(R || A || m)

        let h_scalar = Scalar::from_bytes_mod_order_wide(&hash_val); // h = H(R || A || m)
        let s: Scalar = (h_scalar * self.secret_scalar) + r_scalar; // s = h * a + r
        (r, s)
    }
```

HashType is defined at SHA1, from that i was thinking at a identical choosen prefix attack like SHAttered for getting a collision on r_scalar and directly get the secret_scalar,
but it was a fake lead, i spent a lot of time on it, but because we cannot control the prefix, it was impossible to do a collision.

## The real attack

SHA1 is a hash function who output 160 bits but the order of the curve is 252 bits, so we can use LLL to find the secret_scalar.

The idea is to find get multiple signature and construct a matrix for this equation :
```
s = h * a + r mod l
```

We can rewrite this equation like this :
```
ri = si - hi * a mod l
```
where `ri` is a unknown scalar < 2**160, `si` is the signature, `hi` is H(R || A || m_i) and can be computed, `l` is the order of the curve
and `a` is the secret scalar. I put i for the i-th message signed.

The matrix is like this :
```
|  l  |  0  | ... |  0  |  0  | 0 |
|  0  |  l  | ... |  0  |  0  | 0 |
|  0  |  0  | ... |  l  |  0  | 0 |
| -h1 | -h2 | ... | -hn | B/n | 0 |
|  s1 |  s2 | ... |  sn |  0  | B |
```
where B is upper bound for all the ri.

a short vector of this matrix is
```
(r1, r2, ..., rn, a*B/n, B)
```

## The code

### Step 1: Get multiple signature

```py
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
```

### Step 2: Construct the matrix and apply LLL

```py

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

```

### Step 3: Get the flag

```py
#sign with the secret
re.sendline()
needtosign = re.recvuntil(b'signature> ')
needtosign = needtosign.split(b'\n')[0].split(b': ')[1]
r_scalar = 0
r = 1 # it's just the compressed value of the point at infinity
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
```