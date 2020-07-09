## Challenge writeup

In this challenge, you are given access to a web server that performs encryption and decryption with RSA using its public and private keys, although you are only given the public key. 
Navigating to `/flag`, you are given the challenge's flag that has been encrypted. By passing the `decrypt` GET parameter to the server, the server will decrypt the message using its private key, but it will only return the result of the plaintext modulo 2. (i.e, whether the resulting plaintext is odd or even).

This challenge is an RSA parity oracle, or an LSB oracle, and there are a number of articles that explain the relevant mathematics well.
https://bitsdeep.com/posts/attacking-rsa-for-fun-and-ctf-points-part-3/
https://github.com/ashutosh1206/Crypton/tree/master/RSA-encryption/Attack-LSBit-Oracle

In short, knowing whether a ciphertext's decryption is odd or even can reveal a lot of information and can be used to construct an adaptive chosen ciphertext attack.

RSA is homomorphic through multiplication, and so through given only a ciphertext `C` whose decryption results in `P`, it is possible to create a modified ciphertext `C'` such that its decryption results in `k*P`, where `k` is some integer value.

Given a plaintext `P`, we know that it lies within the range `0 < P < N`, as RSA cannot encrypt a message larger than its modulus. However, these ranges can be reduced by knowing whether resultant modified plaintexts are odd or even.

`2P` is always an even number by definition. However, if `2P mod N` is odd, this means that `2P > N`, as N is the product two odd (prime) numbers, and given that `2P < 2N`, reducing `2P` modulo `N` is the same as subtracting `N` from it. Hence, there are two possible scenarios:

If `2P` is even, `2P < N`. Hence, `0 < P < N/2.`
If `2P` is odd, `2P > N`. Hence, `N/2 < P < N`.

Therefore, through leaking a single bit of the plaintext, we have halved the interval we need to search.
We can continue reducing this interval by producing more modified plaintexts. Our next step would be to calculate `4P`. If for example `2P` is odd and `4P` is even, we know that `P > N/2` and that `2(2P-N) < N`. In this case, we would be able to determine that `N/2 < P < 3N/4`. These steps can be repeated until the interval is sufficiently small.

Here is the solution script that I used, which took around 10 seconds to run on my computer.
```python
from requests import get
from Crypto.Util.number import *

e, n = get("http://127.0.0.1:5000/key").text.split(",")
e, n = int(e), int(n)
flag_enc = int(get("http://127.0.0.1:5000/flag").text)

upper_bound = n
lower_bound = 0

def oracle(c):
    return int(get("http://127.0.0.1:5000?decrypt="+str(c)).text)

i = 1
while i <= 1024:
    chosen_ct = (flag_enc * pow(2**i, e, n)) % n
    lsb = oracle(chosen_ct)
    if lsb == 0:
        upper_bound = (upper_bound + lower_bound) // 2
    elif lsb == 1:
        lower_bound = (upper_bound + lower_bound) // 2
    i += 1

print(long_to_bytes(upper_bound))
```
Which returns the result:
```
b'FLAG{b3w4r3_0f_r5a_0r4cl3s^'
```
The upper and lower bounds here are not equal, but they are close enough such that each plaintext only differ by one byte. As we know the flag format, we know that the final flag is `FLAG{b3w4r3_0f_r5a_0r4cl3s}`
