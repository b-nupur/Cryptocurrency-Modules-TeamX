from random import randint
import hashlib
import hmac
from helper import encode_base58_checksum, hash160




class FiniteFieldElement:

    def __init__(self, num, prime):
        if num >= prime or num < 0:  
            error = 'Num {} not in field range 0 to {} '.format(num, prime-1)
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __repr__(self):
        # return an unambiguous string representation of an object
        return 'FiniteFieldElement_{}({})'.format(self.prime, self.num)           
    
    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime
    
    def __ne__(self, other):
        return not(self == other)
    
    #modular arithmetic 
    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two number of different Fields')
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime) # create object of class type (num, prime)
   
    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot subtract two number in different Fields')
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime) # returns the instance of class
    
    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two number in different Fields')
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, exponent):
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num , self.prime)
    

    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot two divide number in different Fields')
        num = (self.num * pow(other.num, self.prime-2,self.prime))%self.prime
        return self.__class__(num,self.prime)

    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num=num, prime=self.prime)
class Point:

    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        if self.x is None and self.y is None:
            return
        if self.y**2 != self.x**3 + a * x + b:
            raise ValueError('({}, {}) is not on the curve'.format(x, y))
        
    def __eq__(self, other):
        return self.x == other.x and self.y == other.y and self.a == other.a and self.b == other.b
    
    def __ne__(self, other):
        return not(self == other)
    
    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        elif isinstance(self.x, FiniteFieldElement):
            return 'Point({},{})_{}_{} FiniteFieldElement({})'.format(
                self.x.num, self.y.num, self.a.num, self.b.num, self.x.prime)
        else:
            return 'Point({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)
    
    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError('Points {}, {} are not on the same curve'.format(self, other))
        
        if self.x is None:
            return other
        if other.x is None:
            return self
        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)
        
        if self.x != other.x:
            s = (other.y - self.y)/(other.x - self.x)
            x3 = s**2 - self.x - other.x
            y3 = s * (self.x - x3)-self.y
            return self.__class__(x3, y3, self.a, self.b)
    
        if self == other:
            s = ( 3 * self.x ** 2 + self.a)/(2 * self.y)
            x3 = s ** 2 - 2 * self.x
            y3 = s * (self.x - x3)-self.y
            return self.__class__(x3, y3, self.a, self.b)
    
        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)
        # build the primitives needed to sign and verify msgs

    def __rmul__(self, coefficient):
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>=1
        return result


# class ECCTest(TestCase):
#     def test_on_curve(self):
#         prime = 223
#         a = FiniteFieldElement(0, prime)
#         b = FiniteFieldElement(7, prime)

#         vaild_points = ((192,105), (17,56), (1,193))
#         invaild_points = ((200, 119), (42, 99))

#         for x_raw, y_raw in vaild_points:
#             x = FiniteFieldElement(x_raw, prime)
#             y = FiniteFieldElement(y_raw, prime)
#             Point(x, y, a, b)
        
#         for x_raw, y_raw in vaild_points:
#             x = FiniteFieldElement(x_raw, prime)
#             y = FiniteFieldElement(y_raw, prime)
#             with self.assertRaises(ValueError):
#                 Point(x, y, a, b)

P = 2**256 - 2**32 -977

A = 0
B = 7
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

# defining a field for bitcoin
class S256Field(FiniteFieldElement):
    def __init__(self, num, prime=None):
        super().__init__(num = num, prime = P)

    def __repr__(self):
        return '{:x}'.format(self.num).zfill(64)
    
    def sqrt(self):
        return self ** ((P+1)//4) # floor division
    




class S256Point(Point):
    def __init__(self, x, y, a= None, b= None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(x = S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __repr__(self):
        if self.x is None:
            return '256Point(infinity)'
        else:
            return '256Point({},{})'.format(self.x, self.y)
        

    def __rmul__(self,coefficient):
        coef = coefficient % N
        return super().__rmul__(coef)
    
    def verify(self, z, sig):
        s_inv = pow(sig.s, N-2, N) # using fermat's little theorem
        u = z * s_inv % N 
        v = sig.r * s_inv % N
        total = u * G + v * self
        return total.x.num == sig.r
    
    def sec(self, compressed =True):
        # returns the binary version of the SEC format
        # advantage of compression is we need only 33 bytes instead of 65 bytes

    # Find w such that w^2 = v when we know v.
    # It turns out that if the finite field prime p % 4 = 3, we can do this rather easily. Here’s how.

    # First, we know:

    # p % 4 = 3
    # which implies:

    # (p + 1) % 4 = 0
    # That is, (p + 1)/4 is an integer.

    # By definition:

    # w^2 = v
    # We are looking for a formula to calculate w. From Fermat’s little theorem:

    # w^(p–1) % p = 1
    # which means:

    # w^2 = w^2 ⋅ 1 = w^2 ⋅ w^(p–1) = w^(p+1)
    # Since p is odd, we know we can divide (p+1) by 2 and still get an integer, implying:

    # w = w^(p+1)/2
    # Now we can use (p+1)/4 being an integer this way:

    # w = w^((p+1)/2) = w^(2(p+1)/4) = w^(2(p+1)/4) = v^((p+1)/4)
    # So our formula for finding the square root becomes:

    # if w^2 = v and p % 4 = 3, w = v^((p+1)/4)
    # It turns out that the p used in secp256k1 is such that p % 4 == 3, so we can use this formula:

    # w^2 = v
# w = v^((p+1)/4)

        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\03' + self.x.num.to_byted(32,'big')
        else:
            return b'\04' + self.x.num.to_bytes(32, 'big') + self.y.num.to_bytes(32,'big')
        
    def parse(self, sec_bin):
        if sec_bin[0] == 4: 
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33:65], 'big')
            return S256Point(x=x, y=y)
        
        is_even = sec_bin[0] == 2 
        x = S256Field(int.from_bytes(sec_bin[1:], 'big'))
        # y^2 = x^3 + 7
        alpha = x**3 + S256Field(B)
    
        beta = alpha.sqrt() # get y

        if beta.num % 2 == 0:  # even
            even_beta = beta
            odd_beta = S256Field(P - beta.num)
        else:
            even_beta = S256Field(P - beta.num)
            odd_beta = beta
        if is_even:
            return S256Point(x, even_beta)
        else:
            return S256Point(x, odd_beta)
        
    def hash160(self, compressed=True):
        return hash160(self.sec(compressed))
    
    def address(self, compressed=True, testnet=False):
        # Returns the address string
        h160 = self.hash160(compressed)
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return encode_base58_checksum(prefix + h160)
    
    
     
    

G = S256Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


#####   PUBLIC KEY CRYPTOGRAPHY
#           P = eG
# can compute P when we know e and G
# can not compute e when we know P and G <------- discrete log problem
# e --------- PRIVATE KEY ----- 256 bit number
# P --------- PUBLIC KEY  ----- is (x,y) coordinate where x and y each number is 256 bit

######################## SIGNING VERIFICATION ########################

# ECDSA Elliptic Curve Digital Signature Algorithm

# prove the possesion of the secret without revealing the secret itself

# the secret is e 
# P is public key
# the target is a random 256 bit number ---- k
# kG = R
# R is now the target we are aiming for --- x coordinate of  R "r" 
# discete log 
# uG + vP = kG
# k --- choosen randomly
# u,v choosen signer
# uG+vP = kG ------> 
# if we are able to find u,v then we have broken/sloved discrete log
# but discrete log problem is hard
# we say e is assumed to be know by the one who came up with u, v
# z ======> hash of message that we want to sign
# u = z/s
# v = r/s 
# know : z, u, v,p,g, k
# calculate s:
# uG + vP  = R = kG
# uG + veG = kG
# u + ve = k
# z/s re/s = k
# (z+re)/s = k
# s = (z+re)/k

# two numbers in signature are: r, s
# verifaication is straightforward:
# uG+vP 

# verification 
# hash the document --> signature hash z
# (r,s) we know e , k and z
# calculation of z requires two rounds bcz of well know attacks on SHA-1 called birthday attack
# so using SHA-1 twice we reduce collision


# for storing r and s value
class Signature:
    def __init__(self, r, s):
        self.r = r
        self.s = s
    
    def __repr__(self):
        return 'Signature({:x},{:x})'.format(self.r, self.s)
    
    def der(self):

        # DER signature format is defined like this:

        # Start with the 0x30 byte.
        # Encode the length of the rest of the signature and append.
        # Append the marker byte, 0x02.
        # Encode r as a big-endian integer, 
        # but prepend it with the 0x00 byte if r’s first byte ≥ 0x80.
        # Prepend the resulting length to r. Add this to the result.
        # Append the marker byte, 0x02.
        # Encode s as a big-endian integer, but prepend with the 0x00 byte if s’s first byte ≥ 0x80.
        # Prepend the resulting length to s. Add this to the result.



        rbin = self.r.to_bytes(32, byteorder='big')
        # remove all null bytes at the beginning
        rbin = rbin.lstrip(b'\x00')
        # if rbin has a high bit, add a \x00
        if rbin[0] & 0x80:
            rbin = b'\x00' + rbin

        result = bytes([2, len(rbin)]) + rbin  
        sbin = self.s.to_bytes(32, byteorder='big')

        # remove all null bytes at the beginning
        sbin = sbin.lstrip(b'\x00')
        # if sbin has a high bit, add a \x00

        if sbin[0] & 0x80:
            sbin = b'\x00' + sbin
        result += bytes([2, len(sbin)]) + sbin
        return bytes([0x30, len(result)]) + result

    
# Message signing
class PrivateKey:
    def __init__(self, secret):
        self.secret = secret
        self.point = secret * G # public key
    
    def hex(self):
        return '{:x}'.format(self.secret).zfill(64) 
    
    def sign(self, z):

        k = randint(0,N) # choose random integer (0,n)
        r = (k*G).x.num  # r's x coordinate
        k_inv = pow(k,N-2,N)  # find inverse using fermat's little theorem
        s = (z + r*self.secret) * k_inv % N
        if s > N/2:
            s = N - s
        return Signature(r,s)
    
    def deterministic_k(self, z):
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > N:
            z -= N
        
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32,'big')
        
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()

        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < N:
                return candidate 
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()



    
    


# transmit objects
# transmit SHA256 point over a network
# Using the standards for efficient cryptography (SEC)
# SEC -----------> 1. compressed
#                  2. uncompressed

# the motivation for big endain --> storing a disk
# ------------------ Uncompressed SEC format----------------
# 1. convert 256 bits ---> 32 Bytes big endian

# uncompressed
# 04 --marker
# x coordinate - 32 bytes
# y coordinate - 32 bytes
# compressed
# 02 if y is even and 03 if odd --marker

# distinguised encoding rule DER


        