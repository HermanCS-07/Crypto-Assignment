# README.md

## RSA Cryptography Project

This repository contains an implementation of the RSA public-key cryptosystem. The project was developed as part of a cryptography class, focusing on foundational number theoretic operations, secure prime generation, and the core RSA encryption/decryption functionalities.

### Features

* **Modular Arithmetic**: Efficient implementations of modular multiplication and modular exponentiation.
* **Probabilistic Primality Testing**: Includes the Miller-Rabin primality test.
* **Deterministic Primality Testing**: Includes the Lucas primality test for higher confidence in prime generation.
* **Cryptographically Secure Random Number Generation**: Utilizes a Hash-based Deterministic Random Bit Generator (HashDRBG) compliant with NIST SP 800-90A.
* **RSA Key Generation**: Generates RSA key pairs with support for custom public exponents and adherence to NIST recommendations for prime number selection (e.g., bit length, proximity of primes, specific congruences).
* **RSA Encryption and Decryption**: Implements standard RSA encryption and decryption operations.
* **Key Management**: Functionality to save and load RSA key pairs to/from a JSON file.

### Project Structure

* `KKI.ipynb`: Jupyter Notebook containing all the Python code for the RSA implementation, along with detailed comments and explanations for each function.
* `project_documentation.pdf`: A comprehensive LaTeX-generated PDF document detailing the project, including:
    * Introduction to RSA.
    * Explanation of each core function with pseudocode and code snippets.
    * Design choices and their cryptographic rationale, citing NIST and PKCS standards.
    * Example usage.
    * References and Glossary.
* `images/`: Directory containing figures and pseudocode diagrams used in the documentation.
* `README.md`: This file.

### Setup and Installation

This project requires Python 3 and the `gmpy2` library for efficient arbitrary-precision arithmetic and built-in primality testing for comparison/validation.

1.  **Clone the repository**:
    ```bash
    git clone https://github.com/darc12345/Crypto-Assignment.git
    cd Crypto-Assignment
    ```

2.  **Create a virtual environment (recommended)**:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: `venv\Scripts\activate`
    ```

3.  **Install dependencies**:
    ```bash
    pip3 install gmpy2
    ```
    *Note: Installing `gmpy2` might require C compiler tools. Please refer to the [gmpy2 documentation](https://gmpy2.readthedocs.io/en/latest/install.html) for specific platform requirements.*

### Usage

You can run the code directly from the `KKI.ipynb` Jupyter Notebook or integrate the `RSA` class into your Python scripts.

#### Example Python Script

```python
import math
import secrets
import hashlib
import datetime
import gmpy2
import json

# Assuming the HashDRBG and RSA classes are defined as in KKI.ipynb

class HashDRBG():
    # ... (paste HashDRBG class code from KKI.ipynb)
    def __init__(self, seedlen:int):
        self.seedlen = seedlen
        self.personalization_string = b'NeverGonnaGiveYouUp'
        self.C = None
        self.V = None
        self.reseed_counter = 1
        self.reseed_interval = 5
        self.seed_material = None
        self.seed = None
        self.outlen = 256

        self.__initialize_state()
    
    def __generate_nonce(self)-> bytes:
        temp = int(datetime.datetime.now(datetime.timezone.utc).timestamp()*1000000)
        return temp.to_bytes(length=(temp.bit_length() // 8) + 1)
    
    def __Hash_df(self, m:bytes)-> bytes:
        return hashlib.sha256(m).digest()
        
    def __initialize_state(self):
        entropy_input = secrets.token_bytes(self.seedlen // 8)
        nonce = self.__generate_nonce()
        self.seed_material = entropy_input + nonce + self.personalization_string
        self.seed = self.__Hash_df(self.seed_material)
        self.V = self.seed
        self.C = self.__Hash_df(b'00000000'+ self.V)
        self.reseed_counter = 1

    def __reseed(self, additional_input:bytes = b''):
        entropy_input = secrets.token_bytes(self.seedlen // 8)
        self.seed_material = b"00000001" +self.V+ entropy_input + additional_input
        self.seed = self.__Hash_df(self.seed_material)
        self.V = self.seed
        self.C = self.__Hash_df(b'00000001' + self.V)
        self.reseed_counter = 1
    
    def leftmost_bits(self, data: bytes, n: int) -> bytes:
        if n < 0:
            raise ValueError("n must be non-negative")
        if n == 0:
            return b''

        total_bits = len(data) * 8
        x = int.from_bytes(data, 'big')
        if n > total_bits:
            raise ValueError(f"n ({n}) is greater than the total bit width of data ({total_bits})")
        x >>= (total_bits - n)
        out_len = (n + 7) // 8
        return x.to_bytes(out_len, 'big')

    def bytes_to_long(self, b: bytes) -> int:
        return int.from_bytes(b)

    def long_to_bytes(self, n: int) -> bytes:
        length = (n.bit_length() + 7) // 8 or 1
        return n.to_bytes(length)

    def __hash_gen(self, requested_bits:int) -> bytes:
        output = b''
        m = math.ceil(requested_bits / self.outlen)
        data = self.bytes_to_long(self.V)
        for i in range(m):
            w = self.__Hash_df(self.long_to_bytes(data))
            output = output + w
            data = (data + 1) % 2**self.seedlen
        return self.leftmost_bits(output, requested_bits)

    def generate_ramdom_bits(self, requested_bits:int) -> bytes:
        if self.reseed_counter >= self.reseed_interval:
            self.__reseed()
        self.reseed_counter += 1
        output = self.__hash_gen(requested_bits)
        H = self.__Hash_df(b"00000003"+ self.V)
        self.V = self.long_to_bytes((self.bytes_to_long(self.V) + self.bytes_to_long(H) + self.reseed_counter) % 2**self.seedlen)
        return output
        
    def generate_random_int(self, min_value:int, max_value:int) -> int:
        if min_value >= max_value:
            raise ValueError("min_value must be less than max_value")
        range_size = max_value - min_value
        if range_size <= 0:
            raise ValueError("Range size must be greater than 0")
        bit_size:int = int(gmpy2.ceil(gmpy2.log2(range_size+1)))
        while True:
            random_bytes = self.generate_ramdom_bits(bit_size)
            random_int = self.bytes_to_long(random_bytes)
            if random_int < range_size:
                return min_value + random_int

class RSA():
    # ... (paste RSA class code from KKI.ipynb)
    def __init__(self):
        self.p = None
        self.q = None
        self.n = None
        self.e = None
        self.d = None
        self.drbg = HashDRBG(seedlen=256)  
        self.security_strength = 128
        self.nlen = 3072 #This is hardcoded in respect to SP800-57, Part 1 for security_strength 128
        self.min_mr = 4
    def __long_to_bytes(self,n: int) -> bytes:
        length = (n.bit_length() + 7) // 8 or 1
        return n.to_bytes(length)
    def __zn_multiplication(self, a:int, b:int, n:int)->int:
        if a > b:
            smallest:int = b
            biggest:int = a
        else:
            smallest:int = a
            biggest:int = b
        del a, b
        str_big:str = str(bin(biggest))[2:]
        result = list()
        length = len(str_big)
        result = 0
        result += smallest * int(str_big[length-1])
        for i in range(1, length):
            smallest = (smallest << 1) % n
            result = (result + smallest*int(str_big[length-1-i]))%n
        del smallest, biggest
        return result

    def __zn_power(self, a:int, k:int, n:int)->int:
      str_k = str(bin(k))[2:][::-1]
      result = 1
      temp = a
      for i in range(len(str_k)):
        if(str_k[i]=='1'):
          result = self.__zn_multiplication(result, temp, n)
        temp = self.__zn_multiplication(temp, temp, n)
      return result % n

    def __bytes_to_long(self, b: bytes) -> int:
        return int.from_bytes(b)
    def __gcd(self, a, b):
        a = abs(a)
        b = abs(b)
        if a==0 and b==0:
            raise ValueError("GCD is undefined for 0 and 0")
        if b == 0: 
            return a
        while b:
            a, b = b, a % b
        return a
    def __is_perfect_square(self, c:int)->bool:
        n = 0
        while (1<<n) < c:
            n += 1
        m = (n//2)+1 if n%2==1 else (n//2)
        xi = gmpy2.mpq(self.drbg.generate_random_int(2**(m-1), 2**m))
        while True:
            xi = (xi*xi+c)/(2*xi)
            if (xi*xi < ((1<<m)+c)):
                break
        xi = math.floor(xi)
        if c == xi*xi:
            return True
        else:
            return False
    
    def __find_k_and_q(self, n:int)->tuple[int, int]:
        temp = int(n)
        s = 0
        while temp % 2 == 0:
            s += 1
            temp = temp >> 1
        return s, temp
    
    def __jacobi(self, a:int, n:int)->int:
        a = a % n
        if a ==1 or n ==1:
            return 1
        if a == 0:  
            return 0    
        e, a1 = self.__find_k_and_q(a)
        if e%2==0:
            s = 1
        elif (n%8) == 1 or (n%8) == 7:
                s = 1
        elif (n%8) == 3 or (n%8) == 5:
            s = -1
        if ((n%4)==3 and a1 % 4 == 3):
            s = -s
        n1 = n % a1
        return jacobi(n1, a1) * s

    def __miller_rabin(self, w:int, k:int)-> bool:
        a, m = self.__find_k_and_q(w-1)
        for i in range(k):
            b = (self.drbg.generate_random_int(2, w-2))
            if not (1<b<w-1):
                continue
            z = self.__zn_power(b, m, w)
            if (z==1 or z==w-1):
                continue
            for j in range(1, a):
                z = self.__zn_multiplication(z, z, w)
                if z == w-1:
                    break
                if z == 1:
                    return False
            else:
                return False
        return True

    def __lucas_test(self, c:int)-> bool:
        if self.__is_perfect_square(c):
            return False
        s = 0
        while True:
            s+=1
            if(s%2==1):
                d = s*2+3
            else:
                d = ((s*2+3)*-1)
            jcb = gmpy2.jacobi(d, c)
            if jcb == 0 and abs(c) != abs(d):
                return False
            if(jcb==-1 and self.__gcd(c, (1-d)//4)==1):
                break
        k = c+1
        bin_k = str(bin(k))[2:][::-1]
        r = len(bin_k)-1
        u_i = 1
        v_i = 1
        inverse_2 = pow(2, -1, c)
        for i in range(r-1, -1, -1):
            u_temp = (u_i*v_i) % c
            v_temp = ((v_i*v_i + d*u_i*u_i)*inverse_2) % c
            if bin_k[i] == '1':
                u_i = ((u_temp + v_temp)*inverse_2 )% c
                v_i = ((v_temp + d*u_temp)*inverse_2) % c
            else:
                u_i = u_temp
                v_i = v_temp
        if u_i == 0:
            return True
        else:
            return False

    def lucas_test(self, c:int)-> bool: # Public facing Lucas test, calls internal
        return self.__lucas_test(c)
    
    def __get_probable_prime(self, e:int, a:int=None, b:int = None) -> int:
        if self.nlen < 2048:
            raise ValueError("nlen must be at least 2048 bits")
        if not ((16<math.log2(e)<256) or e % 2 == 1):
            raise ValueError("e must be an odd integer between 16 and 256 bits")
        
        i = 0 
        while True:
            ub = 2**(self.nlen//2)
            lb = (((2**(self.nlen//2-1)) * int(math.sqrt(2)*1e12)) //int(1e12))
            p = (self.drbg.generate_random_int(lb, ub))
            if a is not None:
                p = p + ((a-p)%8)
            if p % 2 == 0:
               p +=1 
            if p < (((2**(self.nlen//2-1)) * int(math.sqrt(2)*1e12)) //int(1e12)):
               continue
            if self.__gcd(p-1, e) == 1:
                if gmpy2.mpz(p).is_probab_prime(self.min_mr*2): # Using gmpy2 for faster primality test
                    if self.__lucas_test(p):
                        self.p = p
                        break
            i += 1
            if i > self.nlen*5:
                raise Exception("Failed to generate a probable prime after many attempts")
        
        i = 0
        while True:
            q  =self.__bytes_to_long(self.drbg.generate_ramdom_bits(self.nlen//2))
            if b is not None:
                q = q + ((b-q)%8)
            if q % 2 == 0:
               q +=1 
            if q < (((2**(self.nlen//2-1)) * int(math.sqrt(2)*1e12)) //int(1e12)):
                continue
            if (abs(p-q)<((2**(self.nlen//2-100)))):\
                continue
            if self.__gcd(q-1, e) == 1:
                if gmpy2.mpz(q).is_probab_prime(self.min_mr*2): # Using gmpy2 for faster primality test
                    if self.__lucas_test(q):
                        self.q = q
                        break
            i += 1
            if i > self.nlen*10:
                raise Exception("Failed to generate a probable prime after many attempts")
    
    def __extended_euclidian_algorithm(self, a, b):
        if a == 0:
            return b, 0, 1 
        gcd_val, x1_rec, y1_rec = self.__extended_euclidian_algorithm(b % a, a)
        x_rec = y1_rec - (b // a) * x1_rec
        y_rec = x1_rec                      
        return gcd_val, x_rec, y_rec
    
    def __modular_inverse(self, a, m):
        gcd_val, x, y = self.__extended_euclidian_algorithm(a, m)
        if gcd_val != 1:
            raise ValueError(f"No modular inverse exists for {a} mod {m}")
        return x % m 
    
    def innitialize_rsa(self, e:int, a:int=None, b:int=None):
        if self.p is not None or self.q is not None:
            raise Exception("RSA is already initialized")
        self.__get_probable_prime(e, a, b)
        self.n = self.p * self.q
        phi = (self.p-1)*(self.q-1)
        if self.__gcd(e, phi) != 1:
            raise ValueError("e must be coprime to phi(n)")
        self.e = e
        self.d = self.__modular_inverse(self.e, phi)
    
    def encrypt(self, plaintext: bytes) -> bytes:
        if self.n is None or self.e is None:
            raise Exception("RSA is not initialized")
        plaintext_int = self.__bytes_to_long(plaintext)
        if plaintext_int >= self.n:
            raise ValueError("Plaintext must be less than n")
        ciphertext_int = self.__zn_power(plaintext_int, self.e, self.n)
        ciphertext = self.__long_to_bytes(ciphertext_int)
        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        if self.n is None or self.d is None:
            raise Exception("RSA is not initialized")
        ciphertext_int = self.__bytes_to_long(ciphertext)
        plaintext_int = self.__zn_power(ciphertext_int, self.d, self.n)
        plaintext = self.__long_to_bytes(plaintext_int)
        return plaintext
    
    def get_public_key(self) -> tuple[int, int]:
        if self.n is None or self.e is None:
            raise Exception("RSA is not initialized")
        return self.n, self.e    
    
    def get_private_key(self) -> tuple[int, int]:
        if self.n is None or self.d is None:
            raise Exception("RSA is not initialized")
        return self.n, self.d
    
    def save_state(self, filename: str):
        state = {
            'p': self.__long_to_bytes(self.p).hex(), # Convert bytes to hex string for JSON
            'q': self.__long_to_bytes(self.q).hex(),
            'n': self.__long_to_bytes(self.n).hex(),
            'e': self.e,
            'd': self.__long_to_bytes(self.d).hex()
        }
        with open(filename, 'w') as f:
            json.dump(state, f)
            
    def load_state(self, filename: str):
        with open(filename, 'r') as f: # Open in text mode for JSON
            state = json.load(f)
            self.p = int(state['p'], 16) # Convert hex string back to int
            self.q = int(state['q'], 16)
            self.n = int(state['n'], 16)
            self.e = state['e']
            self.d = int(state['d'], 16)
            if not (self.p and self.q and self.n and self.e and self.d):
                raise ValueError("Invalid RSA state in the file")

# Example Usage:
rsa = RSA()
rsa.innitialize_rsa(e=65537, a=3, b=5)

public_key_n, public_key_e = rsa.get_public_key()
private_key_n, private_key_d = rsa.get_private_key()

print(f"Public Key (n): {public_key_n}")
print(f"Public Key (e): {public_key_e}")
print(f"Private Key (d): {private_key_d}")

plaintext = b"Hello, secure world!"
print(f"Original Plaintext: {plaintext}")

ciphertext = rsa.encrypt(plaintext)
print(f"Ciphertext: {ciphertext.hex()}")

decrypted_plaintext = rsa.decrypt(ciphertext)
print(f"Decrypted Plaintext: {decrypted_plaintext}")

if plaintext == decrypted_plaintext:
    print("Encryption and Decryption successful!")
else:
    print("Error: Decrypted text does not match original plaintext.")

rsa.save_state("rsa_keys.json")
print("RSA keys saved to rsa_keys.json")

new_rsa = RSA()
new_rsa.load_state("rsa_keys.json")
print("RSA keys loaded from rsa_keys.json")

loaded_public_key_n, loaded_public_key_e = new_rsa.get_public_key()
loaded_private_key_n, loaded_private_key_d = new_rsa.get_private_key()

print(f"Loaded Public Key (n): {loaded_public_key_n}")
print(f"Loaded Public Key (e): {loaded_public_key_e}")
print(f"Loaded Private Key (d): {loaded_private_key_d}")

assert public_key_n == loaded_public_key_n
assert public_key_e == loaded_public_key_e
assert private_key_d == loaded_private_key_d
print("Loaded keys match original keys.")
```
![Screenshot 2025-06-20 000249](https://github.com/user-attachments/assets/713cfdad-9989-4e94-9c5d-9e06e1253a87)


