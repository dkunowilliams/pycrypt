class RSA():
    """Implementation of the RSA cryptosystem without padding. Uses simple
    ASCII numeric to character representation to process string format message
    into integer that can be used in RSA encryption.
    """
    
    from random import randrange, getrandbits
    import re
    
    def __init__(self, b=256):
        """Initializes an instance of the class.
        
        Paramerers
        ----------
        b : int
            Bit size to use for encryption.
        """
        self.bit_len = b
        
    def gcd(self, x, y):
        """Finds the greatest common divisor of two integers.
        
        Paramerers
        ----------
        x : int
            First number to find gcd of.
        y : int
            Second number to find gcd of.
        Returns
        -------
        int : Greatest common divisor of x and y.   
        """
        while (y != 0):
            z = y
            y = x % y
            x = z
        return x

    def lcm(self, x, y):
        """Finds the least common multiple of two integers.
        
        Paramerers
        ----------
        x : int
            First number to find lcm of.
        y : int
            Second number to find lcm of.
        
        Returns
        -------
        int : Least common multiple of x and y.
        """
        return (x * y) // self.gcd(x, y)
    
    # Author: GeeksforGeeks
    def modInverse(self, a, m):
        """Calculates the multiplicitave modular inverse.
        
        Parameters
        ----------
        a : int
            number to find modular inverse of.
        m : int
            mod to calculate inverse in.
        
        Returns
        -------
        x : int
            multiplicative modular inverse of a.
        """
        m0 = m
        y = 0
        x = 1

        if (m == 1):
            return 0

        while (a > 1):

            # q is quotient
            q = a // m

            t = m

            # m is remainder now, process
            # same as Euclid's algo
            m = a % m
            a = t
            t = y

            # Update x and y
            y = x - q * y
            x = t

        # Make x positive
        if (x < 0):
            x = x + m0

        return x  
    
    def mod_power(self, base, power, m):
        """Calculates the power of a number mod m.
        
        Paramerers
        ----------
        base : int
               Base term in expression.
        power : int
                Exponent term in expression.
        m : int
            Mod to do arithmetic in.
        
        Returns
        -------
        result : int
                 The result of base^power in mod m.
        """
        if (m == 1):
            return 0

        result = 1
        base = base % m
        while (power > 0):
            if (power % 2 == 1):
                result = (result * base) % m

            power = power >> 1
            base = (base ** 2) % m

        return result
    
    # Author: Antoine Prudhomme
    def is_prime(self, n, k=128):
        """Checks if a number is prime.
           Uses the Miller-Rabin Primality Test.
        
        Paramerers
        ----------
        n : int
            Number to test primality for.
        k : int
            Number of tests to do.
        
        Returns
        -------
        bool : If n is prime or not
        """
        # Test if n is not even.
        # But care, 2 is prime !
        if n == 2 or n == 3:
            return True
        if n <= 1 or n % 2 == 0:
            return False
        # find r and s
        s = 0
        r = n - 1
        while r & 1 == 0:
            s += 1
            r //= 2
        # do k tests
        for _ in range(k):
            a = self.randrange(2, n - 1)
            x = pow(a, r, n)
            if x != 1 and x != n - 1:
                j = 1
                while j < s and x != n - 1:
                    x = pow(x, 2, n)
                    if x == 1:
                        return False
                    j += 1
                if x != n - 1:
                    return False
        return True
    
    # Author: Antoine Prudhomme
    def generate_prime_candidate(self, length):
        """Generates a random odd integer.
        
        Paramerers
        ----------
        length : int
                 Length of the number to generate, in bits.
        
        Returns
        -------
        p : int
            Odd number of length bits.
        """
        # generate random bits
        p = self.getrandbits(length)
        # apply a mask to set MSB and LSB to 1
        p |= (1 << length - 1) | 1
        return p
    
    # Author: Antoine Prudhomme
    def generate_prime_number(self):
        """Generates a prime number
        
        Paramerers
        ----------
        length : int
                 Length of the number to generate, in bits.
        
        Returns
        -------
        p : int
            Prime of length bits.
        """
        p = 4
        # keep generating while the primality test fail
        while not self.is_prime(p, 128):
            p = self.generate_prime_candidate(self.bit_len)
        return p
    
    def preprocess(self, plainText):
        """Processes text into a numberical format.
           Allows input into RSA algorithm.
        
        Paramerers
        ----------
        plainText : str
                    Message to convert to numeric form.
        
        Returns
        -------
        int(int_str) : int
                       Numeric form of plainText.
        
        """
        # Removes all characters with ascii >= 96
        regex = self.re.compile('[^a-zA-Z0-9\\s\!\"\#\$\%\&\'\(\)\*\+\`\-\.\/\:\;\<\=|.\?\@\,\\\[\^\]]')
        chars = regex.sub('', plainText).upper()
        
        # Generates numeric representation by converting each char to two digit number and appending to string
        int_str = ''
        for char in chars:
            int_str += str(ord(char))

        return int(int_str)

    def deprocess(self, processed_text):
        """Deprocesses RSA output into text format.
        
        Paramerers
        ----------
        processed_text : int
                         Numeric form of a string, processed using the preprocess function.
        
        Returns
        -------
        result : str
                 Message found by converting numeric form to string.
        
        """
        result = ''
        line = str(processed_text)
        
        # Break input in to two digit numbers, then use ascii to convert to chars
        n = 2
        char_array = [line[i:i+n] for i in range(0, len(line), n)]
        for i in char_array:
            result += chr(int(i))

        return result
    
    def generate_key(self):
        """Generates a RSA public/private key pair.
        
        Returns
        -------
        public_key : tuple, (n, e)
                     Public key for RSA consisting of n, the modulus, and a number coprime to n.
        private_key : tuple, (n, d)
                      Private key for RSA. Tuple consists of modulus and modular multiplicative inverse of e.
        
        """
        e = 65537

        # Generate two primes
        p = self.generate_prime_number()
        q = self.generate_prime_number()
        
        # Define modulus for RSA by taking their power
        n = p * q
        
        # Compute Carmichael's Totient of n
        totient = self.lcm(p-1, q-1)
        
        # Define the public and private keys
        public_key = (n, e)
        private_key = (n, self.modInverse(e, totient))

        return public_key, private_key
    
    def encrypt(self, plainText, public_key):
        """Encrypts a message using RSA.
        
        Paramerers
        ----------
        plainText : str
                    Message to encrypt using RSA.
                    
        public_key : tuple, (n, e)
                     Public key for RSA consisting of n, the modulus, and a number coprime to n.
        
        Returns
        -------
        int : Encrypted message.
        
        """
        # Process plainText into format RSA can use
        b = self.preprocess(plainText)

        return self.mod_power(b, public_key[1], public_key[0])
    
    def decrypt(self, cipherText, private_key):
        """Decrypts a message using RSA.
        
        Paramerers
        ----------
        cipherText : str
                     Message to decrypt using RSA.
                     
        private_key : tuple, (n, d)
                      Private key for RSA. Tuple consists of modulus and modular multiplicative inverse of e.
        
        Returns
        -------
        str : Decrypted message.
        
        """
        int_message = self.mod_power(cipherText, private_key[1], private_key[0])
        return self.deprocess(int_message)
