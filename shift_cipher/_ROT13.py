class ROT13():
    def __init__(self):
        pass
    
    def encrypt(self, plainText):
        """Encrypts text by shifting each character 13.

        Parameters
        ----------
        plainText : str
                    Message to encrypt.

        Returns
        -------
        cipherText : str
                    Encrypted string.
        """
        cipherText = ''
        for char in plainText:
            if (char.isalpha()):
                if char.islower():
                    cipherText += chr((ord(char) - 84) % 26 + 97)
                else:
                    cipherText += chr((ord(char) - 52) % 26 + 65)
            else:
                cipherText += char
        return cipherText
    
    def decrypt(self, cipherText):
        """Decrypts a string by shifting in reverse
        
        Parameters
        ----------
        cipherText : str
                    Encrypted string.

        Returns
        -------
        plainText : str
                    Decrypted string.
        """
        plainText = ''
        for char in cipherText:
            if (char.isalpha()):
                if char.islower():
                    plainText += chr((ord(char) - 110) % 26 + 97)
                else:
                    plainText += chr((ord(char) - 78) % 26 + 65)
            else:
                plainText += char
        return plainText
