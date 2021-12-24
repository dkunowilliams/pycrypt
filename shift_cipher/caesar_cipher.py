import re

class CaesarCipher():
    # helper functions for prediction function
    def calc_frequencies(cipherText):
        """Computes the frequency of a letter in a string.

        Parameters
        ----------
        cipherText : str
                     String which frequencies are calculated from.

        Returns
        -------
        cipherFreqs : list
                      Frequencies correlated to each letter. Arranged such that a=0, b=1, ...
        """
        cipherFreqs = list()
        for i in range(0,26):
            cipherFreqs.append(0)
            
        regex = re.compile('[^a-zA-Z]')
        cipherChars = regex.sub('', cipherText).lower()
        
        for char in cipherChars:
            index = ord(char) - 97
            cipherFreqs[index] += 1
            
        length = len(cipherChars)
        if (length > 0):
            for i in range(0,26):
                cipherFreqs[i] /= length
        
        return cipherFreqs

    def calc_score(cipherFreqs, shift):
        """Calculates a score for a shift.
        
        Better shifts have lower scores.

        Parameters
        ----------
        cipherFreqs : list
                      Frequency of each letter in the string.

        shift : int
                Shift to calculate a score for.

        Returns
        -------
        score : float
                Score for a given shift 
        
        """
        letterFreqs = [0.0812, 0.0149, 0.0271, 0.0432, 0.1202, 0.0230, 0.0203, 0.0592, 0.0731,
                    0.0010, 0.0069, 0.0398, 0.0261, 0.0695, 0.0768, 0.0182, 0.0011, 0.0602,
                    0.0628, 0.0910, 0.0288, 0.0111, 0.0209, 0.0017, 0.0211, 0.0007]
        
        score = 0
        
        for i in range(0,26):
            score += (letterFreqs[i] - cipherFreqs[(i + shift) % 26]) ** 2
        
        return score

    def guess_shift(cipherFreqs):
        """Predicts the shift based on a list of letter frequencies.

        Parameters
        ----------
        cipherFreqs : list
                      Frequency of each letter in the string.

        Returns
        -------
        min_index : int
                    Index correlating to a specific character, 0 indexed.
        """
        min_score = -1
        min_index = -1
        
        for i in range(0,26):
            score = calc_score(cipherFreqs, i)

            if min_index < 0 or score < min_score:
                min_score = score
                min_index = i
        
        return min_index

    # public functions for client to interact with Caesar Cipher
    def __init__(self):
        pass

    def encrypt(self, plainText, shift=0):
        """Encrypts text by shifting each character by a set amount.

        Parameters
        ----------
        plainText : str
                    Message to encrypt.

        shift : int
                Amount to increment each character by.

        Returns
        -------
        cipherText : str
                     Encrypted string.
        """
        cipherText = ''
        for char in plainText:
            if (char.isalpha()):
                if char.islower():
                    cipherText += chr((ord(char) - 97 + shift) % 26 + 97)
                else:
                    cipherText += chr((ord(char) - 65 + shift) % 26 + 65)
            else:
                cipherText += char
        return cipherText

    def decrypt(self, cipherText, shift):
        """Decrypts a string by shifting in reverse
        
        Parameters
        ----------
        cipherText : str
                     Encrypted string.

        shift : int
                Amount plain text was shifted by to get cipher text.

        Returns
        -------
        plainText : str
                    Decrypted string.
        """
        plainText = ''
        for char in cipherText:
            if (char.isalpha()):
                if char.islower():
                    plainText += chr((ord(char) - 97 - shift) % 26 + 97)
                else:
                    plainText += chr((ord(char) - 65 - shift) % 26 + 65)
            else:
                plainText += char
        return plainText

    def predict(self, cipherText):
        """Predicts plainText from a cipherText.
        
        Parameters
        ----------
        cipherText : str
                     Encrypted string.
        
        Returns
        -------
        predPlainText : str
                        Most likely decrypted string.
        
        predShift : int
                    Most likely shift used in encryption.
        """
        predShift = guess_shift(calc_frequencies(cipherText))
        predPlainText = decrypt(cipherText, predShift)
        
        return predPlainText, predShift
