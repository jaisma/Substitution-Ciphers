# Substitution-Ciphers
Implementation of an algorithm that tries to decrypt an L-symbol challenge ciphertext using a plaintext dictionary (containing a number q of English words or plaintexts obtained as a sequence of English words), using only partial knowledge of the encryption algorithm used, no knowledge of any keys involved.

## Implementation
- Takes in the number t of key symbols and symbol challenge ciphertext
- Each symbol is either a space or one of the 26 lower-case letters from the English alphabet
- No special character, punctuation symbol or upper-case letter
- Returns as output a guess for which L-symbol plaintext was encrypted
- A text file Dictionary1.txt contains a number u of L-symbol candidate plaintext

