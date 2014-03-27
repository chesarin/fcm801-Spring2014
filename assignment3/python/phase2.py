#!/usr/bin/env python
from M2Crypto import EVP
from bitstring import BitArray

def find_difference_bits(input1, input2):
    bitarray1 = BitArray(hex=input1)
    bitarray2 = BitArray(hex=input2)
    print 'bitarray1 is {}'.format(bitarray1.bin)
    print 'bitarray2 is {}'.format(bitarray2.bin)
    counter = 0
    for i in range(len(bitarray1)):
        if bitarray1[i] != bitarray2[i]:
            counter += 1
    print 'there are {} bits different or {} percent of bits were changed'.format(counter,(float(counter)/len(bitarray1))*100)
    return counter
    
def cipher_filter(cipher, inf, outf):
        while 1:
            buf=inf.read()
            if not buf:
                break
            outf.write(cipher.update(buf))
        outf.write(cipher.final())
        return outf.getvalue()
def encrypt2(alg, key, iv, data):
    cipher = EVP.Cipher(alg, key, iv, 1, padding=0)
    v = cipher.update(data)
    v = v + cipher.final()
    del cipher
    return v
def decrypt2(alg, key, iv,  data):
    cipher = EVP.Cipher(alg, key, iv, 0, padding=0)
    v = cipher.update(data)
    v = v + cipher.final()
    del cipher
    return v
def change_one_bit(input):
    bitarray = BitArray(hex=input)
    bitarray.invert(0)
    newinput = bitarray.hex
    return newinput, bitarray
key = '6c3ea0477630ce21a2ce334aa746c2cd'
largekey = key * 2
iv =  'c782dc4c098c66cbd9cd27d825682c81'
ciphers = ['aes_128_cbc', 'bf_cbc', 'des_ede3_cbc']
ciphers_large_keys = ['aes_256_cbc']
plain_text = 'Single block msg'
newkey, bitarray = change_one_bit(key)
print 'old key is {} new key is {}'.format(key,newkey)
newlargekey = newkey * 2
for cipher in ciphers:
    print 'testing cipher {}'.format(cipher)
    print 'length of key is {}'.format(len(key))
    print 'length of plain_text: {}'.format(len(plain_text))
    cipher_text = encrypt2(cipher, key, iv, plain_text)
    recovered_plain_text = decrypt2(cipher, key, iv, cipher_text)
    print 'lenght of cipher text is {}'.format(len(cipher_text))
    print 'plain  text in hex {}'.format(plain_text.encode('hex'))
    print 'cipher text in hex {}'.format(cipher_text.encode('hex'))
    print 'recovered plain text is {}'.format(recovered_plain_text)
    newinput, bitarray = change_one_bit(plain_text.encode('hex'))
    print 'new input is {} and its length {}'.format(newinput.decode('hex'), len(newinput))
    cipher_text2 = encrypt2(cipher, key, iv, newinput.decode('hex'))
    print 'new cipher text {} '.format(cipher_text2.encode('hex'))
    print 'length of ciphertext {}'.format(len(cipher_text2))
    difference = find_difference_bits(cipher_text.encode('hex'), cipher_text2.encode('hex'))
    cipher_text3 = encrypt2(cipher, newkey, iv, plain_text)
    difference2 = find_difference_bits(cipher_text.encode('hex'), cipher_text3.encode('hex'))

for cipher in ciphers_large_keys:
    print 'testing cipher {}'.format(cipher)
    print 'length of key is {}'.format(len(key))
    print 'length of plain_text: {}'.format(len(plain_text))
    cipher_text = encrypt2(cipher, largekey, iv, plain_text)
    recovered_plain_text = decrypt2(cipher, largekey, iv, cipher_text)
    print 'lenght of cipher text is {}'.format(len(cipher_text))
    print 'plain  text in hex {}'.format(plain_text.encode('hex'))
    print 'cipher text in hex {}'.format(cipher_text.encode('hex'))
    print 'recovered plain text is {}'.format(recovered_plain_text)
    newinput, bitarray = change_one_bit(plain_text.encode('hex'))
    print 'new input is {} and its length {}'.format(newinput.decode('hex'), len(newinput))
    cipher_text2 = encrypt2(cipher, largekey, iv, newinput.decode('hex'))
    print 'new cipher text {} '.format(cipher_text2.encode('hex'))
    print 'length of ciphertext {}'.format(len(cipher_text2))
    difference = find_difference_bits(cipher_text.encode('hex'), cipher_text2.encode('hex'))
    cipher_text3 = encrypt2(cipher, newlargekey, iv, plain_text)
    difference2 = find_difference_bits(cipher_text.encode('hex'), cipher_text3.encode('hex'))
