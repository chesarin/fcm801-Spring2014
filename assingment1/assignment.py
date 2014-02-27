#!/usr/bin/env python
from collections import defaultdict
import math
import operator
class Frequency(object):
    def __init__(self,input):
        self.input = input
        self.size = len(self.input)
        self.cpdist = {}
        self.db = defaultdict(int)
    def find_frequency(self):
        '''Find the frequency distribution of the input text.
        This gets stored in the dictionary self.db'''
        for i in self.input:
            self.db[i] += 1
        print 'cipher alphabet size {} total size of ciphetext {}'.format(len(self.db),self.size)
        for key,value in sorted(self.db.items()):
            print '{}:{}'.format(key,value)
    def calculate_p_dist(self):
        for key,value in sorted(self.db.items()):
            temp = float(value)/self.size
            self.cpdist[key]=round(temp*100,1)
        print 'probability distribution of ciphertext'
        for key,value in sorted(self.cpdist.items()):
            print '{}:{}'.format(key,value)
    def get_pdist(self):
        return self.cpdist
    def print_db(self):
        print 'total lenght of input {}'.format(self.size)
        total = 0
        self.cipher = {}
        for key,value in sorted(self.db.items()):
            # print key,'',value,
            print "{}:{}".format(key,value)
            total += value
        for key,value in sorted(self.db.items()):
            self.cipher[key]=float(value)/self.size
        print 'total calculated from value {}'.format(total)
        print 'English alphabet frequency probabilities and size of English alphabet {}'.format(len(self.english))
        for key,value in sorted(self.english.items()):
            print '{}:{}'.format(key,value)
    def find_index(self):
        index = 0.0
        print 'cipher text frequency probabilities and size of ciphertext alphabet {}'.format(len(self.db))
        for key,value in sorted(self.cpdist.items()):
            temp = pow((value/100),2)
            print 'index:{} temp:{}'.format(index,temp)
            index += temp
            # print 'letter {} value {} size {} q(probability) {:.1f} temp {:.3f} index {:.3f}'.format(key,value,self.size,round(freq*100,1),temp,index)
        print 'index is {:.3f}'.format(index)
        return round(index,3)
    def find_index2(self):
        if len(self.input) > 1:
            index = 0.0
            accumulator = 0.0
            for key,value in sorted(self.db.items()):
                print 'key:{} value:{}'.format(key,value)
                temp = float(value) * (value - 1)
                accumulator += temp
                print 'temp:{} accumulator:{}'.format(temp,accumulator)
                denominator = len(self.input)*(len(self.input)-1)
                index = accumulator / denominator
            print 'accumulator:{} denominator:{} index is:{}'.format(accumulator,denominator,index)
        else:
            index = 0.000
        return round(index,3)
    def find_smallest(self):
        sorted_cpdist = sorted(self.cpdist.iteritems(),key=operator.itemgetter(1),reverse=True)
        print 'largest probability: {}:{}'.format(sorted_cpdist[0][0],sorted_cpdist[0][1])
        return sorted_cpdist[0][0]
                
class IndexCalc(object):
    def __init__(self,pdist):
        self.pdist = pdist
        self.english = {'A':8.2,'B':1.5,'C':2.8,'D':4.2,'E':12.7,
                        'F':2.2,'G':2.0,'H':6.1,'I':7.0,'J':0.1,
                        'K':0.8,'L':4.0,'M':2.4,'N':6.7,'O':7.5,
                        'P':1.9,'Q':0.1,'R':6.0,'S':6.3,'T':9.0,
                        'U':2.8,'V':1.0,'W':2.4,'X':0.2,'Y':2.0,
                        'Z':0.1}
        self.letters = sorted(list(self.english.keys()))
    def calculate(self):
        print 'english alphabet'
        print 'size of English alphabet {}'.format(len(self.english))
        for key,value in sorted(self.english.items()):
            print '{}:{}'.format(key,value)
        print 'size of Cipher alphabet {}'.format(len(self.pdist))
        for key,value in sorted(self.pdist.items()):
            print '{}:{}'.format(key,value)
    def find_key(self):
        index_db = {}
        for offset in range(len(self.letters)):
            temp = 0.0
            for i in range(len(self.letters)):
                # temp += (self.english[self.letters[i]] + self.pdist[self.letters[(i+offset)%26]])
                letter1 = self.letters[i]
                letter2 = self.letters[(i+offset)%26]
                if letter2 in self.pdist:
                    result = self.english[letter1] * self.pdist[letter2]
                    temp += result
                    # print 'i={} letter1={} letter2:{}'.format(i,letter1,letter2)
                    # print 'english p:{} cipher p:{} and product:{}'.format(self.english[letter1],self.pdist[letter2],result)
            index_db[offset] = temp/100
            print 'Offset:{} Total product:{} percentage:{}'.format(offset,temp,temp/100)
        sorted_indexdb = sorted(index_db.iteritems(),key=operator.itemgetter(1),reverse=True)
        result1 = sorted_indexdb[0][0]
        # for index in range(len(index_db)):
        #     if index_db[index] >= 6.0:
        #         result1 = index
        print 'the correct index is:{}'.format(result1)
        return result1
        
class CSolver(object):
    def __init__(self,filename):
        self.filename=filename
        self.fp = FileProcessor(self.filename)
        self.data = self.fp.get_content()
        self.Freq = Frequency(self.data)
    def solve(self):
        self.Freq.find_frequency()
        self.Freq.calculate_p_dist()
        index = self.Freq.find_index2()
        print 'index is:{}'.format(index)
        if index == 0.062:
            self.shift_cipher()
        elif index == 0.042:
            self.vigenere_cipher()
        else:
            print "sorry can't deal with this cipher text for now"
    def shift_cipher(self):
        pdist = self.Freq.get_pdist()
        indexcalc = IndexCalc(pdist)
        indexcalc.calculate()
        key = indexcalc.find_key()
        cipher = ShiftCipher(self.data,key)
        ptext = cipher.decrypt()
        print 'Cipher Text'
        print self.data
        print 'Decrypted Text'
        print ptext
    def vigenere_cipher(self):
        cipher = Vigenere(self.data)
        cipher.sequence2()
        index_db = cipher.get_index_db()
        keyfinder = VigenereFindKey(index_db,self.data)
        keyfinder.create_index_list()
        keyfinder.create_block_cipher()
        key = keyfinder.get_key()
        dcipher = VigenereCipher(self.data.lower(),key.lower())
        # dcipher = VigenereCipher(self.data.lower(),'about')
        dcipher.decrypt()
        # print 'ciphertext:{}'.format(self.data)
        # print 'key is :{}'.format(key)
                
class FileProcessor(object):
    def __init__(self,filename):
        with open(filename,'r') as infile:
            self.line = infile.readline().rstrip('\n')
    def get_content(self):
        return self.line
        
class ShiftCipher(object):
    def __init__(self,text,shift):
        self.text=text
        self.shift=shift
        self.alphabet=['a','b','c','d','e',
                       'f','g','h','i','j',
                       'k','l','m','n','o',
                       'p','q','r','s','t',
                       'u','v','w','x','y',
                       'z']
    def encrypt(self):
        sub = {}
        for i in range(0,len(self.alphabet)):
            sub[self.alphabet[i]]=self.alphabet[(i+self.shift)%len(self.alphabet)]
        ciphertext=''
        for letter in self.text:
            cletter = sub[letter]
            ciphertext += cletter
        return ciphertext.upper()
    def decrypt(self):
        sub = {}
        print 'shift:{}'.format(self.shift)
        for i in range(len(self.alphabet)):
            sub[self.alphabet[i]]=self.alphabet[(i-self.shift)%len(self.alphabet)]
        for key,value in sorted(sub.items()):
            print 'key:{} value:{}'.format(key,value)
        plaintext=''
        for letter in self.text.lower():
            pletter=sub[letter]
            plaintext += pletter
        return plaintext
            
            # ciphertext[self.alphabet[i]]=self.alphabet[(i+self.shift)%len(self.alphabet)]
class VigenereCipher(ShiftCipher):
    def __init__(self,text,key):
        self.text=text
        self.key=key
        self.alphabetdict={'a':0,'b':1,'c':2,'d':3,'e':5,
                           'f':5,'g':6,'h':7,'i':8,'j':9,
                           'k':10,'l':11,'m':12,'n':13,'o':14,
                           'p':15,'q':16,'r':17,'s':18,'t':19,
                           'u':20,'v':21,'w':22,'x':23,'y':24,
                           'z':25}
        self.alphabet=['a','b','c','d','e',
                       'f','g','h','i','j',
                       'k','l','m','n','o',
                       'p','q','r','s','t',
                       'u','v','w','x','y',
                       'z']


    def encrypt(self):
        psize = len(self.text)
        ksize = len(self.key)
        fullblocks = psize/ksize
        tempkey = self.key*fullblocks
        if len(tempkey) < psize:
            print 'size of tempkey is less than actual plain text size tempkey size:{} plaintext size:{}'.format(len(tempkey),psize)
            diff = psize - len(tempkey)
            print 'difference is:{}'.format(diff)
            tempkey += self.key[:diff]
        print 'size of plain text:{} and size of key:{} total blocks:{} and size of tempkey:{}'.format(psize,ksize,fullblocks,len(tempkey))
        # print 'size of key:{} key is:{}'.format(len(key),key)
        print self.text
        print tempkey
        ciphertext = self.process(self.text,tempkey)
        return ciphertext
    def decrypt(self):
        psize = len(self.text)
        ksize = len(self.key)
        fullblocks = psize/ksize
        tempkey = self.key*fullblocks
        if len(tempkey) < psize:
            print 'size of tempkey is less than actual plain text size tempkey size:{} plaintext size:{}'.format(len(tempkey),psize)
            diff = psize - len(tempkey)
            print 'difference is:{}'.format(diff)
            tempkey += self.key[:diff]
        print 'size of plain text:{} and size of key:{} total blocks:{} and size of tempkey:{}'.format(psize,ksize,fullblocks,len(tempkey))
        # print 'size of key:{} key is:{}'.format(len(key),key)
        print self.text
        print tempkey
        ptext = ''
        for i in range(len(self.text)):
            x = self.alphabetdict[self.text[i]]
            k = self.alphabetdict[tempkey[i]]
            offsetletter = (x-k) % len(self.alphabet)
            pletter = self.alphabet[offsetletter]
            ptext += pletter
            print 'x:{} k:{} offset:{} pletter:{}'.format(x,k,offsetletter,pletter)
        print ptext

    def process(self,text,tempkey):
        ciphertext = ''
        print 'size of alphabet:{}'.format(len(self.alphabet))
        for i in range(len(text)):
            x = self.alphabetdict[text[i]]
            k = self.alphabetdict[tempkey[i]]
            tempresult = (x+k)%len(self.alphabet)
            cipherletter = self.alphabet[tempresult]
            ciphertext += cipherletter
            print 'x:{} k:{} and tempresult:{} cipherletter:{}'.format(x,k,tempresult,cipherletter)
        print ciphertext.upper()
        return ciphertext.upper()

class VigenereFindKey(object):
    def __init__(self,indexdb,ctext):
        self.indexdb = indexdb
        self.ctext = ctext
        self.indexlist = []
        self.index = 0
        self.blocklist = []
        self.tempkey = '' 
        self.alphabet=['a','b','c','d','e',
                       'f','g','h','i','j',
                       'k','l','m','n','o',
                       'p','q','r','s','t',
                       'u','v','w','x','y',
                       'z']
    def create_index_list(self):
        print 'creating index table'
        for key,value in sorted(self.indexdb.items()):
            print 'key:{} value:{}'.format(key,value)
            if value > 0.06:
                self.indexlist.append(key)
        print 'list of best keys to try'
        for i in self.indexlist:
            print 'index:{}'.format(i)
        self.index = self.indexlist[0]
        print 'index chosen:{}'.format(self.index)
    def create_block_cipher(self):
        textsize = len(self.ctext)
        for j in range(textsize/self.index):
            print 'index:{} j:{}'.format(self.index,j)
            start = self.index * j
            end = start +self. index
            print 'start:{} end:{}'.format(start,end)
            cipher = self.ctext[start:end]
            print 'cipher block:{}'.format(cipher)
            self.blocklist.append(cipher)
    def get_key(self):
        tempkey = []
        for i in range(self.index):
            cipher = ''
            for block in self.blocklist:
                cipherletter = block[i]
                cipher += cipherletter
            freq = Frequency(cipher)
            freq.find_frequency()
            freq.calculate_p_dist()
            pdist = freq.get_pdist()
            indexcalc = IndexCalc(pdist)
            indexcalc.calculate()
            key = indexcalc.find_key()
            tempkey.append(key)
            print 'key is :{}'.format(key)
        #     freq.find_index2()
        #     cletter = freq.find_smallest()
        #     self.tempkey += cletter
        # print self.tempkey
        key = ''
        for k in tempkey:
            print 'key is:{}'.format(k)
            letter = self.alphabet[k]
            key += letter
        print key.upper()
        return key.upper()
        
class Vigenere(object):
    def __init__(self,cipher):
        self.text = cipher
        self.index_db = {}
    def sequence(self):
        # index_db = {}
        print 'length of cipher text:{}'.format(len(self.text))
        print 'maximum iterations for a 2 block cipher text:{}'.format(len(self.text)/2)
        max = (len(self.text)/2)+1
        for pos in range(1,max):
            print'pos:{}'.format(pos)
            cipher = ''
            cipher += self.text[0]
            for i in range(1,len(self.text)/pos):
                temp = self.text[0+(i*pos)]
                cipher += temp
            print cipher
            freq = Frequency(cipher)
            freq.find_frequency()
            freq.calculate_p_dist()
            index = freq.find_index()
            self.index_db[pos]=index
        for key,value in sorted(self.index_db.items()):
            print 'key:{} value:{}'.format(key,value)
    def sequence2(self):
        # index_db = {}
        textsize = len(self.text)
        limit = textsize/2
        print 'textsize:{}'.format(textsize)
        for i in range(2,textsize+1):
            # cipher = ''
            # print i,
            blocklist = []
            print 'maximum blocks:{} of size:{}'.format(textsize/i,i)
            for j in range(textsize/i):
                print 'i:{} j:{}'.format(i,j)
                start = i * j
                end = start + i
                print 'start:{} end:{}'.format(start,end)
                cipher = self.text[start:end]
                print 'cipher block:{}'.format(cipher)
                blocklist.append(cipher)
                print 'length of blocklist:{}'.format(len(blocklist))
            index = self.process_blocklist(blocklist,i)
            self.index_db[i]=index
        for key,value in sorted(self.index_db.items()):
            print 'key:{} value:{}'.format(key,value)
    def get_index_db(self):
        return self.index_db
    def process_blocklist(self,blocklist,blocksize):
        totalindex = 0.0
        for i in range(blocksize):
            cipher = ''
            for block in blocklist:
                cipherletter = block[i]
                cipher += cipherletter
            print cipher
            freq = Frequency(cipher)
            freq.find_frequency()
            # freq.calculate_p_dist()
            index = freq.find_index2()
            totalindex += index
            # print 'index is:{}'.format(index)
        print 'blocksize:{} totalindex is:{}'.format(blocksize,totalindex/blocksize)
        return round(totalindex/blocksize,3)
            


            
if __name__ == '__main__':
    file1 = 'cipher1.txt'
    file2 = 'cipher2.txt'
    file3 = 'cipher3.txt'
    solver = CSolver(file3)
    solver.solve()
    # ptext = 'helloceasarthisisasecretmessagehelloandyouhavesolveitcongratulations'
    # key = 'hello'
    # vcipher = VigenereCipher(ptext,key)
    # ctext = vcipher.encrypt()
    # cipher = Vigenere(ctext)
    # cipher.sequence2()
    # cipher = ShiftCipher(ptext,2)
    # ctext = cipher.encrypt()
    # print ctext
    # ctext = data3
    # Freq3 = Frequency(ctext)
    # Freq3.find_frequency()
    # Freq3.calculate_p_dist()
    # Freq3.find_index()
    # pdist = Freq3.get_pdist()
    # indexcalc = IndexCalc(pdist)
    # indexcalc.calculate()
    # index = indexcalc.find_index()
    # print 'index:{}'.format(index)
    # cipher2 = ShiftCipher(ctext,index)
    # mtext = cipher2.decrypt()
    # print ctext
    # print mtext
    # Freq3.print_db()
    # Freq3.find_index()
    # for i in data1:
    #     print i,
    
