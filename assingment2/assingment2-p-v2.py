#!/usr/bin/env python
import re
import crypt
import time
import logging
import os
from multiprocessing import Process,Queue
logging.basicConfig(level=logging.DEBUG,
                    format='[%(levelname)s] (%(processName)-10s) %(message)s')

class UsernameCombinations(object):
    def __init__(self,username,fullname):
        self.username = username
        self.fullname = fullname
        self.combinations = []
    def _combine(self):
        self.combinations.append(self.username)
        self.combinations.append(self.fullname)
        initials = self._initials(self.fullname)
        self.combinations.append(initials)
    def _initials(self,fullname):
        name = fullname.lower()
        splitname = re.split(' ',name)
        initials = splitname[0][0] + splitname[1][0]
        return initials
    def get_combinations(self):
        self._combine()
        return self.combinations
class WordCombination(object):
    def __init__(self,word):
        self.word = word
        self.combinations = []
    def _combine(self):
        self._upper()
        self._lower()
    def _upper(self):
        word = self.word.upper()
        self.combinations.append(word)
    def _lower(self):
        word = self.word.lower()
        self.combinations.append(word)
    def get_combinations(self):
        self._combine()
        return self.combinations
class FileProcessor(object):
    def __init__(self,fname):
        self.fname = fname
        self.data = []
    def extract_data(self):
        with open(self.fname,'r') as f:
            for line in f:
                self.data.append(line.rstrip())
    def get_data(self):
        return self.data
    def print_data(self):
        for i in self.data:
            print i,
class ShadowCombiner(object):
    def __init__(self,passwdEntries,shadowEntries):
        self.passwdEntries = passwdEntries
        self.shadowEntries = shadowEntries
        self.combinedEntries = []
    def _combine(self):
        for shadow in self.shadowEntries:
            for passentry in self.passwdEntries:
                if passentry.get_username() == shadow.get_username():
                    username = passentry.get_username()
                    fullname = passentry.get_fullname()
                    salt = shadow.get_salt()
                    password = shadow.get_password()
                    combination = CombinedEntry(username,fullname,salt,password)
                    self.combinedEntries.append(combination)
                    break
    def get_entries(self):
        self._combine()
        return self.combinedEntries
        
class ShadowFileProcessor(object):
    def __init__(self,filename):
        self.filename = filename
        self.filedata = []
        self.shadowentries = []
    def process_file(self):
        fp = FileProcessor(self.filename)
        fp.extract_data()
        # fp.print_data()
        self.filedata = fp.get_data()
    def create_shadow_entry(self):
        for entry in self.filedata:
            temp = re.split(':',entry)
            entry = ShadowEntry(temp[0],temp[1])
            entry.get_salt()
            # print entry
            self.shadowentries.append(entry)
    def get_shadow_entries(self):
        return self.shadowentries
        
class ShadowEntry(object):
    def __init__(self,username,encpassword):
        self.username = username
        self.encpassword = encpassword
        self.salt = ''
    def get_username(self):
        return self.username
    def get_password(self):
        return self.encpassword
    def get_salt(self):
        temp = re.split(r"\$",self.encpassword)
        self.salt = '${}${}$'.format(temp[1],temp[2])
        return self.salt
    def __str__(self):
        return 'username:{} hashed password:{} salt:{}'.format(self.username,self.encpassword,self.get_salt())
class PasswdEntry(object):
    def __init__(self,username,fullname):
        self.username = username
        self.fullname = fullname
    def get_username(self):
        return self.username
    def get_fullname(self):
        return self.fullname
    def __str__(self):
        return '{} {}'.format(self.username,self.fullname)
class CombinedEntry(PasswdEntry):
    def __init__(self,username,fullname,salt,shadowpass):
        PasswdEntry.__init__(self,username,fullname)
        self.salt = salt
        self.shadowpass = shadowpass
    def get_salt(self):
        return self.salt
    def get_shadowpass(self):
        return self.shadowpass
    def __str__(self):
        return '{} {} {} {}'.format(self.username,self.fullname,self.salt,self.shadowpass)
class PasswordCracker(object):
    def __init__(self,shadowQueue,commonPasswords):
        self.shadowQueue = shadowQueue
        self.commonPasswords = commonPasswords
        # self.stagesList = [self._stage1,self._stage2,self._stage3]
        self.stagesList = [self._stage1,self._stage2]
    def run(self):
        while not self.shadowQueue.empty():
            shadowEntry = self.shadowQueue.get()
            shadowTuple = self._getPersonalData(shadowEntry)
            for stage in self.stagesList:
                if stage(shadowTuple):
                    break
            continue
        logging.debug('Dying')
    def _stage1(self,shadowTuple):
        status = False
        username,fullname,salt,shadowpass = shadowTuple
        logging.debug('In Stage 1 username %s',username)
        for p in self.commonPasswords:
            # logging.debug('stage 3: base word %s',p)
            wordCombinator = WordCombination(p)
            wordList = wordCombinator.get_combinations()
            # logging.debug('size of combination list is %s',len(wordList))
            for word in wordList:
                # logging.debug('stage 3: combination word %s',word)
                ptemp = crypt.crypt(word,salt)
                if ptemp == shadowpass:
                    logging.debug ('SUCCESS Stage1:Found password for %s and that is %s',username,p)
                    status = True
                    break
            if status:
                break
        logging.debug('exiting _stage1')
        return status
        
    def _stage2(self,shadowTuple):
        status = False
        username,fullname,salt,shadowpass = shadowTuple
        logging.debug('In Stage 2 username %s and fullname %s',username,fullname)
        credentialCombination = UsernameCombinations(username,fullname)
        combinations = credentialCombination.get_combinations()
        for p in combinations:
            # logging.debug('combination is %s',p)
            ptemp = crypt.crypt(p,salt)
            if ptemp == shadowpass:
                logging.debug ('SUCCESS Stage2:Found password for %s and that is %s',username,p)
                status = True
                break
        return status
        
    def print_results(self):
        print 'passwords cracked via dictionary attack'
        for key,value in self.success.iteritems():
            print 'key:{} password:{} hashed-password:{}'.format(key,value[0],value[1])
    def _getPersonalData(self,shadowEntry):
        username = shadowEntry.get_username()
        salt = shadowEntry.get_salt()
        shadowpass = shadowEntry.get_shadowpass()
        fullname = shadowEntry.get_fullname()
        return username,fullname,salt,shadowpass
            
class PasswordEncrypt(object):
    def __init__(self,passwd,salt):
        self.encryptpass = crypt.crypt(passwd,salt)
    def get_password(self):
        return self.encryptpass
        
class PasswordFileProcessor(object):
    def __init__(self,filename):
        self.filename = filename
        self.passwords = []
    def process_file(self):
        fp = FileProcessor(self.filename)
        fp.extract_data()
        data = fp.get_data()
        for entry in data:
            if not re.match(r'^#',entry):
                self.passwords.append(entry)
    def print_data(self):
        for i in self.passwords:
            print i
    def get_data(self):
        return self.passwords

class PasswdFileProcessor(PasswordFileProcessor):
    def __init__(self,filename):
        PasswordFileProcessor.__init__(self,filename)
    def process_file(self):
        fp = FileProcessor(self.filename)
        fp.extract_data()
        data = fp.get_data()
        for entry in data:
            temp = re.split(':',entry)
            username = temp[0]
            fullname = temp[4]
            entry = PasswdEntry(username,fullname)
            self.passwords.append(entry)
def mpCrack(combinedEntries,commonPasswords):
    starttime = time.clock()
    processes = []
    cpus = os.sysconf("SC_NPROCESSORS_ONLN")
    shadowQueue = Queue(20)
    logging.debug('filling shadowQueue number of cpus %s',str(cpus))
    logging.debug('size of shadowEntries %s',len(combinedEntries))
    for entry in combinedEntries:
        shadowQueue.put(entry)
    logging.debug('before getting into loop to create threads')
    for pname in range(cpus):
        logging.debug('creating process %s',str(pname))
        c = PasswordCracker(shadowQueue,commonPasswords)
        process = Process(target=c.run,args=())
        process.start()
        processes.append(process)
    
    stoptime = time.clock()
    for p in processes:
        p.join()
    logging.debug('Dying')
def get_name_entries():
    passwdfile = 'passwd.txt'
    passfp = PasswdFileProcessor(passwdfile)
    passfp.process_file()
    # passfp.print_data()
    return passfp.get_data()
def get_dictionary_words():
    passwordfile = 'passwords.txt'
    passfp = PasswordFileProcessor(passwordfile)
    passfp.process_file()
    # passfp.print_data()
    return passfp.get_data()
def combine_entries(nameEntries,shadowEntries):
    combination = ShadowCombiner(nameEntries,shadowEntries)
    return combination.get_entries()

def get_shadow_entries():
    shadowfile = 'shadow.txt'
    shadowfp = ShadowFileProcessor(shadowfile)
    shadowfp.process_file()
    shadowfp.create_shadow_entry()
    shadowEntries = shadowfp.get_shadow_entries()
    return shadowEntries
    
if __name__ == '__main__':
    logging.debug('starting main')
    nameEntries = get_name_entries()
    shadowEntries = get_shadow_entries()
    combinedEntries = combine_entries(nameEntries,shadowEntries)
    commonPasswords = get_dictionary_words()
    mpCrack(combinedEntries,commonPasswords)
