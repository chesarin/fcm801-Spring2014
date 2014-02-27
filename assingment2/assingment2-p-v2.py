#!/usr/bin/env python
import re
import crypt
import time
import logging
import os
from multiprocessing import Process,Queue
logging.basicConfig(level=logging.DEBUG,
                    format='[%(levelname)s] (%(processName)-10s) %(message)s')

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
        
class PasswordCracker(object):
    def __init__(self,shadowQueue,commonPasswords,nameEntries):
        self.shadowQueue = shadowQueue
        self.commonPasswords = commonPasswords
        self.nameEntries = nameEntries
    def run(self):
        while not self.shadowQueue.empty():
            shadowEntry = self.shadowQueue.get()
            shadowTuple = self._getPersonalData(shadowEntry)
            if self._stage1(shadowTuple):
                continue
            elif self._stage2(shadowTuple):
                continue
            elif self._stage3(shadowTuple):
                continue
                
        logging.debug('Dying')
    def _stage1(self,shadowTuple):
        status = False
        username,salt,shadowpass = shadowTuple
        logging.debug('In Stage 1 username %s',username)
        for p in self.commonPasswords:
            ptemp = crypt.crypt(p,salt)
            if ptemp == shadowpass:
                logging.debug ('SUCCESS Stage1:Found password for %s and that is %s',username,p)
                status = True
                break
        return status
    def _stage2(self,shadowTuple):
        status = False
        username,salt,shadowpass = shadowTuple
        logging.debug('In Stage 2 username %s',username)
        ptemp = crypt.crypt(username,salt)
        if ptemp == shadowpass:
            logging.debug ('SUCCESS Stage2:Found password for %s and that is %s',username,username)
            status = True
        return status
    def _stage3(self,shadowTuple):
        status = False
        username,salt,shadowpass = shadowTuple
        logging.debug('In Stage 3 username %s',username)
        for p in self.nameEntries:
            temp = p.lower().split(' ')
            w = temp[0][0]+temp[1]
            # logging.debug('names entry is %s',w)
            ptemp = crypt.crypt(w,salt)
            if ptemp == shadowpass:
                logging.debug ('SUCCESS Stage1:Found password for %s and that is %s',username,p)
                status = True
                break
        return status
        
    def print_results(self):
        print 'passwords cracked via dictionary attack'
        for key,value in self.success.iteritems():
            print 'key:{} password:{} hashed-password:{}'.format(key,value[0],value[1])
    def _getPersonalData(self,shadowEntry):
        name = shadowEntry.get_username()
        salt = shadowEntry.get_salt()
        shadowpass = shadowEntry.get_password()
        return name,salt,shadowpass
            
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
            pw = entry.split(':')[4]
            if pw:
                self.passwords.append(pw)
            # if not re.match(r'^#',entry):
def mpCrack(shadowEntries,commonPasswords,nameEntries):
    starttime = time.clock()
    processes = []
    cpus = os.sysconf("SC_NPROCESSORS_ONLN")
    shadowQueue = Queue(20)
    logging.debug('filling shadowQueue number of cpus %s',str(cpus))
    logging.debug('size of shadowEntries %s',len(shadowEntries))
    for entry in shadowEntries:
        shadowQueue.put(entry)
    logging.debug('before getting into loop to create threads')
    for pname in range(cpus):
        logging.debug('creating process %s',str(pname))
        c = PasswordCracker(shadowQueue,commonPasswords,nameEntries)
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
    commonPasswords = passfp.get_data()
    return commonPasswords
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
    commonPasswords = get_dictionary_words()
    mpCrack(shadowEntries,commonPasswords,nameEntries)
