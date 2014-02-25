#!/usr/bin/env python
import re
import password
import time
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
class ShadowFileProcessor(object):
    def __init__(self,filename):
        self.filename = filename
        self.filedata = []
        self.shadowentries = []
    def process_file(self):
        fp = FileProcessor(self.filename)
        fp.extract_data()
        fp.print_data()
        self.filedata = fp.get_data()
    def create_shadow_entry(self):
        for entry in self.filedata:
            temp = re.split(':',entry)
            entry = ShadowEntry(temp[0],temp[1])
            entry.get_salt()
            print entry
            self.shadowentries.append(entry)
    def get_shadow_entries(self):
        return self.shadowentries
class PasswordCracker(object):
    def __init__(self,shadowentries,passdb):
        self.passdb = passdb
        self.shadowentries = shadowentries
        self.success = {}
    def get_cracking(self):
        for entry in self.shadowentries:
            print 'trying to crack {}'.format(entry)
            ptemp = ''
            username = entry.get_username()
            salt = entry.get_salt()
            shadowpass = entry.get_password()
            for p in self.passdb:
                # print 'password testing:{}'.format(p)
                ptemp = password.encryptp(p,salt)
                if ptemp == shadowpass:
                    print 'sucess cracked password:{} for user:{} shadowentry:{} and salt:{}'.format(p,username,shadowpass,salt)
                    self.success[username] = (p,ptemp)
                    break
    def print_results(self):
        print 'passwords cracked via dictionary attack'
        for key,value in self.success.iteritems():
            print 'key:{} password:{} hashed-password:{}'.format(key,value[0],value[1])
class PasswordEncrypt(object):
    def __init__(self,passwd,salt):
        self.encryptpass = password.encrypt(passwd,salt)
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
if __name__ == '__main__':
    starttime = time.clock()
    shadowfile = 'shadow.txt'
    passwordfile = 'passwords.txt'
    passfp = PasswordFileProcessor(passwordfile)
    passfp.process_file()
    passfp.print_data()
    passwdentries = passfp.get_data()
    shadowfp = ShadowFileProcessor(shadowfile)
    shadowfp.process_file()
    shadowfp.create_shadow_entry()
    shadowentries = shadowfp.get_shadow_entries()
    passwordcracker = PasswordCracker(shadowentries,passwdentries)
    print "let's start cracking"
    passwordcracker.get_cracking()
    passwordcracker.print_results()
    stoptime = time.clock()
    print 'running took {} seconds'.format(str(stoptime-starttime))
