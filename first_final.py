import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
import binascii
from Tkinter import *
import Tkinter, Tkconstants, tkFileDialog, tkMessageBox
import tkFileDialog
#variables used
BLOCK_SIZE = 16
pad= lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
file
path=""
class Home_Screen:
    def __init__(self,master):
        self.master=master
        self.frame=Frame(self.master)
	tite_label=Label(self.frame,text='FILE CRYPTOGRAPHY', font=12).pack(padx=10,pady=20)
        encryption_btn=Button(self.frame,text='ENCRYPTION',bg='green',command=self.encryption,font=10).pack(padx=20,pady=30)
        decryption_btn=Button(self.frame,text='DECRYPTION',bg='red',command=self.decryption,font=10).pack(padx=10,pady=10)
        self.frame.pack()
    def encryption(self):
        self.newWindow = Toplevel(self.master)
        self.app = Encrypting(self.newWindow)
    def decryption(self):
        self.newWindow = Toplevel(self.master)
        self.app = Decrypting(self.newWindow)
        

class Encrypting:
    def __init__(self,master):
        self.path=""
        self.a= StringVar()
        self.b= StringVar()
        self.master=master
        self.frame=Frame(self.master,width=200,height=100)
        self.spacetext=Label(self.frame,width=50).pack(padx=20,pady=30)
        self.message=Label(self.frame,text='ENTER THE MESSAGE TO BE ENCRYPTED',font=10).pack(padx=10,pady=10)
        self.message_text=Entry(self.frame,textvariable= self.a,width=40).pack()
        self.password=Label(self.frame,text='ENTER PASSWORD',font=10).pack(padx=10,pady=10)
        self.password_text=Entry(self.frame,textvariable= self.b,width=40).pack()
        self.uploadButton=Button(self.frame,text='UPLOAD',fg='white',bg='black',font=9,command=self.fileopener,width=40).pack(padx=10,pady=20)
        self.process_btn=Button(self.frame,text='ENCRYPT',fg='white',bg='green',font=9,command=self.process,width=40).pack(padx=10,pady=20)
        self.spacetext=Label(self.frame,width=50).pack(padx=20,pady=30)
        self.frame.pack(fill=None, expand=False)
        
    def fileopener(self):
        self.filename = tkFileDialog.askopenfilename(initialdir = "D:\Project Folder\Files",title = "Select file")
        self.path = self.filename
        
        #print ("file name= "+self.filename)
        
    def get_private_key(self,password):
        salt = b"this is a salt"
        kdf = PBKDF2(password, salt, 64, 1000)
        #print "kdf= "+kdf
        self.key = kdf[:32]
        #print "key ="+self.key
        return self.key


    def encrypt(self,raw, password):
        private_key = self.get_private_key(password)
        raw = pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(private_key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))


    def process(self):
        if_control=0
        message=self.a.get()
        password=self.b.get()
        encrypted = self.encrypt(message, password)
        #print "***** Encrypted Starting *****"
        #print("Encrypted value= "+encrypted+"\n")

        binaryn = bin(int(binascii.hexlify(encrypted), 16))

        finalencrypt =  binascii.hexlify(binaryn)
        #print "Final Encypted in hex= "+finalencrypt
        #print "\n***** Encrypted Ending *****\n"
        #print "file path= "+self.path
        filename = self.path
        identifier_string ="22B10A8DB164E0754105B7A99BE72E3FE522"
        file = open(filename,'ab')
        file.write(binascii.unhexlify(identifier_string))
        file.write(binascii.unhexlify(finalencrypt))
        file.close()

        succesful = 'Message Succesfully Encrypted in '+filename
        tkMessageBox.showinfo(title='successful',message=succesful)








        
class Decrypting:
    def __init__(self,master):
        self.master=master
        self.a= StringVar()
        self.b= StringVar()
        self.frame=Frame(self.master,width=200,height=100)
        self.spacetext=Label(self.frame,width=50).pack(padx=20,pady=30)
        self.password=Label(self.frame,text='ENTER PASSWORD',font=10).pack()
        self.password_text=Entry(self.frame,textvariable= self.a,width=40).pack()
        self.uploadButton=Button(self.frame,text='upload the File',fg='white',bg='black',font=10,command=self.fileopener,width=40).pack(padx=10,pady=20)
        self.process_btn=Button(self.frame,text='DECRYPT',fg='white',bg='green',font=10,command= self.process,width=40).pack(padx=10,pady=20)
        self.spacetext=Label(self.frame,width=50).pack(padx=20,pady=30)
        self.frame.pack(fill=None, expand=False)
    def fileopener(self):
        self.filename = tkFileDialog.askopenfilename(initialdir = "D:\Project Folder\Files",title = "Select file")
        self.path = self.filename
        
        
    def get_private_key(self,password):
        salt = b"this is a salt"
        kdf = PBKDF2(password, salt, 64, 1000)
        self.key = kdf[:32]
        return self.key
    
    def decrypt(self,enc, password):
        private_key = self.get_private_key(password)
        enc = base64.b64decode(enc)
        iv = enc[:16]
        self.cipher = AES.new(private_key, AES.MODE_CBC, iv)
        return unpad(self.cipher.decrypt(enc[16:]))
    
    def process(self):
	
        password=self.a.get()

        
        filename = self.path
        with open(filename, 'rb') as f:
            content = f.read()
            f.close()
        hexcode = binascii.hexlify(content)
        x=hexcode.find("22b10a8db164e0754105b7a99be72e3fe522")
        dec = hexcode[x+36:len(hexcode)]
        #print dec
	
        hex2binary = binascii.unhexlify(dec)
        n = int(hex2binary, 2)
        binary2ascii = binascii.unhexlify('%x' % n)
	
	print binary2ascii
        decrypted = self.decrypt(binary2ascii, password)
        finaldecrypt = bytes.decode(decrypted)

        
        tkMessageBox.showinfo(title='Successfully Decrypted',message=finaldecrypt)
        

def main(): 
    root = Tk()
    root.title('File Cryptography App')
    root.geometry("400x250+483+250")
    app=Home_Screen(root)
    root.mainloop()

if __name__ == '__main__':
    main()
