import Rsa
import tkinter

#Methods
# modeEncrypt() method prepares the frame for encryption process
def modeEncrypt():
    mainTitle.config(text="Rsa Encryptor")
    publicKeyEntry.pack_forget()
    privateKeyEntry.pack_forget()
    publicKeyLabel.config(text="Public Key: ")
    privateKeyLabel.config(text="Private Key: ")
    outputArea.config(state='normal')
    outputArea.delete('1.0', tkinter.END)
    outputArea.config(state='disabled')
    inputArea.delete('1.0', tkinter.END)
    submitButton.config(text= "Encrypt", command= lambda: encrypt())
    modeButton.config(text="Decryption", command=lambda: modeDecrypt())

# modeDecrypt() method prepares the frame for encryption process
def modeDecrypt():
    mainTitle.config(text="Rsa Decryptor")
    submitButton.pack_forget()
    outputArea.pack_forget()
    outputLabel.pack_forget()
    privateKeyEntry.pack_forget()
    privateKeyLabel.pack_forget()
    publicKeyLabel.config(text="Public Key: ")
    publicKeyEntry.delete(0, tkinter.END)
    publicKeyEntry.pack(anchor="w", padx=50, pady=10)
    privateKeyLabel.config(text="Private Key: ")
    privateKeyLabel.pack(anchor="w", padx=50, pady=10)
    privateKeyEntry.delete(0, tkinter.END)
    privateKeyEntry.pack(anchor="w", padx=50, pady=10)
    outputLabel.config(text="Decrypted Text")
    outputLabel.pack(anchor="w", padx=50, pady=10)
    outputArea.config(state='normal')
    outputArea.delete('1.0', tkinter.END)
    outputArea.config(state='disabled')
    outputArea.pack(anchor="w", padx=50, pady=10)
    inputArea.delete('1.0', tkinter.END)
    submitButton.pack()
    submitButton.config(text="Decrypt",command=lambda: decrypt(int(privateKeyEntry.get()), int(publicKeyEntry.get())))
    modeButton.config(text="Encryption", command=lambda: modeEncrypt())

# encrypt() method includes implementation for encrypting with Rsa algorithm. It benefits from the methods
# of RsaEncryptor class. It encrypts the text in inputArea and prints the encrypted text on outputArea.
# Also, it prints the values of public key (n) and private key (d) as labels because they are required
# for desired to decrypt the encrypted text
def encrypt():
    x = inputArea.get("1.0", "end-1c")
    y = []
    for char in x:
        y.append(ord(char))
    p = Rsa.prime_finder()
    q = Rsa.prime_finder()
    public_n = p * q
    A = Rsa.totient(p, q)
    e = Rsa.public_e_finder(A)
    d = Rsa.private_d_finder(e, A)
    encrypted_msg = []
    encrypted_text = ""

    for char in y:
        encrypted_msg.append(Rsa.encrypt(char, e, public_n))

    for char in encrypted_msg:
        encrypted_text = encrypted_text + chr(char)

    outputArea.config(state='normal')
    outputArea.delete('1.0', tkinter.END)
    outputArea.insert(tkinter.END, encrypted_text)
    outputArea.config(state='disabled')
    publicKeyLabel.config(text="Public Key: " + str(public_n))
    privateKeyLabel.config(text="Private Key: " + str(d))

# decrypt() method includes implementation for decrypting with Rsa algorithm. It benefits from the methods
# of RsaEncryptor class. It decrypts the text in inputArea and prints the decrypted text on outputArea.

def decrypt(d,n):
    x = inputArea.get("1.0", "end-1c")
    y = []
    for char in x:
        y.append(Rsa.decrypt(ord(char),d,n))

    decrypted_text = ""
    for char in y:
        decrypted_text = decrypted_text + (chr(char))
    outputArea.config(state='normal')
    outputArea.delete('1.0', tkinter.END)
    outputArea.insert(tkinter.END, decrypted_text)
    outputArea.config(state='disabled')

# Initiations of the UI elements
frame = tkinter.Tk()
frame.geometry("1000x750")
frame.title("Rsa Encryption Converter")
frame.iconbitmap('src/icon.ico')
mainTitle = tkinter.Label(frame, text="Rsa Encryptor", width=20, height=2, highlightthickness=10, font=("Arial", 20))
mainTitle.pack()
modeLabel = tkinter.Label(frame, text="Change Mode", font=("Arial", 15))
modeLabel.pack( padx=50, pady=10)
modeButton = tkinter.Button(frame, text="Decryption", command= lambda: modeDecrypt(), width=20)
modeButton.pack(padx=50, pady=10)


inputLabel = tkinter.Label(frame, text="Enter text", justify="left", font=("Arial", 15))
inputLabel.pack(anchor="w", padx=50)
inputArea = tkinter.Text(frame, height = 5, width = 800, font=("Arial", 12))
inputArea.pack(anchor="w", padx=50)

publicKeyLabel = tkinter.Label(frame, justify="left", text="Public Key:", font=("Arial", 15))
publicKeyLabel.pack(anchor="w", padx=50, pady=10)
publicKeyEntry = tkinter.Entry(frame, justify="left", font=("Arial", 15))

privateKeyLabel = tkinter.Label(frame, justify="left", text="Private Key:", font=("Arial", 15))
privateKeyLabel.pack(anchor="w", padx=50, pady=10)
privateKeyEntry = tkinter.Entry(frame, justify="left", font=("Arial", 15))

outputLabel = tkinter.Label(frame, text="Encrypted Text", justify="left", font=("Arial", 15))
outputLabel.pack(anchor="w", padx=50, pady=10)
outputArea = tkinter.Text(frame, height = 5, width = 800, font=("Arial", 15), state='disabled')
outputArea.pack(anchor="w", padx=50, pady=10)

submitButton = tkinter.Button(frame, text="Encrypt", command=lambda: encrypt(), width=20)
submitButton.pack()

frame.mainloop()







