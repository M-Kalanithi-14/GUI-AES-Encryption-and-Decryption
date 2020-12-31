import tkinter as tk
from tkinter import ttk
from tkinter import filedialog as fd
from tkinter import messagebox as mb
from Crypto.Cipher import AES
from hashlib import sha256
from ast import literal_eval
from chardet import detect as dt

def encryption(type, root1):
	root1.destroy()

	root = tk.Tk()
	root.title("AES Encryption and Decryption")
	root.geometry('{}x{}+0+0'.format(*root.maxsize()))
	root.resizable(False, False)	
	root.group()	

	#============================= Variables ====================================
	global filenameE, inp_strE, keyE, IVe, encodingE
	global filenameD, inp_strD, keyD, IVd, encodingD

	filenameE = tk.StringVar(root)
	inp_strE = tk.StringVar(root)
	encodingE = tk.StringVar(root)
	keyE = tk.StringVar(root)
	IVe = tk.StringVar(root)	

	filenameD = tk.StringVar(root)
	encodingD = tk.StringVar(root)	
	keyD = tk.StringVar(root)
	IVd = tk.StringVar(root)

	encodings = ('ascii', 'big5', 'big5hkscs', 'cp037', 'cp273', 'cp424', 'cp437', 'cp500', 'cp720',
				'cp737', 'cp775', 'cp850', 'cp852', 'cp855', 'cp856', 'cp857', 'cp858', 'cp860', 'cp861',
 				'cp862', 'cp863', 'cp864', 'cp865', 'cp866', 'cp869', 'cp874', 'cp875', 'cp932', 'cp949',
 				'cp950','cp1006', 'cp1026', 'cp1125', 'cp1140', 'cp1250', 'cp1251', 'cp1252', 'cp1253',
 				'cp1254', 'cp1255', 'cp1256', 'cp1257', 'cp1258', 'cp65001', 'euc_jp', 'euc_jis_2004',
 				'euc_jisx0213', 'euc_kr', 'gb2312', 'gbk', 'gb18030', 'hz', 'iso2022_jp', 'iso2022_jp_1',
 				'iso2022_jp_2', 'iso2022_jp_2004', 'iso2022_jp_3', 'iso2022_jp_ext', 'iso2022_kr',
 				'latin_1','iso8859_2', 'iso8859_3', 'iso8859_4', 'iso8859_5', 'iso8859_6', 'iso8859_7',
 				'iso8859_8', 'iso8859_9', 'iso8859_10', 'iso8859_11', 'iso8859_13', 'iso8859_14',
 				'iso8859_15', 'iso8859_16', 'johab', 'koi8_r', 'koi8_t', 'koi8_u', 'kz1048', 'mac_cyrillic',
 				'mac_greek', 'mac_iceland', 'mac_latin2', 'mac_roman', 'mac_turkish', 'ptcp154', 'shift_jis',
 				'shift_jis_2004', 'shift_jisx0213','utf_32', 'utf_32_be', 'utf_32_le', 'utf_16', 'utf_16_be',
				'utf_16_le', 'utf_7', 'utf_8', 'utf_8_sig')

	#============================= Function to Choose File ======================
	def chooseFile(file_type):
		filename = fd.askopenfilename(title="AES Encryption and Decryption")
		if file_type == "encrypt":
			filenameE.set(filename)
		else:
			filenameD.set(filename)

	#============================= Label Frames =================================
	Mainframe = tk.Frame(root)
	Mainframe.grid()

	Tops = tk.Frame(Mainframe , bd = 10 , relief = 'ridge')
	Tops.pack(side = 'top')

	lblTitle = tk.Label(Tops , width = 34 , font = ('arial' , 40 , 'bold') ,
	                            text = 'AES Encryption and Decryption' , justify = 'center')
	lblTitle.grid(padx = 150)

	Membername = tk.LabelFrame(Mainframe , bd = 10 , width = 600 , height = 612 ,
	                            font = ('Times New Roman' , 14 , 'bold') , text = 'Encryption' , relief = 'ridge')
	Membername.pack(padx = 38 , side = 'left')
	Membername.grid_propagate(False)

	Membername2 = tk.LabelFrame(Mainframe , bd = 10 , width = 600 , height = 612 ,
	                            font = ('Times New Roman' , 14 , 'bold') , text = 'Decryption' , relief = 'ridge')
	Membername2.pack(padx = 38 , side = 'right')
	Membername2.grid_propagate(False)

	#============================== Widgets for Encryption ===========================================
	if type == "text":
		lblstr = tk.Label(Membername , font = ('arial', 16),
		                            text = 'Normal Text String' , bd = 7)
		lblstr.grid(row = 0 , column = 0)
		txtstr = tk.Entry(Membername , font = ('arial', 17),
		                        textvariable = inp_strE, bd = 7, insertwidth = 2)
		txtstr.grid(row=0,column=1)
	else:
		lblstr = tk.Label(Membername , font = ('arial', 16),
		                            text = 'Choose Normal File' , bd = 7)
		lblstr.grid(row = 0 , column = 0)
		txtstr = tk.Entry(Membername , font = ('arial', 17),
		                        textvariable = filenameE, bd = 7, insertwidth = 2, state="disabled")
		txtstr.grid(row=0,column=1)

		btnChoose = tk.Button(Membername, font = ('arial', 16), bd=7, text = 'Choose File', command = lambda : chooseFile("encrypt"))
		btnChoose.grid(row=1, column=1)

	lblenc = tk.Label(Membername , font = ('arial', 16),
	                            text = 'Encoding Scheme' , bd = 7)
	lblenc.grid(row = 2 , column = 0)
	txtenc = ttk.Combobox(Membername, font = ('arial', 16), textvariable = encodingE)
	txtenc['values'] = encodings
	txtenc.current(0)
	txtenc.grid(row=2,column=1)

	lblkey = tk.Label(Membername , font = ('arial', 16),
	                            text = 'Encryption Key' , bd = 7)
	lblkey.grid(row = 3 , column = 0)
	txtkey = tk.Entry(Membername , font = ('arial', 17),
	                        textvariable = keyE, bd = 7, insertwidth = 2, show="*")
	txtkey.grid(row=3,column=1)

	lblIV = tk.Label(Membername , font = ('arial', 16),
	                            text = 'Initialization Vector' , bd = 7)
	lblIV.grid(row = 4 , column = 0)
	txtIV = tk.Entry(Membername , font = ('arial', 17),
	                        textvariable = IVe, bd = 7, insertwidth = 2)
	txtIV.grid(row=4,column=1)

	lblResultE = tk.Label(Membername , font = ('arial', 16) , \
	                            text = '\n\n\n\nResult' , bd = 7)
	lblResultE.grid(row = 6 , column = 0 , sticky = 'n')
	txtResultE = tk.Text(Membername , width = 25 , height = 10 , font = ('arial', 16, "bold"),
	                    foreground='black', background='white', state='disabled')
	txtResultE.grid(row = 6 , column = 1)	

	#=============================== Widgets for Decryption ==========================
	if type == "text":
		lblstr = tk.Label(Membername2 , font = ('arial', 16),
		                            text = 'AES Encrypted String' , bd = 7)
		lblstr.grid(row = 0 , column = 0)
		txtstr1 = tk.Entry(Membername2 , font = ('arial', 17), bd = 7, insertwidth = 2)
		txtstr1.grid(row=0,column=1)
	else:
		lblstr = tk.Label(Membername2 , font = ('arial', 16),
		                            text = 'Choose Encrypted File' , bd = 7)
		lblstr.grid(row = 0 , column = 0)
		txtstr1 = tk.Entry(Membername2 , font = ('arial', 17),
		                        textvariable = filenameD, bd = 7, insertwidth = 2, state="disabled")
		txtstr1.grid(row=0,column=1)

		btnChoose1 = tk.Button(Membername2, font = ('arial', 16), bd=7, text = 'Choose File', command = lambda : chooseFile("decrypt"))
		btnChoose1.grid(row=1, column=1)

	lblenc1 = tk.Label(Membername2 , font = ('arial', 16),
	                            text = 'Encoding Scheme' , bd = 7)
	lblenc1.grid(row = 2 , column = 0)
	txtenc1 = ttk.Combobox(Membername2, font = ('arial', 16), textvariable = encodingD)
	txtenc1['values'] = encodings
	txtenc1.current(0)
	txtenc1.grid(row=2,column=1)

	lblkey = tk.Label(Membername2 , font = ('arial', 16),
	                            text = 'Encryption Key' , bd = 7)
	lblkey.grid(row = 3 , column = 0)
	txtkey1 = tk.Entry(Membername2 , font = ('arial', 17),
	                        textvariable = keyD, bd = 7, insertwidth = 2, show="*")
	txtkey1.grid(row=3,column=1)

	lblIV = tk.Label(Membername2 , font = ('arial', 16),
	                            text = 'Initialization Vector' , bd = 7)
	lblIV.grid(row = 4 , column = 0)
	txtIV1 = tk.Entry(Membername2 , font = ('arial', 17),
	                        textvariable = IVd, bd = 7, insertwidth = 2)
	txtIV1.grid(row=4,column=1)

	lblResultD = tk.Label(Membername2 , font = ('arial', 16) , \
	                            text = '\n\n\n\nResult' , bd = 7)
	lblResultD.grid(row = 6 , column = 0 , sticky = 'n')
	txtResultD = tk.Text(Membername2 , width = 25 , height = 10 , font = ('arial', 16, "bold"),
	                    foreground='black', background='white', state='disabled')
	txtResultD.grid(row = 6 , column = 1)

	#============================== Function to Encrypt and Decrypt =====================
	def pad_msg(msg):

		if isinstance(msg, bytes):
			while bool(len(msg) % 16):
				msg += b'0'
		elif isinstance(msg, str):
			while bool(len(msg) % 16):
				msg += " "	

		return msg

	def encrypt(enc_type):
		global filenameE, inp_strE, keyE, IVe
		global filenameD, inp_strD, keyD, IVd



		if not (any(filenameE.get()) or any(filenameD.get()) or any(inp_strE.get()) or any(txtstr1.get())):
			txtstr.config(bg='red', fg='white')
			txtstr1.config(bg='red', fg='white')
			mb.showerror("AES Encryption and Decryption", "You've left both the Input Field Empty!!!\nAll Fields of a single sub-column are Compulsory...")
			
		elif not (any(keyE.get()) or any(keyD.get())):
			txtkey.config(bg='red', fg='white')
			txtkey1.config(bg='red', fg='white')
			mb.showerror("AES Encryption and Decryption", "You've left both the 'Encryption Key' Field Empty!!!\nAll Fields of a single sub-column are Compulsory...")
			
		elif not (any(IVe.get()) or any(IVd.get())):
			txtIV.config(bg='red', fg='white')
			txtIV1.config(bg='red', fg='white')
			mb.showerror("AES Encryption and Decryption", "You've left both the 'Initialization Vector' Field Empty!!!\nAll Fields of a single sub-column are Compulsory...")
			
		else :
			if type == "text":
				if enc_type == "encrypt":
					password = keyE.get().encode()
					key = sha256(password).digest()
					mode = AES.MODE_CBC

					if any(IVe.get()):
						IV = IVe.get().encode()
						cipher = AES.new(key, mode, IV)

					else:
						txtIV.config(bg='red', fg='white')
						mb.showerror("AES Encryption", "You've left the 'Initialization Vector' Field Empty!!!\nAll Fields are Compulsory...")
						cipher = AES.new(key, mode)

					message = pad_msg(inp_strE.get())

					if not any(encodingE.get()):
						mb.showinfo("AES Encryption", "You haven't selected any Encoding Scheme\nThe Default Scheme 'ascii' will be considered...")
						enc_msg = cipher.encrypt(message.encode())
					else:
						enc_msg = cipher.encrypt(message.encode(encodingE.get()))

					txtResultE.config(state="normal")
					txtResultE.delete('1.0', 'end')
					txtResultE.insert('1.0', rf'{enc_msg}')

				else:
					str_input = literal_eval(rf'{txtstr1.get()}')

					password2 = keyD.get().encode()
					key2 = sha256(password2).digest()
					mode2 = AES.MODE_CBC

					if any(IVd.get()):
						IV2 = IVd.get().encode()
						cipher2 = AES.new(key2, mode2, IV2)

					else:
						txtIV1.config(bg='red', fg='white')
						mb.showerror("AES Decryption", "You've left the 'Initialization Vector' Field Empty!!!\nAll Fields are Compulsory...")
						cipher2 = AES.new(key2, mode2)			
					
					dec_msg = cipher2.decrypt(str_input)		

					txtResultD.config(state="normal")
					txtResultD.delete('1.0', 'end')

					if not any(encodingD.get()):
						enc_scheme = dt(dec_msg)['encoding']
						mb.showinfo("AES Encryption", f"You haven't selected any Encoding Scheme\nIt has been detected that the string has been encoded with {enc_scheme}")
						txtResultD.insert('1.0', dec_msg.decode(enc_scheme).strip())
					else:
						txtResultD.insert('1.0', dec_msg.decode(encodingD.get()).strip())

			else:
				if enc_type == "encrypt":

					with open(filenameE.get()) as file:
						data = file.read()

						password = keyE.get().encode()
						key = sha256(password).digest()
						mode = AES.MODE_CBC

						if any(IVe.get()):
							IV = IVe.get().encode()
							cipher = AES.new(key, mode, IV)

						else:
							txtIV.config(bg='red', fg='white')
							mb.showerror("AES Encryption", "You've left the 'Initialization Vector' Field Empty!!!\nAll Fields are Compulsory...")
							cipher = AES.new(key, mode)

						message = pad_msg(data)

						if not any(encodingE.get()):
							mb.showinfo("AES Encryption", "You haven't selected any Encoding Scheme\nThe Default Scheme 'ascii' will be considered...")
							enc_msg = cipher.encrypt(message.encode())
						else:
							enc_msg = cipher.encrypt(message.encode(encodingE.get()))

					with open("Encrypted.dat", 'wb') as res_file:
						res_file.write(enc_msg)

					mb.showinfo("AES Encryption", "The Result has been SUCCESSFULLY Written to a File named 'Encrypted.dat'...")

					txtResultE.config(state="normal")
					txtResultE.delete('1.0', 'end')
					txtResultE.insert('1.0', "The Result has been SUCCESSFULLY Written to a File named 'Encrypted.dat'...")
					txtResultE.config(state="disabled")

				else:
					with open(filenameD.get(), 'rb') as file:
						data = file.read()

						password2 = keyD.get().encode()
						key2 = sha256(password2).digest()
						mode2 = AES.MODE_CBC

						if any(IVd.get()):
							IV2 = IVd.get().encode()
							cipher2 = AES.new(key2, mode2, IV2)

						else:
							txtIV1.config(bg='red', fg='white')
							mb.showerror("AES Decryption", "You've left the 'Initialization Vector' Field Empty!!!\nAll Fields are Compulsory...")
							cipher2 = AES.new(key2, mode2)
						
						dec_msg = cipher2.decrypt(data)

					if not any(encodingD.get()):
						enc_scheme = dt(dec_msg)['encoding']
						mb.showinfo("AES Encryption", f"You haven't selected any Encoding Scheme\nIt has been detected that the string has been encoded with {enc_scheme}")
					else:
						enc_scheme = encodingD.get()

					with open("Decrypted.txt", "w") as res_file:
						res_file.write(dec_msg.decode(enc_scheme).strip())

					mb.showinfo("AES Decryption", "The Result has been SUCCESSFULLY Written to a File named 'Decrypted.dat'...")

					txtResultD.config(state="normal")
					txtResultD.delete('1.0', 'end')
					txtResultD.insert('1.0', "The Result has been SUCCESSFULLY Written to a File named 'Decrypted.txt'...")
					txtResultD.config(state="disabled")

	btnEncrypt = tk.Button(Membername, font=('arial', 16, 'bold'), text='Encrypt', command = lambda : encrypt("encrypt") , bd = 7)
	btnEncrypt.grid(row = 10 , column = 1 , sticky = 'w')

	btnDecrypt = tk.Button(Membername2, font=('arial', 16, 'bold'), text='Decrypt', command = lambda : encrypt("decrypt") , bd = 7)
	btnDecrypt.grid(row = 10 , column = 1 , sticky = 'w')

	mb.showwarning("AES Encryption and Decryption", "This Program Uses the Cipher-Block Chaining(CBC) mode of AES\nThus, all Fields are Compulsory...and\nMessages that are not a block of 16 bytes shall be padded...")

	root.mainloop()

def main():
	root = tk.Tk()
	root.title("AES Encryption and Decryption")
	root.resizable(False, False)	
	root.group()

	#============================= Buttons and Widgets ===========================
	lbltitle = tk.Label(root , font = ('Times new Roman' , 24 , 'bold') ,
	                       text = '\t\t\tAES Encryption and Decryption')
	lbltitle.grid(row = 0 , column = 0)

	lbltitle2 = tk.Label(root , font = ('Times new Roman' , 20 , 'bold') ,
	                       text = '\t\t\t\tChoose Any One...\n')
	lbltitle2.grid(row = 1 , column = 0)

	btnFile = tk.Button(root, font=('arial', 16, 'bold'), text='Encrypt/Decrypt FILE', command = lambda : encryption("file", root) , bd = 7)
	btnFile.grid(row = 2 , column = 0 , sticky = 'w')

	btnText = tk.Button(root, font=('arial', 16, 'bold'), text='Encrypt/Decrypt TEXT STRING', command = lambda : encryption("text", root), bd = 7)
	btnText.grid(row=2 , column=1 , sticky = 'w')

	root.mainloop()
main()