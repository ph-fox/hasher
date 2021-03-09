import hashlib, os, random, readline, pyperclip, socket, base64, re

user = socket.gethostname()
uid = os.getuid()

def md5():
	try:
		ui = input('[!] Encrypt/Decrypt (D/E): ').lower()
		if ui == 'd' or ui == 'decrypt' or ui == 'decode':
			#file = 'rockyou.txt'
			file = input("[*] Enter wordlist path: ")
			ui = input('[*] Enter hash to decrypt: ')
			style = '-'

			o = open(file, 'r')
			for i in o:
				x = hashlib.md5(i.strip().encode())
				wtf = x.hexdigest()
				if wtf == ui:
					os.system('clear')
					a = random.choices(list(style), k=len(wtf))
					b = random.choices(list(style), k=len(i))
					c = ''.join(a)
					d = ''.join(b)
					print("[</>] Hash Md5 Decrypted = Success!\n")
					print('--------------------'+c)
					print(f'| [+] Encrypted: {wtf}  |')
					print('--------------------'+c)
					print('| [-] Decrypted: '+i.strip()+'   |')
					print('--------------------'+d)
					print('| [!] Hash Type: MD5  |')
					print('--------------------')
					exit(0)

		elif ui == 'e' or ui == 'encrypt':
			ui = input('Enter word to encrypt: ').encode()
			x = hashlib.md5(ui).hexdigest()
			print(f'\nEncrypted: {x}')
			pyperclip.copy(x)
			print('\nsuccessfully copied to clipbaord!')
			exit(0)

		else:
			input('Error!! Press Enter to Select Again...')
			os.system('clear')
			md5()

	except UnicodeDecodeError:
		os.system('clear')
		for i in range(1):
			print('[!] Hash Md5 Decrypt = Fail ')
			for i in range(5):
				print('Error! hash not found!')


def sha1():
	try:
		ui = input('[!] Encrypt/Decrypt (D/E): ').lower()
		if ui == 'd' or ui == 'decrypt' or ui == 'decode':
			file = 'rockyou.txt'
			#file = input("[*] Enter wordlist path: ")
			ui = input('[*] Enter hash to decrypt: ')
			style = '-'

			o = open(file, 'r')
			for i in o:
				x = hashlib.sha1(i.strip().encode())
				wtf = x.hexdigest()
				if wtf == ui:
					os.system('clear')
					a = random.choices(list(style), k=len(wtf))
					b = random.choices(list(style), k=len(i))
					c = ''.join(a)
					d = ''.join(b)
					print("[</>] Hash Sha1 Decrypted = Success!\n")
					print('--------------------'+c)
					print(f'| [+] Encrypted: {wtf}  |')
					print('--------------------'+c)
					print('| [-] Decrypted: '+i.strip()+'   |')
					print('--------------------'+d)
					print('| [!] Hash Type: SHA1  |')
					print('--------------------')
					exit(0)

		elif ui == 'e' or ui == 'encrypt':
			ui = input('Enter word to encrypt: ').encode()
			x = hashlib.sha1(ui).hexdigest()
			print(f'\nEncrypted: {x}')
			pyperclip.copy(x)
			print('\nsuccessfully copied to clipbaord!')
			exit(0)

		else:
			input('Error!! Press Enter to Select Again...')
			os.system('clear')
			md5()

	except UnicodeDecodeError:
		os.system('clear')
		for i in range(1):
			print('[!] Hash Sha1 Decrypt = Fail ')
			for i in range(5):
				print('Error! hash not found!')


def sha224():
	try:
		ui = input('[!] Encrypt/Decrypt (D/E): ').lower()
		if ui == 'd' or ui == 'decrypt' or ui == 'decode':
			file = 'rockyou.txt'
			#file = input("[*] Enter wordlist path: ")
			ui = input('[*] Enter hash to decrypt: ')
			style = '-'

			o = open(file, 'r')
			for i in o:
				x = hashlib.sha224(i.strip().encode())
				wtf = x.hexdigest()
				if wtf == ui:
					os.system('clear')
					a = random.choices(list(style), k=len(wtf))
					b = random.choices(list(style), k=len(i))
					c = ''.join(a)
					d = ''.join(b)
					print("[</>] Hash Sha224 Decrypted = Success!\n")
					print('--------------------'+c)
					print(f'| [+] Encrypted: {wtf}  |')
					print('--------------------'+c)
					print('| [-] Decrypted: '+i.strip()+'   |')
					print('--------------------'+d)
					print('| [!] Hash Type: Sha224  |')
					print('--------------------')
					exit(0)

		elif ui == 'e' or ui == 'encrypt':
			ui = input('Enter word to encrypt: ').encode()
			x = hashlib.sha224(ui).hexdigest()
			print(f'\nEncrypted: {x}')
			pyperclip.copy(x)
			print('\nsuccessfully copied to clipbaord!')
			exit(0)

		else:
			input('Error!! Press Enter to Select Again...')
			os.system('clear')
			md5()

	except UnicodeDecodeError:
		os.system('clear')
		for i in range(1):
			print('[!] Hash Sha224 Decrypt = Fail ')
			for i in range(5):
				print('Error! Hash not found!')


def sha256():
	try:
		ui = input('[!] Encrypt/Decrypt (D/E): ').lower()
		if ui == 'd' or ui == 'decrypt' or ui == 'decode':
			file = 'rockyou.txt'
			#file = input("[*] Enter wordlist path: ")
			ui = input('[*] Enter hash to decrypt: ')
			style = '-'

			o = open(file, 'r')
			for i in o:
				x = hashlib.sha256(i.strip().encode())
				wtf = x.hexdigest()
				if wtf == ui:
					os.system('clear')
					a = random.choices(list(style), k=len(wtf))
					b = random.choices(list(style), k=len(i))
					c = ''.join(a)
					d = ''.join(b)
					print("[</>] Hash sha256 Decrypted = Success!\n")
					print('--------------------'+c)
					print(f'| [+] Encrypted: {wtf}  |')
					print('--------------------'+c)
					print('| [-] Decrypted: '+i.strip()+'   |')
					print('--------------------'+d)
					print('| [!] Hash Type: sha256  |')
					print('--------------------')
					exit(0)

		elif ui == 'e' or ui == 'encrypt':
			ui = input('Enter word to encrypt: ').encode()
			x = hashlib.sha256(ui).hexdigest()
			print(f'\nEncrypted: {x}')
			pyperclip.copy(x)
			print('\nsuccessfully copied to clipbaord!')
			exit(0)

		else:
			input('Error!! Press Enter to Select Again...')
			os.system('clear')
			md5()

	except UnicodeDecodeError:
		os.system('clear')
		for i in range(1):
			print('[!] Hash sha256 Decrypt = Fail ')
			for i in range(5):
				print('Error! Hash not found!')


def sha512():
	try:
		ui = input('[!] Encrypt/Decrypt (D/E): ').lower()
		if ui == 'd' or ui == 'decrypt' or ui == 'decode':
			file = 'rockyou.txt'
			#file = input("[*] Enter wordlist path: ")
			ui = input('[*] Enter hash to decrypt: ')
			style = '-'

			o = open(file, 'r')
			for i in o:
				x = hashlib.sha512(i.strip().encode())
				wtf = x.hexdigest()
				if wtf == ui:
					os.system('clear')
					a = random.choices(list(style), k=len(wtf))
					b = random.choices(list(style), k=len(i))
					c = ''.join(a)
					d = ''.join(b)
					print("[</>] Hash sha512 Decrypted = Success!\n")
					print('--------------------'+c)
					print(f'| [+] Encrypted: {wtf}  |')
					print('--------------------'+c)
					print('| [-] Decrypted: '+i.strip()+'   |')
					print('--------------------'+d)
					print('| [!] Hash Type: sha512  |')
					print('--------------------')
					exit(0)

		elif ui == 'e' or ui == 'encrypt':
			ui = input('Enter word to encrypt: ').encode()
			x = hashlib.sha512(ui).hexdigest()
			print(f'\nEncrypted: {x}')
			pyperclip.copy(x)
			print('\nsuccessfully copied to clipbaord!')
			exit(0)

		else:
			input('Error!! Press Enter to Select Again...')
			os.system('clear')
			md5()

	except UnicodeDecodeError:
		os.system('clear')
		for i in range(1):
			print('[!] Hash sha512 Decrypt = Fail ')
			for i in range(5):
				print('Error! Hash not found!')

def base():
	print("""
/======================\\
 /| [1] =>= base16   |\\
 /| [2] =>= base32   |\\
 /| [3] =>= base64   |\\
 /| [4] =>= base85   |\\
 -----------------------
""")
	ui = input('Select~> ')
	if ui == '1':
		ui = input('Encode/Decode (d/e): ').lower()
		if ui =='encode' or ui == 'encrypt' or ui == 'e':
			os.system('clear')
			ui = input('Enter word to encrypt: ').encode()
			x = base64.b16encode(bytes(ui))
			print(x)


def main():
	print(f"""
>-------------------------------<
|  number  |  Hash Type       ||
 | =========================== ||
|  [1] ===>> MD5              ||
 | [2] ===>> SHA1              ||
|  [3] ===>> SHA224           ||
 | [4] ===>> SHA256            ||
|  [5] ===>> SHA512           ||
 | [6] ===>> Base              ||
>>=============================<<
{user}:{uid}
""")
	print(f'┌──(Select㉿Number)-[~{os.getcwd()}]')
	ui = input('└─>->> ')

	if ui == '1':
		md5()
	elif ui == '2':
		sha1()
	elif ui == '3':
		sha224()
	elif ui == '4':
		sha256()
	elif ui == '5':
		sha512()
	elif ui == '6':
		for i in range(5):
			print('comming soon!')
		txt = 'comming soon'
		for i in txt:
			print(i)

	else:
		print('[!] Select from the numbers. to perform hash.')
		os.system(ui)
		main()


main()
