_q='YGOI&Ah'
_p='(&*GHA'
_o=')*HND_'
_n='*IHda&gT'
_m='(*HSA$i'
_l='(*HskW'
_k='&^F*GV'
_j='O&iA6u'
_i='*(HARR'
_h='O.-P[A'
_g='*H)PA-G'
_f='+*jsGA'
_e='(*HGA('
_d='🔓 Password recovered via master key'
_c='No embedded password marker'
_b='decrypted_inv.png'
_a='chaos_inv.png'
_Z='No master.pem found'
_Y=b'--ENCRYPTED_PWD--'
_X='\nFile Does Not Seem To Exist!'
_W='Failed To Encode File, The Key File Is Corrupted!'
_V='RGB'
_U='FAIL!'
_T='SUCCESS!'
_S='BEGIN PRIVATE KEY'
_R='*&fdhauiGGVGUDoiai'
_Q='r'
_P='4G5tRA'
_O='A8igTOmG'
_N='ascii'
_M='Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!'
_L='r+b'
_K='wb'
_J='rb'
_I='big'
_H='-'
_G='0'
_F='='
_E=None
_D='.fwx'
_C='W:\\master.pem'
_B='~/master.pem'
_A='utf-8'
class basefwx:
	import base64,sys,secrets,pathlib,random;from PIL import Image;from io import BytesIO;import numpy as np,os,zlib,hashlib,string;from cryptography.hazmat.primitives import hashes,padding;from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes;from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC;from cryptography.hazmat.primitives import serialization;from cryptography.hazmat.primitives.asymmetric import padding as asym_padding;from cryptography.hazmat.backends import default_backend
	def __init__(A):A.sys.set_int_max_str_digits(2000000000)
	@staticmethod
	def generate_random_string(length):'Generates a random string of the specified length.';A=basefwx.string.ascii_letters+basefwx.string.digits;return''.join(basefwx.secrets.choice(A)for B in range(length))
	@staticmethod
	def derive_key_from_text(text,salt,key_length_bytes=32):'Derives an AES key from text using PBKDF2.';A=basefwx.hashlib.pbkdf2_hmac('sha256',text.encode(),salt.encode(),100000,dklen=key_length_bytes);return A
	@staticmethod
	def _derive_user_key(password):A=password;B=(A[:5]+_R).encode(_A);C=basefwx.PBKDF2HMAC(algorithm=basefwx.hashes.SHA256(),length=32,salt=B,iterations=100000,backend=basefwx.default_backend());return C.derive(A.encode(_A))
	@staticmethod
	def encryptAES(plaintext,user_key):
		A=user_key
		if A=='':
			if basefwx.os.path.exists(basefwx.os.path.expanduser(_B)):A=basefwx.os.path.expanduser(_B)
			elif basefwx.os.path.exists(_C):A=_C
			else:print(_W);basefwx.sys.exit(1)
		basefwx.sys.set_int_max_str_digits(2000000000);E=basefwx.os.urandom(32);N=basefwx._derive_user_key(A);O=basefwx.base64.b64encode(E).decode(_A);G=basefwx.os.urandom(16);P=basefwx.Cipher(basefwx.algorithms.AES(N),basefwx.modes.CBC(G));H=P.encryptor();Q=basefwx.zlib.decompress(basefwx.base64.b64decode(basefwx.MASTERk));I=basefwx.padding.PKCS7(128).padder();R=I.update(O.encode(_A))+I.finalize();B=H.update(R)+H.finalize();B=G+B;S=basefwx.serialization.load_pem_public_key(Q,backend=basefwx.default_backend());J=S.encrypt(E,basefwx.asym_padding.OAEP(mgf=basefwx.asym_padding.MGF1(algorithm=basefwx.hashes.SHA256()),algorithm=basefwx.hashes.SHA256(),label=_E));K=basefwx.os.urandom(16);T=basefwx.Cipher(basefwx.algorithms.AES(E),basefwx.modes.CBC(K));L=T.encryptor();M=basefwx.padding.PKCS7(128).padder();U=M.update(plaintext.encode(_A))+M.finalize();C=L.update(U)+L.finalize();C=K+C
		def F(i):return i.to_bytes(4,byteorder=_I,signed=False)
		D=b'';D+=F(len(B))+B;D+=F(len(J))+J;D+=F(len(C))+C;return D
	@staticmethod
	def decryptAES(encrypted_blob,key=''):
		C=encrypted_blob;A=key;basefwx.sys.set_int_max_str_digits(2000000000)
		if A=='':
			if basefwx.os.path.exists(basefwx.os.path.expanduser(_B)):A=basefwx.os.path.expanduser(_B)
			elif basefwx.os.path.exists(_C):A=_C
			else:print(_M);basefwx.sys.exit(1)
		def D(in_bytes,offset):B=in_bytes;A=offset;C=int.from_bytes(B[A:A+4],_I);A+=4;D=B[A:A+C];A+=C;return D,A
		B=0;F,B=D(C,B);L,B=D(C,B);G,B=D(C,B);E=_E
		if basefwx.os.path.isfile(A):
			with open(A,_J)as M:N=M.read()
			O=basefwx.serialization.load_pem_private_key(N,password=_E,backend=basefwx.default_backend());E=O.decrypt(L,basefwx.asym_padding.OAEP(mgf=basefwx.asym_padding.MGF1(algorithm=basefwx.hashes.SHA256()),algorithm=basefwx.hashes.SHA256(),label=_E))
		else:P=basefwx._derive_user_key(A);Q=F[:16];R=F[16:];S=basefwx.Cipher(basefwx.algorithms.AES(P),basefwx.modes.CBC(Q));H=S.decryptor();T=H.update(R)+H.finalize();I=basefwx.padding.PKCS7(128).unpadder();U=I.update(T)+I.finalize();E=basefwx.base64.b64decode(U)
		V=G[:16];W=G[16:];X=basefwx.Cipher(basefwx.algorithms.AES(E),basefwx.modes.CBC(V));J=X.decryptor();Y=J.update(W)+J.finalize();K=basefwx.padding.PKCS7(128).unpadder();Z=K.update(Y)+K.finalize();return Z.decode(_A)
	MASTERk=b'eJxdkkuPqkAUhPf3V7gnhqcCy25otEGbh4DIThpEXgMKCvLrZ+auLrdWJ1XJl5NUrdc/gmiHycoJ4AFrKwtdfr31n9U/OmIMcQkIzKvHvSp26shB4CIDAFsDrgJ+cy23fm4EtmMsqcqs7pFEKIu3XpMMC1g/2s2Zc3tyqfVDnAs3NhKTV/uR6qir77GgtW+nHXiYevAmPv1TwvLzMPM1tXRnfBnuAlZqVuTMjlyAsH0q1Hf84GNlVK25Zy5XGTNyU0GM7phwmnI1OTO2aRoKuCDpFCAwXhcw2aM5XwWkSx5Jt0NeCfYiAXfTG3JKQ2meh8yIxIzJ8pY5l/E2SGuHZG4hMh9L9oXlZw/cSxWkCPThJzoBeJRiGrKWhns/cp6tMqiCpLtmIyuI9yZjK79T6r8AKg/8JJyBuYClQokiZrOZNtFQGMY12diwsTw3uZ2b4fbep0Z8CDTVE62w+9qzEivOJ/PLO0n40l1kx17AdiPWgQvgwvxbOiL6/zv4BsbIl0s='
	@staticmethod
	def b64encode(string):return basefwx.base64.b64encode(string.encode(_A)).decode(_A)
	@staticmethod
	def b64decode(string):return basefwx.base64.b64decode(string.encode(_A)).decode(_A)
	@staticmethod
	def hash512(string):return basefwx.hashlib.sha256(string.encode(_A)).hexdigest()
	@staticmethod
	def uhash513(string):A=string;return basefwx.hashlib.sha256(basefwx.b512encode(basefwx.hashlib.sha512(basefwx.hashlib.sha1(basefwx.hashlib.sha256(A.encode(_A)).hexdigest().encode(_A)).hexdigest().encode(_A)).hexdigest(),basefwx.hashlib.sha512(A.encode(_A)).hexdigest()).encode(_A)).hexdigest()
	@staticmethod
	def pb512encode(t,p):
		if p=='':
			if basefwx.os.path.exists(basefwx.os.path.expanduser(_B)):p=open(basefwx.os.path.expanduser(_B)).read()
			elif basefwx.os.path.exists(_C):p=open(_C).read()
			else:print(_W);basefwx.sys.exit(1)
		def D(s):
			A=''
			for C in bytearray(s.encode(_N)):B=str(int(bin(C)[2:],2));A+=str(len(B))+B
			return A
		def K(m,n):
			A=len(n);F=int(n);G=10**A;B=len(m);C=(B+A-1)//A*A;H=m.ljust(C,_G);D=[]
			for E in range(0,C,A):I=int(H[E:E+A]);J=(I+F)%G;D.append(str(J).zfill(A))
			return''.join(D)+str(B).zfill(10)
		def V(s):
			C='';A=0;B=0;D=0;F=list(s)
			for E in F:
				A+=1
				if E!='':
					if A==1:B=int(E);C+=chr(int(s[A:A+B]));D=A
					elif B+D+1==A:B=int(E);C+=chr(int(s[A:A+B]));D=A
			return C
		def L(txt,code):return K(D(txt),D(code)).replace(_H,_G).replace(_F,_P)
		def M(u):A=(u[:5]+_R).encode(_A);B=basefwx.PBKDF2HMAC(algorithm=basefwx.hashes.SHA256(),length=32,salt=A,iterations=100000,backend=basefwx.default_backend());return B.derive(u.encode(_A))
		B=''.join(basefwx.random.choices(basefwx.string.digits,k=16));N=L(t,B);E=N.encode(_A);O=basefwx.base64.b64encode(B.encode(_A)).decode(_A);P=M(p);F=basefwx.os.urandom(16);G=basefwx.Cipher(basefwx.algorithms.AES(P),basefwx.modes.CBC(F)).encryptor();H=basefwx.padding.PKCS7(128).padder();Q=H.update(O.encode(_A))+H.finalize();A=G.update(Q)+G.finalize();R=basefwx.zlib.decompress(basefwx.base64.b64decode(basefwx.MASTERk));A=F+A;S=basefwx.serialization.load_pem_public_key(R,backend=basefwx.default_backend());I=S.encrypt(B.encode(_A),basefwx.asym_padding.OAEP(mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),algorithm=basefwx.hashes.SHA256(),label=_E))
		def C(x):return x.to_bytes(4,_I)
		J=C(len(A))+A+C(len(I))+I+C(len(E))+E;T=len(J);U=int.from_bytes(J,_I);return str(T).zfill(6)+str(U)
	@staticmethod
	def pb512decode(digs,key):
		C=key
		if C=='':
			if basefwx.os.path.exists(basefwx.os.path.expanduser(_B)):C=open(basefwx.os.path.expanduser(_B)).read()
			elif basefwx.os.path.exists(_C):C=open(_C).read()
			else:print(_M);basefwx.sys.exit(1)
		D=C
		def L(s):
			A=''
			for C in bytearray(s.encode(_N)):B=str(int(bin(C)[2:],2));A+=str(len(B))+B
			return A
		def M(e,n):
			A=len(n);B=[];E=int(n);F=10**A;G=int(e[-10:]);C=e[:-10]
			for D in range(0,len(C),A):H=int(C[D:D+A]);I=(H-E)%F;B.append(str(I).zfill(A))
			return''.join(B)[:G]
		def N(s):
			C='';A=0;B=0;D=0;F=list(s)
			for E in F:
				A+=1
				if E!='':
					if A==1:B=int(E);C+=chr(int(s[A:A+B]));D=A
					elif B+D+1==A:B=int(E);C+=chr(int(s[A:A+B]));D=A
			return C
		def O(txt,code):
			A=txt
			if A and A[0]==_G:A=_H+A[1:]
			return N(M(A,L(code)))
		def P(u):A=(u[:5]+_R).encode(_A);B=basefwx.PBKDF2HMAC(algorithm=basefwx.hashes.SHA256(),length=32,salt=A,iterations=100000,backend=basefwx.default_backend());return B.derive(u.encode(_A))
		F=int(digs[:6]);G=int(digs[6:]);A=G.to_bytes((G.bit_length()+7)//8,_I)
		if len(A)<F:A=b'\x00'*(F-len(A))+A
		def E(b,o):A=int.from_bytes(b[o:o+4],_I);o+=4;B=b[o:o+A];o+=A;return B,o
		B=0;H,B=E(A,B);Q,B=E(A,B);R,B=E(A,B)
		if _S in D:S=basefwx.serialization.load_pem_private_key(D.encode(_A),_E,backend=basefwx.default_backend());I=S.decrypt(Q,basefwx.asym_padding.OAEP(mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),algorithm=basefwx.hashes.SHA256(),label=_E))
		else:T=P(D);U=H[:16];V=H[16:];J=basefwx.Cipher(basefwx.algorithms.AES(T),basefwx.modes.CBC(U)).decryptor();W=J.update(V)+J.finalize();K=basefwx.padding.PKCS7(128).unpadder();I=basefwx.base64.b64decode(K.update(W)+K.finalize())
		return O(R.decode(_A),I.decode(_A))
	@staticmethod
	def b512encode(string,user_key):
		A=user_key
		if A=='':
			if basefwx.os.path.exists(basefwx.os.path.expanduser(_B)):A=open(basefwx.os.path.expanduser(_B)).read()
			elif basefwx.os.path.exists(_C):A=open(_C).read()
			else:print(_W);basefwx.sys.exit(1)
		def E(s):
			A=''
			for C in bytearray(s.encode(_N)):B=str(int(bin(C)[2:],2));A+=str(len(B))+B
			return A
		def K(bn,ky):
			A=len(ky);F=int(ky);G=10**A;B=len(bn);C=(B+A-1)//A*A;H=bn.ljust(C,_G);D=[]
			for E in range(0,C,A):I=int(H[E:E+A]);J=(I+F)%G;D.append(str(J).zfill(A))
			return''.join(D)+str(B).zfill(10)
		def L(s,c):return basefwx.fwx256bin(K(E(s),E(c)).replace(_H,_G)).replace(_F,_P)
		def M(usr):A=(usr[:5]+_R).encode(_A);B=basefwx.PBKDF2HMAC(algorithm=basefwx.hashes.SHA256(),length=32,salt=A,iterations=100000,backend=basefwx.default_backend());return B.derive(usr.encode(_A))
		C=''.join(basefwx.random.choices(basefwx.string.digits,k=16));N=L(string,C);F=N.encode(_A);O=basefwx.base64.b64encode(C.encode(_A));P=M(A);G=basefwx.os.urandom(16);H=basefwx.Cipher(basefwx.algorithms.AES(P),basefwx.modes.CBC(G)).encryptor();I=basefwx.padding.PKCS7(128).padder();Q=I.update(O)+I.finalize();B=H.update(Q)+H.finalize();B=G+B;R=basefwx.zlib.decompress(basefwx.base64.b64decode(basefwx.MASTERk));S=basefwx.serialization.load_pem_public_key(R,backend=basefwx.default_backend());J=S.encrypt(C.encode(_A),basefwx.asym_padding.OAEP(mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),algorithm=basefwx.hashes.SHA256(),label=_E))
		def D(x):return x.to_bytes(4,_I)
		T=D(len(B))+B+D(len(J))+J+D(len(F))+F;return basefwx.base64.b64encode(T).decode(_A)
	@staticmethod
	def b512decode(enc,key=''):
		A=key
		if A=='':
			if basefwx.os.path.exists(basefwx.os.path.expanduser(_B)):A=open(basefwx.os.path.expanduser(_B)).read()
			elif basefwx.os.path.exists(_C):A=open(_C).read()
			else:print(_M);basefwx.sys.exit(1)
		def I(s):
			A=''
			for C in bytearray(s.encode(_N)):B=str(int(bin(C)[2:],2));A+=str(len(B))+B
			return A
		def J(e,n):
			A=len(n);E=int(n);F=10**A;G=int(e[-10:]);B=e[:-10];C=[]
			for D in range(0,len(B),A):H=int(B[D:D+A]);I=(H-E)%F;C.append(str(I).zfill(A))
			return''.join(C)[:G]
		def K(s):
			C='';A=0;B=0;D=0;F=list(s)
			for E in F:
				A+=1
				if E!='':
					if A==1:B=int(E);C+=chr(int(s[A:A+B]));D=A
					elif B+D+1==A:B=int(E);C+=chr(int(s[A:A+B]));D=A
			return C
		def L(txt,c):
			B=txt.replace(_P,_F);A=basefwx.fwx256unbin(B)
			if A and A[0]==_G:A=_H+A[1:]
			return K(J(A,I(c)))
		def M(u):A=(u[:5]+_R).encode(_A);B=basefwx.PBKDF2HMAC(algorithm=basefwx.hashes.SHA256(),length=32,salt=A,iterations=100000,backend=basefwx.default_backend());return B.derive(u.encode(_A))
		C=basefwx.base64.b64decode(enc)
		def D(b,o):A=int.from_bytes(b[o:o+4],_I);o+=4;B=b[o:o+A];o+=A;return B,o
		B=0;E,B=D(C,B);N,B=D(C,B);O,B=D(C,B)
		if _S in A:P=basefwx.serialization.load_pem_private_key(A.encode(_A),_E,backend=basefwx.default_backend());F=P.decrypt(N,basefwx.asym_padding.OAEP(mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),algorithm=basefwx.hashes.SHA256(),label=_E))
		else:Q=M(A);R=E[:16];S=E[16:];G=basefwx.Cipher(basefwx.algorithms.AES(Q),basefwx.modes.CBC(R)).decryptor();T=G.update(S)+G.finalize();H=basefwx.padding.PKCS7(128).unpadder();F=basefwx.base64.b64decode(H.update(T)+H.finalize())
		return L(O.decode(_A),F.decode(_A))
	@staticmethod
	def b512file_encode(file,code):
		def A(file):
			A=file
			with open(A,_J)as A:return A.read()
		def B(file,code):B=basefwx.b512encode(basefwx.pathlib.Path(file).suffix,code);C=str(basefwx.b512encode(basefwx.base64.b64encode(A(file)).decode(_A),code));return B+_O+C
		def C(nm,cont):
			with open(nm+_D,_K):0
			with open(nm+_D,_L)as A:A.write(cont.encode(_A));A.close()
		def D(name,cd):A=name;C(basefwx.pathlib.Path(A).stem,B(A,cd));basefwx.os.chmod(basefwx.pathlib.Path(basefwx.pathlib.Path(A).stem+_D),0);basefwx.os.remove(basefwx.pathlib.Path(basefwx.pathlib.Path(A)))
		try:D(file,code);return _T
		except:return _U
	@staticmethod
	def b512file(file,password):
		B=file;A=password
		if A=='':
			if basefwx.os.path.exists(basefwx.os.path.expanduser(_B)):A=basefwx.os.path.expanduser(_B)
			elif basefwx.os.path.exists(_C):A=_C
			else:print(_M);basefwx.sys.exit(1)
		if basefwx.os.path.isfile(A):A=open(A,_Q).read()
		def E(file):
			A=file
			with open(A,_J)as A:return A.read()
		def F(file):
			with open(file,_Q)as A:return A.read()
		def G(file,content):
			with open(file,_K):0
			A=open(file,_L);A.write(content);A.close()
		def H(file,code):A=basefwx.b512encode(basefwx.pathlib.Path(file).suffix,code);B=str(basefwx.b512encode(basefwx.base64.b64encode(E(file)).decode(_A),code));return A+_O+B
		def C(content,code):
			C=content;B=code
			if _S in A:B=''
			D=basefwx.b512decode(C.split(_O)[0],B);return[basefwx.base64.b64decode(basefwx.b512decode(C.split(_O)[1],B)),D]
		def I(nm,cont):
			with open(nm+_D,_K):0
			with open(nm+_D,_L)as A:A.write(cont.encode(_A));A.close()
		def J(name,cd):
			A=name;basefwx.os.chmod(basefwx.pathlib.Path(A),511)
			try:B=F(basefwx.pathlib.Path(A).stem+_D);G(basefwx.pathlib.Path(A).stem+C(B,cd)[1],C(B,cd)[0]);basefwx.os.remove(basefwx.pathlib.Path(A))
			except:basefwx.os.chmod(basefwx.pathlib.Path(A),0);print(_M);return _U
		def K(name,cd):A=name;I(basefwx.pathlib.Path(A).stem,H(A,cd));basefwx.os.chmod(basefwx.pathlib.Path(basefwx.pathlib.Path(A).stem+_D),0);basefwx.os.remove(basefwx.pathlib.Path(basefwx.pathlib.Path(A)));return _T
		if not basefwx.os.path.isfile(B):print(_X);exit('-1')
		if basefwx.pathlib.Path(B).suffix==_D:D=J(B,A)
		else:D=K(B,A)
		return D
	class sepImageCipher:
		_MARKER=_Y
		@staticmethod
		def _load_master_pubkey():A=basefwx.zlib.decompress(basefwx.base64.b64decode(basefwx.MASTERk));return basefwx.serialization.load_pem_public_key(A)
		@staticmethod
		def _load_master_privkey():
			for A in(basefwx.os.path.expanduser(_B),_C):
				if basefwx.os.path.exists(A):B=open(A,_J).read();return basefwx.serialization.load_pem_private_key(B,password=_E)
			raise FileNotFoundError(_Z)
		@staticmethod
		def scramble_indices(size,key):B=int(basefwx.hashlib.sha256(key).hexdigest(),16)%2**32;basefwx.np.random.seed(B);A=basefwx.np.arange(size);basefwx.np.random.shuffle(A);return A
		@staticmethod
		def rotate8(x,k):return x<<k&255|x>>8-k
		@staticmethod
		def encrypt_image_inv(path,password,output=_a):
			F=output;H=password.encode();O=basefwx.Image.open(path).convert(_V);L=basefwx.np.array(O);P,Q,X=L.shape;A=L.reshape(-1,3);I=A[basefwx.ImageCipher.scramble_indices(A.shape[0],H)].copy();M=basefwx.hashlib.sha256(H).digest();R=basefwx.np.frombuffer(M*(A.shape[0]//len(M)+1),dtype=basefwx.np.uint8)[:A.shape[0]];S=[(0,1,2),(0,2,1),(1,0,2),(1,2,0),(2,0,1),(2,1,0)]
			for J in range(A.shape[0]):B=int(R[J]);C,D,E=map(int,I[J]);C=C+B&255;D=D+B//2&255;E=E+B//3&255;T=S[B%6];C,D,E=([C,D,E][A]for A in T);K=B%7+1;I[J]=[basefwx.ImageCipher.rotate8(C,K),basefwx.ImageCipher.rotate8(D,K),basefwx.ImageCipher.rotate8(E,K)]
			U=basefwx.Image.fromarray(I.reshape(P,Q,3));U.save(F);V=basefwx.ImageCipher._load_master_pubkey();N=V.encrypt(H,basefwx.asym_padding.OAEP(mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),algorithm=basefwx.hashes.SHA256(),label=_E));W=open(F,_J).read()
			with open(F,_K)as G:G.write(W);G.write(basefwx.ImageCipher._MARKER);G.write(len(N).to_bytes(4,_I));G.write(N)
			print(f"🔥 Encrypted image+pwd → {F}")
		@staticmethod
		def decrypt_image_inv(path,password='',output=_b):
			N=output;M=password;H=open(path,_J).read();I=H.rfind(basefwx.ImageCipher._MARKER)
			if I<0:raise ValueError(_c)
			T=H[:I];O=H[I+len(basefwx.ImageCipher._MARKER):];U=int.from_bytes(O[:4],_I);V=O[4:4+U]
			if M:J=M.encode()
			else:W=basefwx.ImageCipher._load_master_privkey();J=W.decrypt(V,basefwx.asym_padding.OAEP(mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),algorithm=basefwx.hashes.SHA256(),label=_E));print(_d)
			X=basefwx.Image.open(basefwx.BytesIO(T)).convert(_V);P=basefwx.np.array(X);Y,Z,g=P.shape;A=P.reshape(-1,3);Q=basefwx.hashlib.sha256(J).digest();K=basefwx.np.frombuffer(Q*(A.shape[0]//len(Q)+1),dtype=basefwx.np.uint8)[:A.shape[0]];a=[(0,1,2),(0,2,1),(1,0,2),(1,2,0),(2,0,1),(2,1,0)];L=A.copy()
			for B in range(A.shape[0]):C=int(K[B])%7+1;E,F,G=L[B];A[B]=[(E>>C|E<<8-C)&255,(F>>C|F<<8-C)&255,(G>>C|G<<8-C)&255]
			L=A.copy()
			for B in range(A.shape[0]):D=int(K[B]);b=a[D%6];c=[b.index(A)for A in range(3)];d=L[B];A[B]=[d[c[A]]for A in range(3)]
			R=basefwx.np.zeros_like(A);e=basefwx.ImageCipher.scramble_indices(A.shape[0],J);S=basefwx.np.zeros_like(A)
			for B in range(A.shape[0]):D=int(K[B]);E,F,G=A[B];R[B]=[E-D&255,F-D//2&255,G-D//3&255]
			for(B,f)in enumerate(e):S[f]=R[B]
			basefwx.Image.fromarray(S.reshape(Y,Z,3)).save(N);print(f"✅ Decrypted → {N}")
	class ImageCipher:
		_MARKER=_Y
		@staticmethod
		def _load_master_pubkey():A=basefwx.zlib.decompress(basefwx.base64.b64decode(basefwx.MASTERk));return basefwx.serialization.load_pem_public_key(A)
		@staticmethod
		def _load_master_privkey():
			for A in(basefwx.os.path.expanduser(_B),_C):
				if basefwx.os.path.exists(A):B=open(A,_J).read();return basefwx.serialization.load_pem_private_key(B,password=_E)
			raise FileNotFoundError(_Z)
		@staticmethod
		def scramble_indices(size,key):B=int(basefwx.hashlib.sha256(key).hexdigest(),16)%2**32;basefwx.np.random.seed(B);A=basefwx.np.arange(size);basefwx.np.random.shuffle(A);return A
		@staticmethod
		def rotate8(x,k):return x<<k&255|x>>8-k
		@staticmethod
		def encrypt_image_inv(path,password,output=_a):
			F=output;H=password.encode();O=basefwx.Image.open(path).convert(_V);L=basefwx.np.array(O);P,Q,X=L.shape;A=L.reshape(-1,3);I=A[basefwx.ImageCipher.scramble_indices(A.shape[0],H)].copy();M=basefwx.hashlib.sha256(H).digest();R=basefwx.np.frombuffer(M*(A.shape[0]//len(M)+1),dtype=basefwx.np.uint8)[:A.shape[0]];S=[(0,1,2),(0,2,1),(1,0,2),(1,2,0),(2,0,1),(2,1,0)]
			for J in range(A.shape[0]):B=int(R[J]);C,D,E=map(int,I[J]);C=C+B&255;D=D+B//2&255;E=E+B//3&255;T=S[B%6];C,D,E=([C,D,E][A]for A in T);K=B%7+1;I[J]=[basefwx.ImageCipher.rotate8(C,K),basefwx.ImageCipher.rotate8(D,K),basefwx.ImageCipher.rotate8(E,K)]
			U=basefwx.Image.fromarray(I.reshape(P,Q,3));U.save(F);V=basefwx.ImageCipher._load_master_pubkey();N=V.encrypt(H,basefwx.asym_padding.OAEP(mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),algorithm=basefwx.hashes.SHA256(),label=_E));W=open(F,_J).read()
			with open(F,_K)as G:G.write(W);G.write(basefwx.ImageCipher._MARKER);G.write(len(N).to_bytes(4,_I));G.write(N)
			print(f"🔥 Encrypted image+pwd → {F}")
		@staticmethod
		def decrypt_image_inv(path,password='',output=_b):
			N=output;M=password;H=open(path,_J).read();I=H.rfind(basefwx.ImageCipher._MARKER)
			if I<0:raise ValueError(_c)
			T=H[:I];O=H[I+len(basefwx.ImageCipher._MARKER):];U=int.from_bytes(O[:4],_I);V=O[4:4+U]
			if M:J=M.encode()
			else:W=basefwx.ImageCipher._load_master_privkey();J=W.decrypt(V,basefwx.asym_padding.OAEP(mgf=basefwx.asym_padding.MGF1(basefwx.hashes.SHA256()),algorithm=basefwx.hashes.SHA256(),label=_E));print(_d)
			X=basefwx.Image.open(basefwx.BytesIO(T)).convert(_V);P=basefwx.np.array(X);Y,Z,g=P.shape;A=P.reshape(-1,3);Q=basefwx.hashlib.sha256(J).digest();K=basefwx.np.frombuffer(Q*(A.shape[0]//len(Q)+1),dtype=basefwx.np.uint8)[:A.shape[0]];a=[(0,1,2),(0,2,1),(1,0,2),(1,2,0),(2,0,1),(2,1,0)];L=A.copy()
			for B in range(A.shape[0]):C=int(K[B])%7+1;E,F,G=L[B];A[B]=[(E>>C|E<<8-C)&255,(F>>C|F<<8-C)&255,(G>>C|G<<8-C)&255]
			L=A.copy()
			for B in range(A.shape[0]):D=int(K[B]);b=a[D%6];c=[b.index(A)for A in range(3)];d=L[B];A[B]=[d[c[A]]for A in range(3)]
			R=basefwx.np.zeros_like(A);e=basefwx.ImageCipher.scramble_indices(A.shape[0],J);S=basefwx.np.zeros_like(A)
			for B in range(A.shape[0]):D=int(K[B]);E,F,G=A[B];R[B]=[E-D&255,F-D//2&255,G-D//3&255]
			for(B,f)in enumerate(e):S[f]=R[B]
			basefwx.Image.fromarray(S.reshape(Y,Z,3)).save(N);print(f"✅ Decrypted → {N}")
	@staticmethod
	def AESfile(file,password='',light=True):
		K='673827837628292873';B=file;A=password;basefwx.sys.set_int_max_str_digits(2000000000)
		if A=='':
			if basefwx.os.path.exists(basefwx.os.path.expanduser(_B)):A=basefwx.os.path.expanduser(_B)
			elif basefwx.os.path.exists(_C):A=_C
			else:print(_M);basefwx.sys.exit(1)
		if basefwx.os.path.isfile(A):A=open(A,_Q).read()
		if light:
			def E(file):
				A=file
				with open(A,_J)as A:return A.read()
			def L(file):
				with open(file,_L)as A:return A.read()
			def F(file,content):
				with open(file,_K):0
				A=open(file,_L);A.write(content);A.close()
			def G(file,code):A=basefwx.pathlib.Path(file).suffix;B=str(basefwx.base64.b64encode(E(file)).decode(_A));return basefwx.encryptAES(A+_O+B,code)
			def C(content,code):
				B=content
				if _S in A:code=''
				B=basefwx.decryptAES(B,code);C=B.split(_O)[0];return[basefwx.base64.b64decode(B.split(_O)[1]),C]
			def H(nm,cont):
				with open(nm+_D,_K):0
				with open(nm+_D,_L)as A:A.write(cont);A.close()
			def I(name,cd):
				A=name;basefwx.os.chmod(basefwx.pathlib.Path(A),511)
				try:B=basefwx.zlib.decompress(L(basefwx.pathlib.Path(A).stem+_D));F(basefwx.pathlib.Path(A).stem+C(B,cd)[1],C(B,cd)[0]);basefwx.os.remove(basefwx.pathlib.Path(A))
				except:basefwx.os.chmod(basefwx.pathlib.Path(A),0);print(_M);return _U
			def J(name,cd):A=name;H(basefwx.pathlib.Path(A).stem,basefwx.zlib.compress(G(A,cd)));basefwx.os.chmod(basefwx.pathlib.Path(basefwx.pathlib.Path(A).stem+_D),0);basefwx.os.remove(basefwx.pathlib.Path(basefwx.pathlib.Path(A)));return _T
			if not basefwx.os.path.isfile(B):print(_X);exit('-1')
			if basefwx.pathlib.Path(B).suffix==_D:D=I(B,A)
			else:D=J(B,A)
			return D
		else:
			def E(file):
				A=file
				with open(A,_J)as A:return A.read()
			def L(file):
				with open(file,_L)as A:return A.read()
			def F(file,content):
				with open(file,_K):0
				A=open(file,_L);A.write(content);A.close()
			def G(file,code):A=code;B=basefwx.pb512encode(basefwx.pathlib.Path(file).suffix,A);C=str(basefwx.pb512encode(basefwx.base64.b64encode(E(file)).decode(_A),A));return basefwx.encryptAES(B+K+C,A)
			def C(content,code):
				C=code;B=content
				if _S in A:C=''
				B=basefwx.decryptAES(B,C);D=B.split(K)[0];return[basefwx.base64.b64decode(basefwx.pb512decode(B.split(K)[1],C)),basefwx.pb512decode(D,C)]
			def H(nm,cont):
				with open(nm+_D,_K):0
				with open(nm+_D,_L)as A:A.write(cont);A.close()
			def I(name,cd):
				A=name;basefwx.os.chmod(basefwx.pathlib.Path(A),511)
				try:B=E(basefwx.pathlib.Path(A).stem+_D);F(basefwx.pathlib.Path(A).stem+C(B,cd)[1],C(B,cd)[0]);basefwx.os.remove(basefwx.pathlib.Path(A))
				except:basefwx.os.chmod(basefwx.pathlib.Path(A),0);print(_M);return _U
			def J(name,cd):A=name;H(basefwx.pathlib.Path(A).stem,G(A,cd));basefwx.os.chmod(basefwx.pathlib.Path(basefwx.pathlib.Path(A).stem+_D),0);basefwx.os.remove(basefwx.pathlib.Path(basefwx.pathlib.Path(A)));return _T
			if not basefwx.os.path.isfile(B):print(_X);exit('-1')
			if basefwx.pathlib.Path(B).suffix==_D:D=I(B,A)
			else:D=J(B,A)
			return D
	@staticmethod
	def code(string):B={'a':'e*1','b':'&hl','c':'*&Gs','d':'*YHA','e':'K5a{','f':_e,'g':'*&GD2','h':_f,'i':'(aj*a','j':'g%','k':'&G{A','l':'/IHa','m':'*(oa','n':'*KA^7','o':')i*8A','p':_g,'q':'*YFSA',_Q:_h,'s':'{9sl','t':_i,'u':_j,'v':'n):u','w':_k,'x':_l,'y':'{JM','z':'J.!dA','A':'(&Tav','B':'t5','C':'*TGA3','D':'*GABD','E':'{A','F':'pW','G':'*UAK(','H':'&GH+','I':'&AN)','J':'L&VA','K':'(HAF5','L':'&F*Va','M':'^&FVB','N':_m,'O':_n,'P':'&*FAl','Q':')P{A]','R':'*Ha$g','S':'G)OA&','T':'|QG6','U':'Qd&^','V':'hA','W':'8h^va','X':'_9xlA','Y':'*J','Z':'*;pY&',' ':'R7a{',_H:'}F',_F:'OJ)_A','+':'}J','&':'%A','%':'y{A3s','#':'.aGa!','@':'l@','!':'/A','^':'OIp*a','*':'(U','(':'I*Ua]',')':'{0aD','{':'Av[','}':'9j','[':'[a)',']':'*&GBA','|':']Vc!A','/':_o,'~':_p,';':'K}N=O',':':_q,'?':'Oa','.':'8y)a','>':'0{a9','<':'v6Yha',',':'I8ys#',_G:'(HPA7','1':'}v','2':'*HAl%','3':'_)JHS','4':'IG(A','5':'(*GFD','6':'IU(&V','7':'(JH*G','8':'*GHBA','9':'U&G*C','"':'I(a-s'};return''.join(B.get(A,A)for A in string)
	@staticmethod
	def fwx256bin(string):A=basefwx.base64.b32hexencode(basefwx.code(string).encode()).decode();B=A.count(_F);return A.rstrip(_F)+str(B)
	@staticmethod
	def decode(sttr):
		B=sttr;E={'I(a-s':'"','U&G*C':'9','*GHBA':'8','(JH*G':'7','IU(&V':'6','(*GFD':'5','IG(A':'4','_)JHS':'3','*HAl%':'2','}v':'1','(HPA7':_G,'I8ys#':',','v6Yha':'<','0{a9':'>','8y)a':'.','Oa':'?',_q:':','K}N=O':';',_p:'~',_o:'/',']Vc!A':'|','*&GBA':']','[a)':'[','9j':'}','Av[':'{','{0aD':')','I*Ua]':'(','(U':'*','OIp*a':'^','/A':'!','l@':'@','.aGa!':'#','y{A3s':'%','%A':'&','}J':'+','OJ)_A':_F,'}F':_H,'R7a{':' ','*;pY&':'Z','*J':'Y','_9xlA':'X','8h^va':'W','hA':'V','Qd&^':'U','|QG6':'T','G)OA&':'S','*Ha$g':'R',')P{A]':'Q','&*FAl':'P',_n:'O',_m:'N','^&FVB':'M','&F*Va':'L','(HAF5':'K','L&VA':'J','&AN)':'I','&GH+':'H','*UAK(':'G','pW':'F','{A':'E','*GABD':'D','*TGA3':'C','t5':'B','(&Tav':'A','J.!dA':'z','{JM':'y',_l:'x',_k:'w','n):u':'v',_j:'u',_i:'t','{9sl':'s',_h:_Q,'*YFSA':'q',_g:'p',')i*8A':'o','*KA^7':'n','*(oa':'m','/IHa':'l','&G{A':'k','g%':'j','(aj*a':'i',_f:'h','*&GD2':'g',_e:'f','K5a{':'e','*YHA':'d','*&Gs':'c','&hl':'b','e*1':'a'};F=sorted(E.keys(),key=lambda x:-len(x));C='';A=0
		while A<len(B):
			for D in F:
				if B.startswith(D,A):C+=E[D];A+=len(D);break
			else:C+=B[A];A+=1
		return C
	@staticmethod
	def fwx256unbin(string):A=string;B=int(A[-1]);C=A[:-1]+_F*B;return basefwx.decode(basefwx.base64.b32hexdecode(C.encode(_A)).decode(_A))
	@staticmethod
	def b512file_decode(file,code):
		A=code
		if A=='':
			if basefwx.os.path.exists(basefwx.os.path.expanduser(_B)):A=basefwx.os.path.expanduser(_B)
			elif basefwx.os.path.exists(_C):A=_C
			else:print(_M);basefwx.sys.exit(1)
		if basefwx.os.path.isfile(A):A=open(A,_Q).read()
		def D(file):
			with open(file,_Q)as A:return A.read()
		def E(file,content):
			with open(file,_K):0
			A=open(file,_L);A.write(content);A.close()
		def B(content,code):A=content;B=basefwx.b512decode(A.split(_O)[0],code);return[basefwx.base64.b64decode(basefwx.b512decode(A.split(_O)[1],code)),B]
		def C(name,cd):A=name;basefwx.os.chmod(basefwx.pathlib.Path(A),511);C=D(basefwx.pathlib.Path(A).stem+_D);E(basefwx.pathlib.Path(A).stem+B(C,cd)[1],B(C,cd)[0]);basefwx.os.remove(basefwx.pathlib.Path(A))
		try:C(file,A);return _T
		except:basefwx.os.chmod(basefwx.pathlib.Path(basefwx.pathlib.Path(file).stem+_D),0);return _U
	@staticmethod
	def bi512encode(string):
		A=string;C=A[0]+A[len(A)-1]
		def B(string):
			C=str(string);D=map(bin,bytearray(C.encode(_N)));A=''
			for B in D:A+=str(len(str(int(B,2))))+str(int(B,2))
			return str(A)
		def D(string):return str(basefwx.hashlib.sha256(basefwx.fwx256bin(str(str(int(B(string))-int(B(C))).replace(_H,_G))).replace(_F,_P).encode(_A)).hexdigest()).replace(_H,_G)
		return D(A)
	@staticmethod
	def a512encode(string):
		B=string
		def A(string):
			C=str(string);D=map(bin,bytearray(C.encode(_N)));A=''
			for B in D:A+=str(len(str(int(B,2))))+str(int(B,2))
			return str(A)
		C=str(len(A(B))*len(A(B)))
		def D(string):B=string;return str(len(str(len(A(B)))))+str(len(A(B)))+basefwx.fwx256bin(str(str(int(A(B))-int(A(C))).replace(_H,_G))).replace(_F,_P)
		return D(B)
	@staticmethod
	def a512decode(string):
		def E(strin):
			B=strin;F=list(B);C='';A=0;len=0;D=0
			for E in F:
				A+=1
				if E!='':
					if A==1:len=int(E);C+=str(chr(int(B[A:len+A])));D=A
					if A!=1 and len+D+1==A:len=int(E);C+=str(chr(int(B[A:len+A])));D=A
			return C
		def F(string):
			C=str(string);D=map(bin,bytearray(C.encode(_N)));A=''
			for B in D:A+=str(len(str(int(B,2))))+str(int(B,2))
			return str(A)
		def A(string):
			A=string;C=''
			try:
				D=int(A[0]);G=A[D+1:len(A)];H=int(A[1:D+1])*int(A[1:D+1]);I=str(H);B=basefwx.fwx256unbin(G.replace(_P,_F))
				if B[0]==_G:B=_H+B[1:len(B)]
				C=E(str(int(B)+int(F(I))))
			except:C='AN ERROR OCCURED!'
			return C
		return A(string)
	@staticmethod
	def b1024encode(string):
		def A(string):
			def A(string):
				A=string;C=A[0]+A[len(A)-1]
				def B(string):
					C=str(string);D=map(bin,bytearray(C.encode(_N)));A=''
					for B in D:A+=str(len(str(int(B,2))))+str(int(B,2))
					return str(A)
				def D(string):return str(basefwx.hashlib.sha256(basefwx.fwx256bin(str(str(int(B(string))-int(B(C))).replace(_H,_G))).replace(_F,_P).encode(_A)).hexdigest()).replace(_H,_G)
				return D(A)
			def B(string):
				B=string
				def A(string):
					C=str(string);D=map(bin,bytearray(C.encode(_N)));A=''
					for B in D:A+=str(len(str(int(B,2))))+str(int(B,2))
					return str(A)
				C=str(len(A(B))*len(A(B)))
				def D(string):B=string;return str(len(str(len(A(B)))))+str(len(A(B)))+basefwx.fwx256bin(str(str(int(A(B))-int(A(C))).replace(_H,_G))).replace(_F,_P)
				return D(B)
			return A(B(string))
		return A(string)
	@staticmethod
	def b256decode(string):A=string;B=int(A[-1]);C=A[:-1]+_F*B;D=basefwx.base64.b32hexdecode(C.encode(_A)).decode(_A);return basefwx.decode(D)
	@staticmethod
	def b256encode(string):B=basefwx.code(string).encode();A=basefwx.base64.b32hexencode(B).decode();return A.rstrip(_F)+str(A.count(_F))