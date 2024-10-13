# BASEFWX ENCRYPTION ENGINE ->
class basefwx:
 import base64
 import sys
 import pathlib
 import os
 import hashlib
 def __init__(self):
   self.sys.set_int_max_str_digits(2000000000)
   pass
# REVERSIBLE  - SECURITY: ❙
 @staticmethod
 def b64encode(string: str):
   self=basefwx()
   return self.base64.b64encode(string.encode('utf-8')).decode('utf-8')
 @staticmethod
 def b64decode(string: str):
    self=basefwx()
    return self.base64.b64decode(string.encode('utf-8')).decode('utf-8')
 @staticmethod
 def hash512(string: str):
    self=basefwx()
    return self.hashlib.sha256(string.encode('utf-8')).hexdigest()
 @staticmethod
 def uhash513(string: str):
    self=basefwx()
    sti=string
    return self.hashlib.sha256(basefwx.b512encode(self.hashlib.sha512(self.hashlib.sha1(self.hashlib.sha256(sti.encode('utf-8')).hexdigest().encode('utf-8')).hexdigest().encode("utf-8")).hexdigest(),self.hashlib.sha512(sti.encode('utf-8')).hexdigest()).encode('utf-8')).hexdigest()
# REVERSIBLE CODE ENCODE - SECURITY: ❙❙
 @staticmethod
 def pb512encode(string: str, code: str):
     def mdcode(string: str):
      st=str(string)
      binaryvals = map(bin, bytearray(st.encode('ascii')))
      end = ""
      for bb in binaryvals:
        end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
      return str(end)
     def mainenc(string):
      return str((str(int(mdcode((string)))-int(mdcode(code))).replace("-","0")))
     return mainenc(string)
 @staticmethod
 def pb512decode(string: str, code: str):
     def mcode(strin: str):
       end=strin
       eand = list(end)
       finish = ""
       ht = 0
       len = 0
       oht=0
       for een in eand:
         ht+=1
         if een != "":
           if ht==1:
             len=int(een)
             finish+=str(chr(int(end[ht:len+ht])))
             oht=ht
           if ht!=1 and len+oht+1==ht:
             len=int(een)
             finish+=str(chr(int(end[ht:len+ht])))
             oht=ht
       return finish
     def mdcode(string: str):
       st=str(string)
       binaryvals = map(bin, bytearray(st.encode('ascii')))
       end = ""
       for bb in binaryvals:
         end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
       return str(end)
     def maindc(string):
       result=""
       string2=string
       if string2[0]=="0":
         string2="-"+string2[1:len(string2)]
       result=mcode(str(int(string2)+int(mdcode(code))))


       return result
     return maindc(string)

# REVERSIBLE CODE ENCODE - SECURITY: ❙❙
 @staticmethod
 def b512encode(string: str, code: str):
   self=basefwx()
   def fwx256bin(string):
    def code(string):
      mapping={'a':'e*1','b':'&hl','c':'*&Gs','d':'*YHA','e':'K5a{','f':'(*HGA(','g':'*&GD2','h':'+*jsGA','i':'(aj*a','j':'g%','k':'&G{A','l':'/IHa','m':'*(oa','n':'*KA^7','o':')i*8A','p':'*H)PA-G','q':'*YFSA','r':'O.-P[A','s':'{9sl','t':'*(HARR','u':'O&iA6u','v':'n):u','w':'&^F*GV','x':'(*HskW','y':'{JM','z':'J.!dA','A':'(&Tav','B':'t5','C':'*TGA3','D':'*GABD','E':'{A','F':'pW','G':'*UAK(','H':'&GH+','I':'&AN)','J':'L&VA','K':'(HAF5','L':'&F*Va','M':'^&FVB','N':'(*HSA$i','O':'*IHda&gT','P':'&*FAl','Q':')P{A]','R':'*Ha$g','S':'G)OA&','T':'|QG6','U':'Qd&^','V':'hA','W':'8h^va','X':'_9xlA','Y':'*J','Z':'*;pY&',' ':'R7a{','-':'}F','=':'OJ)_A','+':'}J','&':'%A','%':'y{A3s','#':'.aGa!','@':'l@','!':'/A','^':'OIp*a','*':'(U','(':'I*Ua]',')':'{0aD','{':'Av[','}':'9j','[':'[a)',']':'*&GBA','|':']Vc!A','/':')*HND_','~':'(&*GHA',';':'K}N=O',':':'YGOI&Ah','?':'Oa','.':'8y)a','>':'0{a9','<':'v6Yha',',':'I8ys#','0':'(HPA7','1':'}v','2':'*HAl%','3':'_)JHS','4':'IG(A','5':'(*GFD','6':'IU(&V','7':'(JH*G','8':'*GHBA','9':'U&G*C','\"':'I(a-s'
      }
      for char, replacement in mapping.items():
          string = string.replace(char, replacement)
      return string
    return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')
   def mdcode(string: str):
    st=str(string)
    binaryvals = map(bin, bytearray(st.encode('ascii')))
    end = ""
    for bb in binaryvals:
      end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
    return str(end)
   def mainenc(string):
    return fwx256bin(str((str(int(mdcode((string)))-int(mdcode(code))).replace("-","0")))).replace("=","4G5tRA")
   return mainenc(string)
 @staticmethod
 def b512decode(string: str, code: str):
  self=basefwx()
  def mcode(strin: str):
    end=strin
    eand = list(end)
    finish = ""
    ht = 0
    len = 0
    oht=0
    for een in eand:
      ht+=1
      if een != "":
        if ht==1:
          len=int(een)
          finish+=str(chr(int(end[ht:len+ht])))
          oht=ht
        if ht!=1 and len+oht+1==ht:
          len=int(een)
          finish+=str(chr(int(end[ht:len+ht])))
          oht=ht
    return finish
  def mdcode(string: str):
    st=str(string)
    binaryvals = map(bin, bytearray(st.encode('ascii')))
    end = ""
    for bb in binaryvals:
      end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
    return str(end)
  def fwx256unbin(string):
    def decode(sttr):
      mapping={"I(a-s":"\"","U&G*C":"9","*GHBA":"8","(JH*G":"7","IU(&V":"6","(*GFD":"5","IG(A":"4","_)JHS":"3","*HAl%":"2","}v":"1","(HPA7":"0","I8ys#":",","v6Yha":"<","0{a9":">","8y)a":".","Oa":"?","YGOI&Ah":":","K}N=O":";","(&*GHA":"~",")*HND_":"/","]Vc!A":"|","*&GBA":"]","[a)":"[","9j":"}","Av[":"{","{0aD":")","I*Ua]":"(","(U":"*","OIp*a":"^","/A":"!","l@":"@",".aGa!":"#","y{A3s":"%","%A":"&","}J":"+","OJ)_A":"=","}F":"-","R7a{":" ","*;pY&":"Z","*J":"Y","_9xlA":"X","8h^va":"W","hA":"V","Qd&^":"U","|QG6":"T","G)OA&":"S","*Ha$g":"R",")P{A]":"Q","&*FAl":"P","*IHda&gT":"O","(*HSA$i":"N","^&FVB":"M","&F*Va":"L","(HAF5":"K","L&VA":"J","&AN)":"I","&GH+":"H","*UAK(":"G","pW":"F","{A":"E","*GABD":"D","*TGA3":"C","t5":"B","(&Tav":"A","J.!dA":"z","{JM":"y","(*HskW":"x","&^F*GV":"w","n):u":"v","O&iA6u":"u","*(HARR":"t","{9sl":"s","O.-P[A":"r","*YFSA":"q","*H)PA-G":"p",")i*8A":"o","*KA^7":"n","*(oa":"m","/IHa":"l","&G{A":"k","g%":"j","(aj*a":"i","+*jsGA":"h","*&GD2":"g","(*HGA(":"f","K5a{":"e","*YHA":"d","*&Gs":"c","&hl":"b","e*1":"a"}
      for key, value in mapping.items():
        sttr = sttr.replace(key, value)
      return sttr
    return (decode(self.base64.b32hexdecode(string.encode('utf-8')).decode('utf-8')))
  def fwx256bin(string):
   def code(string):
      mapping={'a':'e*1','b':'&hl','c':'*&Gs','d':'*YHA','e':'K5a{','f':'(*HGA(','g':'*&GD2','h':'+*jsGA','i':'(aj*a','j':'g%','k':'&G{A','l':'/IHa','m':'*(oa','n':'*KA^7','o':')i*8A','p':'*H)PA-G','q':'*YFSA','r':'O.-P[A','s':'{9sl','t':'*(HARR','u':'O&iA6u','v':'n):u','w':'&^F*GV','x':'(*HskW','y':'{JM','z':'J.!dA','A':'(&Tav','B':'t5','C':'*TGA3','D':'*GABD','E':'{A','F':'pW','G':'*UAK(','H':'&GH+','I':'&AN)','J':'L&VA','K':'(HAF5','L':'&F*Va','M':'^&FVB','N':'(*HSA$i','O':'*IHda&gT','P':'&*FAl','Q':')P{A]','R':'*Ha$g','S':'G)OA&','T':'|QG6','U':'Qd&^','V':'hA','W':'8h^va','X':'_9xlA','Y':'*J','Z':'*;pY&',' ':'R7a{','-':'}F','=':'OJ)_A','+':'}J','&':'%A','%':'y{A3s','#':'.aGa!','@':'l@','!':'/A','^':'OIp*a','*':'(U','(':'I*Ua]',')':'{0aD','{':'Av[','}':'9j','[':'[a)',']':'*&GBA','|':']Vc!A','/':')*HND_','~':'(&*GHA',';':'K}N=O',':':'YGOI&Ah','?':'Oa','.':'8y)a','>':'0{a9','<':'v6Yha',',':'I8ys#','0':'(HPA7','1':'}v','2':'*HAl%','3':'_)JHS','4':'IG(A','5':'(*GFD','6':'IU(&V','7':'(JH*G','8':'*GHBA','9':'U&G*C','\"':'I(a-s'
      }
      for char, replacement in mapping.items():
          string = string.replace(char, replacement)
      return string
   return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')
  def maindc(string):
    result=""
    string2=fwx256unbin(string.replace("4G5tRA","="))
    if string2[0]=="0":
      string2="-"+string2[1:len(string2)]
    result=mcode(str(int(string2)+int(mdcode(code))))


    return result
  return maindc(string)

  # REVERSIBLE CODE ENCODE - SECURITY: ❙❙
 @staticmethod
 def b512file_encode(file: str, code: str):
      self = basefwx()

      def read(file: str):
          with open(file, 'rb') as file:
              return file.read()

      def encode(file: str, code: str):
          ext = basefwx.b512encode(self.pathlib.Path(file).suffix, code)
          en = str(basefwx.b512encode(self.base64.b64encode(read(file)).decode('utf-8'), code))
          return ext + "A8igTOmG" + en

      def write_fl(nm, cont):
          with open(nm + ".fwx", 'wb'):
              pass
          with open(nm + ".fwx", 'r+b') as f:
              f.write(cont.encode('utf-8'))
              f.close()

      def make_encoded(name, cd):
          write_fl(self.pathlib.Path(name).stem, encode(name, cd))
          self.os.chmod(self.pathlib.Path(self.pathlib.Path(name).stem + ".fwx"), 0)
          self.os.remove(self.pathlib.Path(self.pathlib.Path(name)))
      try:
        make_encoded(file,code)
        return "SUCCESS!"
      except:
          return "FAIL!"
 @staticmethod
 def b512file(file: str, password: str):
      self = basefwx()

      def read(file: str):
          with open(file, 'rb') as file:
              return file.read()

      def read_normal(file: str):
          with open(file, 'r') as fil:
              return fil.read()

      def write(file: str, content: bytes):
          with open(file, 'wb'):
              pass
          f = open(file, 'r+b')
          f.write(content)
          f.close()

      def encode(file: str, code: str):
          ext = basefwx.b512encode(self.pathlib.Path(file).suffix, code)
          en = str(basefwx.b512encode(self.base64.b64encode(read(file)).decode('utf-8'), code))
          return ext + "A8igTOmG" + en

      def decode(content: str, code: str):
          extd = basefwx.b512decode(content.split("A8igTOmG")[0], code)
          return [self.base64.b64decode(basefwx.b512decode(content.split("A8igTOmG")[1], code)), extd]

      def write_fl(nm, cont):
          with open(nm + ".fwx", 'wb'):
              pass
          with open(nm + ".fwx", 'r+b') as f:
              f.write(cont.encode('utf-8'))
              f.close()

      def make_decoded(name, cd):
          self.os.chmod(self.pathlib.Path(name), 0o777)
          try:
              ct = read_normal(self.pathlib.Path(name).stem + ".fwx")
              write(self.pathlib.Path(name).stem + decode(ct, cd)[1], decode(ct, cd)[0])
              self.os.remove(self.pathlib.Path(name))
          except:
              self.os.chmod(self.pathlib.Path(name), 0)
              print("Failed To Decode File, The Password Is Wrong Or The File Is Corrupted!")
              return "FAIL!"

      def make_encoded(name, cd):
          write_fl(self.pathlib.Path(name).stem, encode(name, cd))
          self.os.chmod(self.pathlib.Path(self.pathlib.Path(name).stem + ".fwx"), 0)
          self.os.remove(self.pathlib.Path(self.pathlib.Path(name)))
          return "SUCCESS!"

      if not self.os.path.isfile(file):
        print("\nFile Does Not Seem To Exist!")
        exit("-1")
      if self.pathlib.Path(file).suffix == ".fwx":
        v=make_decoded(file, password)
      else:
        v=make_encoded(file, password)
      return v



 @staticmethod
 def b512file_decode(file: str, code: str):
      self = basefwx()

      def read_normal(file: str):
          with open(file, 'r') as fil:
              return fil.read()

      def write(file: str, content: bytes):
          with open(file, 'wb'):
              pass
          f = open(file, 'r+b')
          f.write(content)
          f.close()

      def decode(content: str, code: str):
          extd = basefwx.b512decode(content.split("A8igTOmG")[0], code)
          return [self.base64.b64decode(basefwx.b512decode(content.split("A8igTOmG")[1], code)), extd]

      def make_decoded(name, cd):
          self.os.chmod(self.pathlib.Path(name), 0o777)
          ct = read_normal(self.pathlib.Path(name).stem+".fwx")
          write(self.pathlib.Path(name).stem + decode(ct, cd)[1], decode(ct, cd)[0])
          self.os.remove(self.pathlib.Path(name))
      try:
        make_decoded(file,code)
        return "SUCCESS!"
      except:
          return "FAIL!"






      # IRREVERSIBLE CODELESS ENCODE - SECURITY: ❙❙❙
 @staticmethod
 def bi512encode(string: str):
  self=basefwx()
  code=string[0]+string[len(string)-1]
  def fwx256bin(string):
   def code(string):
      mapping={'a':'e*1','b':'&hl','c':'*&Gs','d':'*YHA','e':'K5a{','f':'(*HGA(','g':'*&GD2','h':'+*jsGA','i':'(aj*a','j':'g%','k':'&G{A','l':'/IHa','m':'*(oa','n':'*KA^7','o':')i*8A','p':'*H)PA-G','q':'*YFSA','r':'O.-P[A','s':'{9sl','t':'*(HARR','u':'O&iA6u','v':'n):u','w':'&^F*GV','x':'(*HskW','y':'{JM','z':'J.!dA','A':'(&Tav','B':'t5','C':'*TGA3','D':'*GABD','E':'{A','F':'pW','G':'*UAK(','H':'&GH+','I':'&AN)','J':'L&VA','K':'(HAF5','L':'&F*Va','M':'^&FVB','N':'(*HSA$i','O':'*IHda&gT','P':'&*FAl','Q':')P{A]','R':'*Ha$g','S':'G)OA&','T':'|QG6','U':'Qd&^','V':'hA','W':'8h^va','X':'_9xlA','Y':'*J','Z':'*;pY&',' ':'R7a{','-':'}F','=':'OJ)_A','+':'}J','&':'%A','%':'y{A3s','#':'.aGa!','@':'l@','!':'/A','^':'OIp*a','*':'(U','(':'I*Ua]',')':'{0aD','{':'Av[','}':'9j','[':'[a)',']':'*&GBA','|':']Vc!A','/':')*HND_','~':'(&*GHA',';':'K}N=O',':':'YGOI&Ah','?':'Oa','.':'8y)a','>':'0{a9','<':'v6Yha',',':'I8ys#','0':'(HPA7','1':'}v','2':'*HAl%','3':'_)JHS','4':'IG(A','5':'(*GFD','6':'IU(&V','7':'(JH*G','8':'*GHBA','9':'U&G*C','\"':'I(a-s'
      }
      for char, replacement in mapping.items():
          string = string.replace(char, replacement)
      return string
   return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')
  def mdcode(string: str):
    st=str(string)
    binaryvals = map(bin, bytearray(st.encode('ascii')))
    end = ""
    for bb in binaryvals:
      end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
    return str(end)
  def mainenc(string):
    return str(self.hashlib.sha256((fwx256bin(str((str(int(mdcode((string)))-int(mdcode(code))).replace("-","0")))).replace("=","4G5tRA")).encode('utf-8')).hexdigest()).replace("-","0")
  return mainenc(string)

# CODELESS ENCODE - SECURITY: ❙
 @staticmethod
 def a512encode(string: str):
  self=basefwx()
  def fwx256bin(string):
   def code(string):
      mapping={'a':'e*1','b':'&hl','c':'*&Gs','d':'*YHA','e':'K5a{','f':'(*HGA(','g':'*&GD2','h':'+*jsGA','i':'(aj*a','j':'g%','k':'&G{A','l':'/IHa','m':'*(oa','n':'*KA^7','o':')i*8A','p':'*H)PA-G','q':'*YFSA','r':'O.-P[A','s':'{9sl','t':'*(HARR','u':'O&iA6u','v':'n):u','w':'&^F*GV','x':'(*HskW','y':'{JM','z':'J.!dA','A':'(&Tav','B':'t5','C':'*TGA3','D':'*GABD','E':'{A','F':'pW','G':'*UAK(','H':'&GH+','I':'&AN)','J':'L&VA','K':'(HAF5','L':'&F*Va','M':'^&FVB','N':'(*HSA$i','O':'*IHda&gT','P':'&*FAl','Q':')P{A]','R':'*Ha$g','S':'G)OA&','T':'|QG6','U':'Qd&^','V':'hA','W':'8h^va','X':'_9xlA','Y':'*J','Z':'*;pY&',' ':'R7a{','-':'}F','=':'OJ)_A','+':'}J','&':'%A','%':'y{A3s','#':'.aGa!','@':'l@','!':'/A','^':'OIp*a','*':'(U','(':'I*Ua]',')':'{0aD','{':'Av[','}':'9j','[':'[a)',']':'*&GBA','|':']Vc!A','/':')*HND_','~':'(&*GHA',';':'K}N=O',':':'YGOI&Ah','?':'Oa','.':'8y)a','>':'0{a9','<':'v6Yha',',':'I8ys#','0':'(HPA7','1':'}v','2':'*HAl%','3':'_)JHS','4':'IG(A','5':'(*GFD','6':'IU(&V','7':'(JH*G','8':'*GHBA','9':'U&G*C','\"':'I(a-s'
      }
      for char, replacement in mapping.items():
          string = string.replace(char, replacement)
      return string
   return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')
  def mdcode(string: str):
    st=str(string)
    binaryvals = map(bin, bytearray(st.encode('ascii')))
    end = ""
    for bb in binaryvals:
      end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
    return str(end)
  code=(str(len(mdcode((string)))*len(mdcode((string)))))
  def mainenc(string):
    return str(len(str(len(mdcode(string)))))+str(len(mdcode(string)))+fwx256bin(str((str(int(mdcode((string)))-int(mdcode(code))).replace("-","0")))).replace("=","4G5tRA")
  return mainenc(string)
 @staticmethod
 def a512decode(string: str):
   self=basefwx()
   def mcode(strin: str):
    end=strin
    eand = list(end)
    finish = ""
    ht = 0
    len = 0
    oht=0
    for een in eand:
      ht+=1
      if een != "":
       if ht==1:
         len=int(een)
         finish+=str(chr(int(end[ht:len+ht])))
         oht=ht
       if ht!=1 and len+oht+1==ht:
         len=int(een)
         finish+=str(chr(int(end[ht:len+ht])))
         oht=ht
    return finish
   def mdcode(string: str):
    st=str(string)
    binaryvals = map(bin, bytearray(st.encode('ascii')))
    end = ""
    for bb in binaryvals:
     end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
    return str(end)
   def fwx256unbin(string):
    def decode(sttr):
     mapping={"I(a-s":"\"","U&G*C":"9","*GHBA":"8","(JH*G":"7","IU(&V":"6","(*GFD":"5","IG(A":"4","_)JHS":"3","*HAl%":"2","}v":"1","(HPA7":"0","I8ys#":",","v6Yha":"<","0{a9":">","8y)a":".","Oa":"?","YGOI&Ah":":","K}N=O":";","(&*GHA":"~",")*HND_":"/","]Vc!A":"|","*&GBA":"]","[a)":"[","9j":"}","Av[":"{","{0aD":")","I*Ua]":"(","(U":"*","OIp*a":"^","/A":"!","l@":"@",".aGa!":"#","y{A3s":"%","%A":"&","}J":"+","OJ)_A":"=","}F":"-","R7a{":" ","*;pY&":"Z","*J":"Y","_9xlA":"X","8h^va":"W","hA":"V","Qd&^":"U","|QG6":"T","G)OA&":"S","*Ha$g":"R",")P{A]":"Q","&*FAl":"P","*IHda&gT":"O","(*HSA$i":"N","^&FVB":"M","&F*Va":"L","(HAF5":"K","L&VA":"J","&AN)":"I","&GH+":"H","*UAK(":"G","pW":"F","{A":"E","*GABD":"D","*TGA3":"C","t5":"B","(&Tav":"A","J.!dA":"z","{JM":"y","(*HskW":"x","&^F*GV":"w","n):u":"v","O&iA6u":"u","*(HARR":"t","{9sl":"s","O.-P[A":"r","*YFSA":"q","*H)PA-G":"p",")i*8A":"o","*KA^7":"n","*(oa":"m","/IHa":"l","&G{A":"k","g%":"j","(aj*a":"i","+*jsGA":"h","*&GD2":"g","(*HGA(":"f","K5a{":"e","*YHA":"d","*&Gs":"c","&hl":"b","e*1":"a"}
     for key, value in mapping.items():
      sttr = sttr.replace(key, value)
     return sttr
    return (decode(self.base64.b32hexdecode(string.encode('utf-8')).decode('utf-8')))
   def fwx256bin(string):
    def code(string):
     mapping={'a':'e*1','b':'&hl','c':'*&Gs','d':'*YHA','e':'K5a{','f':'(*HGA(','g':'*&GD2','h':'+*jsGA','i':'(aj*a','j':'g%','k':'&G{A','l':'/IHa','m':'*(oa','n':'*KA^7','o':')i*8A','p':'*H)PA-G','q':'*YFSA','r':'O.-P[A','s':'{9sl','t':'*(HARR','u':'O&iA6u','v':'n):u','w':'&^F*GV','x':'(*HskW','y':'{JM','z':'J.!dA','A':'(&Tav','B':'t5','C':'*TGA3','D':'*GABD','E':'{A','F':'pW','G':'*UAK(','H':'&GH+','I':'&AN)','J':'L&VA','K':'(HAF5','L':'&F*Va','M':'^&FVB','N':'(*HSA$i','O':'*IHda&gT','P':'&*FAl','Q':')P{A]','R':'*Ha$g','S':'G)OA&','T':'|QG6','U':'Qd&^','V':'hA','W':'8h^va','X':'_9xlA','Y':'*J','Z':'*;pY&',' ':'R7a{','-':'}F','=':'OJ)_A','+':'}J','&':'%A','%':'y{A3s','#':'.aGa!','@':'l@','!':'/A','^':'OIp*a','*':'(U','(':'I*Ua]',')':'{0aD','{':'Av[','}':'9j','[':'[a)',']':'*&GBA','|':']Vc!A','/':')*HND_','~':'(&*GHA',';':'K}N=O',':':'YGOI&Ah','?':'Oa','.':'8y)a','>':'0{a9','<':'v6Yha',',':'I8ys#','0':'(HPA7','1':'}v','2':'*HAl%','3':'_)JHS','4':'IG(A','5':'(*GFD','6':'IU(&V','7':'(JH*G','8':'*GHBA','9':'U&G*C','\"':'I(a-s'
    }
     for char, replacement in mapping.items():
        string = string.replace(char, replacement)
     return string
    return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')
   def maindc(string):
    result=""
    try:
     leoa=int(string[0])
     string2=string[leoa+1:len(string)]
     cdo=int(string[1:leoa+1])*int(string[1:leoa+1])
     code=(str(cdo))
     string3=fwx256unbin(string2.replace("4G5tRA","="))
     if string3[0]=="0":
      string3="-"+string3[1:len(string3)]
     result=mcode(str(int(string3)+int(mdcode(code))))
    except:
     result="AN ERROR OCCURED!"
    return result
   return maindc(string)

# UNDCODABLE IRREVERSIBLE CODELESS ENCODE - SECURITY: ❙❙❙❙
 @staticmethod
 def b1024encode(string: str):
  self=basefwx()
  def fwx1024uBIN(string: str):
   def fwx512iiBIN(string: str):
    code=string[0]+string[len(string)-1]
    def fwx256bin(string):
     def code(string):
      mapping={'a':'e*1','b':'&hl','c':'*&Gs','d':'*YHA','e':'K5a{','f':'(*HGA(','g':'*&GD2','h':'+*jsGA','i':'(aj*a','j':'g%','k':'&G{A','l':'/IHa','m':'*(oa','n':'*KA^7','o':')i*8A','p':'*H)PA-G','q':'*YFSA','r':'O.-P[A','s':'{9sl','t':'*(HARR','u':'O&iA6u','v':'n):u','w':'&^F*GV','x':'(*HskW','y':'{JM','z':'J.!dA','A':'(&Tav','B':'t5','C':'*TGA3','D':'*GABD','E':'{A','F':'pW','G':'*UAK(','H':'&GH+','I':'&AN)','J':'L&VA','K':'(HAF5','L':'&F*Va','M':'^&FVB','N':'(*HSA$i','O':'*IHda&gT','P':'&*FAl','Q':')P{A]','R':'*Ha$g','S':'G)OA&','T':'|QG6','U':'Qd&^','V':'hA','W':'8h^va','X':'_9xlA','Y':'*J','Z':'*;pY&',' ':'R7a{','-':'}F','=':'OJ)_A','+':'}J','&':'%A','%':'y{A3s','#':'.aGa!','@':'l@','!':'/A','^':'OIp*a','*':'(U','(':'I*Ua]',')':'{0aD','{':'Av[','}':'9j','[':'[a)',']':'*&GBA','|':']Vc!A','/':')*HND_','~':'(&*GHA',';':'K}N=O',':':'YGOI&Ah','?':'Oa','.':'8y)a','>':'0{a9','<':'v6Yha',',':'I8ys#','0':'(HPA7','1':'}v','2':'*HAl%','3':'_)JHS','4':'IG(A','5':'(*GFD','6':'IU(&V','7':'(JH*G','8':'*GHBA','9':'U&G*C','\"':'I(a-s'
      }
      for char, replacement in mapping.items():
          string = string.replace(char, replacement)
      return string
     return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')
    def mdcode(string: str):
     st=str(string)
     binaryvals = map(bin, bytearray(st.encode('ascii')))
     end = ""
     for bb in binaryvals:
      end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
     return str(end)
    def mainenc(string):
     return str(self.hashlib.sha256((fwx256bin(str((str(int(mdcode((string)))-int(mdcode(code))).replace("-","0")))).replace("=","4G5tRA")).encode('utf-8')).hexdigest()).replace("-","0")
    return mainenc(string)
   def fwx512ciBIN(string: str):
    def fwx256bin(string):
     def code(string):
      mapping={'a':'e*1','b':'&hl','c':'*&Gs','d':'*YHA','e':'K5a{','f':'(*HGA(','g':'*&GD2','h':'+*jsGA','i':'(aj*a','j':'g%','k':'&G{A','l':'/IHa','m':'*(oa','n':'*KA^7','o':')i*8A','p':'*H)PA-G','q':'*YFSA','r':'O.-P[A','s':'{9sl','t':'*(HARR','u':'O&iA6u','v':'n):u','w':'&^F*GV','x':'(*HskW','y':'{JM','z':'J.!dA','A':'(&Tav','B':'t5','C':'*TGA3','D':'*GABD','E':'{A','F':'pW','G':'*UAK(','H':'&GH+','I':'&AN)','J':'L&VA','K':'(HAF5','L':'&F*Va','M':'^&FVB','N':'(*HSA$i','O':'*IHda&gT','P':'&*FAl','Q':')P{A]','R':'*Ha$g','S':'G)OA&','T':'|QG6','U':'Qd&^','V':'hA','W':'8h^va','X':'_9xlA','Y':'*J','Z':'*;pY&',' ':'R7a{','-':'}F','=':'OJ)_A','+':'}J','&':'%A','%':'y{A3s','#':'.aGa!','@':'l@','!':'/A','^':'OIp*a','*':'(U','(':'I*Ua]',')':'{0aD','{':'Av[','}':'9j','[':'[a)',']':'*&GBA','|':']Vc!A','/':')*HND_','~':'(&*GHA',';':'K}N=O',':':'YGOI&Ah','?':'Oa','.':'8y)a','>':'0{a9','<':'v6Yha',',':'I8ys#','0':'(HPA7','1':'}v','2':'*HAl%','3':'_)JHS','4':'IG(A','5':'(*GFD','6':'IU(&V','7':'(JH*G','8':'*GHBA','9':'U&G*C','\"':'I(a-s'
      }
      for char, replacement in mapping.items():
          string = string.replace(char, replacement)
      return string
     return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')
    def mdcode(string: str):
     st=str(string)
     binaryvals = map(bin, bytearray(st.encode('ascii')))
     end = ""
     for bb in binaryvals:
      end += str(len(str(int(bb, 2)))) + str(int(bb, 2))
     return str(end)
    code=(str(len(mdcode((string)))*len(mdcode((string)))))
    def mainenc(string):
     return str(len(str(len(mdcode(string)))))+str(len(mdcode(string)))+fwx256bin(str((str(int(mdcode((string)))-int(mdcode(code))).replace("-","0")))).replace("=","4G5tRA")
    return mainenc(string)
   return fwx512iiBIN(fwx512ciBIN(string))
  return fwx1024uBIN(string)

# CODELESS ENCODE - SECURITY: ❙
 @staticmethod
 def b256decode(string):
    self=basefwx()
    def decode(sttr):
     mapping={"I(a-s":"\"","U&G*C":"9","*GHBA":"8","(JH*G":"7","IU(&V":"6","(*GFD":"5","IG(A":"4","_)JHS":"3","*HAl%":"2","}v":"1","(HPA7":"0","I8ys#":",","v6Yha":"<","0{a9":">","8y)a":".","Oa":"?","YGOI&Ah":":","K}N=O":";","(&*GHA":"~",")*HND_":"/","]Vc!A":"|","*&GBA":"]","[a)":"[","9j":"}","Av[":"{","{0aD":")","I*Ua]":"(","(U":"*","OIp*a":"^","/A":"!","l@":"@",".aGa!":"#","y{A3s":"%","%A":"&","}J":"+","OJ)_A":"=","}F":"-","R7a{":" ","*;pY&":"Z","*J":"Y","_9xlA":"X","8h^va":"W","hA":"V","Qd&^":"U","|QG6":"T","G)OA&":"S","*Ha$g":"R",")P{A]":"Q","&*FAl":"P","*IHda&gT":"O","(*HSA$i":"N","^&FVB":"M","&F*Va":"L","(HAF5":"K","L&VA":"J","&AN)":"I","&GH+":"H","*UAK(":"G","pW":"F","{A":"E","*GABD":"D","*TGA3":"C","t5":"B","(&Tav":"A","J.!dA":"z","{JM":"y","(*HskW":"x","&^F*GV":"w","n):u":"v","O&iA6u":"u","*(HARR":"t","{9sl":"s","O.-P[A":"r","*YFSA":"q","*H)PA-G":"p",")i*8A":"o","*KA^7":"n","*(oa":"m","/IHa":"l","&G{A":"k","g%":"j","(aj*a":"i","+*jsGA":"h","*&GD2":"g","(*HGA(":"f","K5a{":"e","*YHA":"d","*&Gs":"c","&hl":"b","e*1":"a"}
     for key, value in mapping.items():
      sttr = sttr.replace(key, value)
     return sttr
    return (decode(self.base64.b32hexdecode(string.encode('utf-8')).decode('utf-8')))
 @staticmethod
 def b256encode(string):
    self=basefwx()
    def code(string):
     mapping={'a':'e*1','b':'&hl','c':'*&Gs','d':'*YHA','e':'K5a{','f':'(*HGA(','g':'*&GD2','h':'+*jsGA','i':'(aj*a','j':'g%','k':'&G{A','l':'/IHa','m':'*(oa','n':'*KA^7','o':')i*8A','p':'*H)PA-G','q':'*YFSA','r':'O.-P[A','s':'{9sl','t':'*(HARR','u':'O&iA6u','v':'n):u','w':'&^F*GV','x':'(*HskW','y':'{JM','z':'J.!dA','A':'(&Tav','B':'t5','C':'*TGA3','D':'*GABD','E':'{A','F':'pW','G':'*UAK(','H':'&GH+','I':'&AN)','J':'L&VA','K':'(HAF5','L':'&F*Va','M':'^&FVB','N':'(*HSA$i','O':'*IHda&gT','P':'&*FAl','Q':')P{A]','R':'*Ha$g','S':'G)OA&','T':'|QG6','U':'Qd&^','V':'hA','W':'8h^va','X':'_9xlA','Y':'*J','Z':'*;pY&',' ':'R7a{','-':'}F','=':'OJ)_A','+':'}J','&':'%A','%':'y{A3s','#':'.aGa!','@':'l@','!':'/A','^':'OIp*a','*':'(U','(':'I*Ua]',')':'{0aD','{':'Av[','}':'9j','[':'[a)',']':'*&GBA','|':']Vc!A','/':')*HND_','~':'(&*GHA',';':'K}N=O',':':'YGOI&Ah','?':'Oa','.':'8y)a','>':'0{a9','<':'v6Yha',',':'I8ys#','0':'(HPA7','1':'}v','2':'*HAl%','3':'_)JHS','4':'IG(A','5':'(*GFD','6':'IU(&V','7':'(JH*G','8':'*GHBA','9':'U&G*C','\"':'I(a-s'
    }
     for char, replacement in mapping.items():
        string = string.replace(char, replacement)
     return string
    return self.base64.b32hexencode(code(string).encode('utf-8')).decode('utf-8')

# ENCRYPTION TYPES:
# BASE64 - b64encode/b64decode  V1.0
# HASH512 - hash512  V1.0
# HASH512U - uhash513 V1.2
# FWX512RP - pb512encode/pb512encode V2.0
# FWX512R - b512encode/b512decode V2.0 ★
# FWX512I - bi512encode V3.4 ★
# FWX512C - a512encode/a512decode V2.0 ❗❗❗ (NOT RECCOMENDED)
# FWX1024I - b1024encode V4.0 ★ (BEST)
# FWX256R - b256encode/b256decode V1.3 ❗❗❗ (NOT RECCOMENDED)

# HOW TO USE: basefwx.ENCRTPTION-TYPE("text","password")
