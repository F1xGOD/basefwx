from .main import *

def b64encode(string: str): return basefwx.b64encode(string)
def b512encode(string: str, code: str="", use_master: bool = True): return basefwx.b512encode(string, code, use_master=use_master)
def b256encode(string: str): return basefwx.b256encode(string)
def b1024encode(string: str): return basefwx.b1024encode(string)
def bi512encode(string: str): return basefwx.bi512encode(string)
def pb512encode(string: str, code: str="", use_master: bool = True): return basefwx.pb512encode(string, code, use_master=use_master)
def a512encode(string: str): return basefwx.a512encode(string)
def hash512(string: str): return basefwx.hash512(string)
def uhash513(string: str): return basefwx.uhash513(string)

def b64decode(string: str): return basefwx.b64decode(string)
def b256decode(string: str): return basefwx.b256decode(string)
def a512decode(string: str): return basefwx.a512decode(string)
def b512decode(string: str, code: str="", use_master: bool = True): return basefwx.b512decode(string, code, use_master=use_master)
def pb512decode(string: str, code: str="", use_master: bool = True): return basefwx.pb512decode(string, code, use_master=use_master)

def b512encodefile(file: str, code: str, strip_metadata: bool = False, use_master: bool = True): return basefwx.b512file_encode(file, code, strip_metadata=strip_metadata, use_master=use_master)
def b512decodefile(file: str, code: str="", strip_metadata: bool = False, use_master: bool = True): return basefwx.b512file_decode(file, code, strip_metadata=strip_metadata, use_master=use_master)
def b512handlefile(file: str, code: str="", strip_metadata: bool = False, use_master: bool = True): return basefwx.b512file(file, code, strip_metadata=strip_metadata, use_master=use_master)
def fwxAES(file: str, code: str="", light: bool = True, strip_metadata: bool = False, use_master: bool = True): return basefwx.AESfile(file, code, light, strip_metadata=strip_metadata, use_master=use_master)
