from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes, GCD
from base64 import *
enc = 0x53465243657a467558336b7764584a66616a4231636d347a655639354d48566664326b786246397a5a544e66644767784e56396c626d4d775a4446755a334e665a58597a636e6c33614756794d33303d

flag = long_to_bytes(enc)
print(b64decode(flag))
