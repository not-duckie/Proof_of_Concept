'''
This is proof of concept python3 script written for Pentester's lab ctf badge 
ECDSA same nonce challenge. Try to do it yourself before copying the script from
here.

Ps:- I have used the ruby code as it was used in ther server too for creation of cookie once
the private is cracked.


'''



import base64
from hashlib import sha256
import urllib.parse
from ecdsa import util, SigningKey, SECP256k1
from ecdsa.util import sigencode_string, sigdecode_string
from ecdsa.numbertheory import inverse_mod
from hashlib import sha256

def attack(publicKeyOrderInteger, signaturePair1, signaturePair2, messageHash1, messageHash2): 
    r1 = signaturePair1[0]
    s1 = signaturePair1[1]
    r2 = signaturePair2[0]
    s2 = signaturePair2[1]

    #Convert Hex into Int
    L1 = int(messageHash1, 16)
    L2 = int(messageHash2, 16)

    if (r1 != r2):
        print("ERROR: The signature pairs given are not susceptible to this attack")
        return None

    #A bit of Math 
    #L1 = Hash(message_1) 
    #L2 = Hash(message_2)
    #pk = Private Key (unknown to attacker)
    #R  = r1 == r2
    #K  = K value that was used (unknown to attacker)
    #N  = integer order of G (part of public key)
    
    #         From Signing Defintion
    #s1 = (L1 + pk * R) / K Mod N    and     s2 = (L2 + pk * R) / K Mod N
    
    #         Rearrange 
    #K = (L1 + pk * R) / s1 Mod N    and     K = (L2 + pk * R) / s2 Mod N
    
    #         Set Equal
    #(L1 + pk * R) / s1 = (L2 + pk * R) / s2     Mod N
    
    #         Solve for pk (private key)
    #pk Mod N = (s2 * L1 - s1 * L2) / R * (s1 - s2)
    #pk Mod N = (s2 * L1 - s1 * L2) * (R * (s1 - s2)) ** -1

    numerator = (((s2 * L1) % publicKeyOrderInteger) - ((s1 * L2) % publicKeyOrderInteger))
    denominator = inverse_mod(r1 * ((s1 - s2) % publicKeyOrderInteger), publicKeyOrderInteger)

    privateKey = numerator * denominator % publicKeyOrderInteger

    return privateKey

if __name__ == "__main__":

    a = '''
	  |\\
          | \\
()########|  ==========================================================*
          | /
          |/
   
				made by duckie 
				(github.com/not-duckie)
	'''
   
    print (a)

    cookie1 ='ZHVja2llMS0tMEUCIFy98GRuXbTqo5jzZfLqeg49QZt%2BAzDjnOkr3e3KxPm8AiEA5reRV9y7xia8Ciw5EFFDyjb36kK3BCF76Nsb%2FwwZuw0%3D'
    m1, sig1 = base64.b64decode(urllib.parse.unquote(cookie1)).split(b'--')
    r1,s1 = util.sigdecode_der(sig1,SECP256k1.order)
    hash1 = sha256(m1).hexdigest()



    cookie2 ='ZHVja2llMi0tMEUCIFy98GRuXbTqo5jzZfLqeg49QZt%2BAzDjnOkr3e3KxPm8AiEAkLAQI7d4djNdpMf3V%2Ftje2oOa%2BB8waWFbcilXmak2II%3D'
    m2, sig2 = base64.b64decode(urllib.parse.unquote(cookie2)).split(b'--')
    r2,s2 = util.sigdecode_der(sig2,SECP256k1.order)
    hash2 = sha256(m2).hexdigest()

    

    
    #Start the attack
    privateKeyCalculation = attack(SECP256k1.order, (r1,s1), (r2,s2), hash1, hash2)
    print('='*25)
    print ('The private key calculated is: {}'.format(privateKeyCalculation))
    print('='*25)



'''
this is ruby code i wrote to generate the cookie.
I wrote in ruby as python and ruby was having different encoding
while processing the byte array.

require 'ecdsa'
require 'digest'
require 'base64'
require 'cgi'


def sign()
    $private_key = 115177129380340245488899269840856286540049583792226156308207883406586822832781
    $str = 'admin'
    $group = ECDSA::Group::Secp256k1
    $digest = Digest::SHA256.digest($str) 
    $temp_key = $str.size 
    $signature = ECDSA.sign($group, $private_key, $digest, $temp_key)
    puts Base64.strict_encode64("admin--"+ECDSA::Format::SignatureDerString.encode($signature))
end


sign()
$cookie = 'ZHVja2llNC0tMEQCIFy98GRuXbTqo5jzZfLqeg49QZt%2BAzDjnOkr3e3KxPm8AiAejzkH0GPlpj%2BBp6IhgjMhb4KKjDaHfAH9ygoH5jsFFg%3D%3D'
puts $cookie

'''



