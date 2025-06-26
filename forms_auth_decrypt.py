import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import enum

import random
from forms_auth_ticket import FormsAuthTicket

CompatibilityMode =enum.Enum("compatibility_mode", names=["FRAMEWORK45", "Framework20SP2"])
Encryption =enum.Enum("encryption", names=[("HMACSHA512",64), ("HMACSHA256", 32)])

class FormAuthDecrypt():
    def __init__(self, decryption_key_hex:str, validation_key_hex:str, key_purpose:str = "FormsAuthentication.Ticket", 
            compatibility:CompatibilityMode =CompatibilityMode.FRAMEWORK45, encryption_type:Encryption = Encryption.HMACSHA512):
        
        self._algo = encryption_type
        self._compatibility = compatibility


        # We need to operate on byte arrays so convert hex strings to bytes
        self.decryption_key = bytes.fromhex(decryption_key_hex)
        self.validation_key = bytes.fromhex(validation_key_hex)
        self.purpose = key_purpose.encode()

        # the purpose needs to have the length in big indian order appended to it after a bitwise 0
        big_indian_decryption_key_length =(len(self.decryption_key)*8).to_bytes(length=4)
        big_indian_validation_key_length =(len(self.validation_key)*8).to_bytes(length=4)

        self.decryption_purpose_padded =  self.purpose +  b'\x00' + big_indian_decryption_key_length
        self.validation_purpose_padded =   self.purpose +  b'\x00' + big_indian_validation_key_length

        self.ticket = FormsAuthTicket.from_empty()
    
    @property
    def algo(self):
        match self._algo: 
        
            case  Encryption.HMACSHA256:
                return hashlib.sha256
            
            case Encryption.HMACSHA512:
                return hashlib.sha512
            case _:
                raise Exception("UnKnown hash")
            
    @property
    def sig_len(self):
        match self._algo: 
        
            case  Encryption.HMACSHA256:
                return 32
            
            case Encryption.HMACSHA512:
                return 64
            case _:
                raise Exception("UnKnown hash")
        


    def derive_key_from_purpose(self, key:bytes, purpose_padded:bytes ) -> bytes:
        derived_key=[]

        # to derive a key we take the purpose which could be really short and we hash it as many times as it takes 
        # with the key but each time we increment the purpose 0001purpose000lengthOfKey 0002purpose000lengthOfKey ...

        for i  in range(1, len(key)):
            byte_counter =i.to_bytes(byteorder="big", signed=False, length=4)
            # print([x for x in by])
            key_purpose_padded_cp = byte_counter + purpose_padded
            h = hmac.new(key, key_purpose_padded_cp, self.algo)

            # as we are appending our derived key we want it to be the same length as the original key so we only
            # append the key if it is less than the original or we append only part of it

            byte_copy_length = min(len(h.digest()),len(key) )
            derived_key += h.digest()[:byte_copy_length]    #this is the Derived key
            if len(key)<=len(derived_key):
                break
        return  derived_key
        
    def check_signatures(self, encrypted_cookie:str) -> bool:
        self.derived_validation_key = self.derive_key_from_purpose(self.validation_key, self.validation_purpose_padded)
        # need to work only on bytes
        encrypted_cookie_bytes =bytes.fromhex(encrypted_cookie)

        # the signature is appended to the end so the first half of the cookie is the body
        self.cookie_body = encrypted_cookie_bytes[:-self.sig_len]

        # last part of the cookie is the signature / hash
        self.cookie_hash = encrypted_cookie_bytes[-self.sig_len:]

        # if we take the derived validation key and hash the cookie body we should get the cookie signature /hash
        # basically i am saying hash the first part of the cookie should equal the last part of the cookie
        hv =hmac.HMAC(bytes(bytearray(self.derived_validation_key)), self.cookie_body, self.algo)
        return(self.cookie_hash == hv.digest())
    
    def decrypt_cookie(self, encrypted_cookie:str) -> bytes:
        # need to work only on bytes
        encrypted_cookie_bytes =bytes.fromhex(encrypted_cookie)
        
        # the initial vector is the first part of the cookie
        initial_vectors =encrypted_cookie_bytes[:16]
        derived_decryption_key = self.derive_key_from_purpose(self.decryption_key, self.decryption_purpose_padded)
        
        # if the signature matched in the cookie then we can decrypt the cookie
        if self.check_signatures(encrypted_cookie=encrypted_cookie):
            # using the initial vector and the derived key we can decrypt the cookie
            cypher = AES.new(bytes(bytearray(derived_decryption_key)), AES.MODE_CBC, initial_vectors)
            decrypted_cookie =unpad(cypher.decrypt(self.cookie_body[16:]), 16)
            self.ticket.deserialize_ticket(decrypted_cookie=decrypted_cookie)
            return self.ticket
        else:
            return None
    

    def encrypt_cookie(self, ticket:FormsAuthTicket) -> bytes:
        
        # generate initial vector by random bytes
        initial_vectors =random.randbytes(16)
        derived_decryption_key = self.derive_key_from_purpose(self.decryption_key, self.decryption_purpose_padded)
        
        # using the initial vector and the derived key we can encrypt the cookie
        cypher = AES.new(bytes(bytearray(derived_decryption_key)), AES.MODE_CBC, initial_vectors)
        encrypted_cookie =cypher.encrypt(pad(ticket.serialize_ticket(),16))
        
        # we need to sign the Cookie this is done by hashing it and appending the hash to the end of the cookie
        cookie_body = initial_vectors + encrypted_cookie
        # we hash it with the derived validation key
        self.derived_validation_key = self.derive_key_from_purpose(self.validation_key, self.validation_purpose_padded)
        hv =hmac.HMAC(bytes(bytearray(self.derived_validation_key)), cookie_body, self.algo)
        return (cookie_body + hv.digest()).hex().upper()
    

    
   
        


if __name__ =="__main__":
    import datetime as dt
    from forms_auth_ticket import FormsAuthTicket
    decryption_key_hex = "".join(random.choices(population="0123456789ABCDEF", k=48))
    validation_key_hex = "".join(random.choices(population="0123456789ABCDEF", k=128))


    fd =FormAuthDecrypt(
        decryption_key_hex= decryption_key_hex,
        validation_key_hex=validation_key_hex,
        encryption_type=Encryption.HMACSHA512, compatibility=CompatibilityMode.FRAMEWORK45
    )
    ticket = FormsAuthTicket(1,1,
                    dt.datetime.now(), dt.datetime.now()+ dt.timedelta(days=1),
                    False, "ChrisKadar", "this is my favorite user data")
    cookie = fd.encrypt_cookie(ticket=ticket)
    print(cookie)

    new_ticket =fd.decrypt_cookie(cookie)
    print(repr(new_ticket))

