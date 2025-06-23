import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import datetime as dt
import enum
from typing import Tuple

CompatibilityMode =enum.Enum("compatibility_mode", names=["FRAMWORK45", "Framework20SP2"])
Encryption =enum.Enum("encryption", names=[("HMACSHA512",64), ("HMACSHA256", 32)])

class FormAuthDecrypt():
    def __init__(self, description_key_hex:str, validation_key_hex:str, key_purpose:str = "FormsAuthentication.Ticket", 
            compatibility:CompatibilityMode =CompatibilityMode.FRAMWORK45, encryption_type:Encryption = Encryption.HMACSHA512):
        
        self._algo = encryption_type
        self._compatibility = compatibility


        # We need to operate on byte arrays so convert hex strings to bytes
        self.decryption_key = bytes.fromhex(description_key_hex)
        self.validation_key = bytes.fromhex(validation_key_hex)
        self.purpose = key_purpose.encode()

        # the purpose needs to have the length in big indian order appended to it after a bytewise 0
        big_indian_decryption_key_length =(len(self.decryption_key)*8).to_bytes(length=4)
        big_indian_validationn_key_length =(len(self.validation_key)*8).to_bytes(length=4)

        self.decryption_purpose_padded =  self.purpose +  b'\x00' + big_indian_decryption_key_length
        self.validation_purpose_padded =   self.purpose +  b'\x00' + big_indian_validationn_key_length
    
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

        # to dervive a key we take the purpose which could be really short and we hash it as many times as it takes 
        # with the key but each time we increment the purpose 0001purpose000lenghtOfKey 0002purpose000lenghtOfKey ...

        for i  in range(1, len(key)):
            byte_counter =i.to_bytes(byteorder="big", signed=False, length=4)
            # print([x for x in by])
            key_purpose_padded_cp = byte_counter + purpose_padded
            h = hmac.new(key, key_purpose_padded_cp, self.algo)

            # as we are appending our derived key we want it to be the same length as the orgional key so we only
            # append the key if it is less than the orgonale or we append only part of it

            byte_copy_length = min(len(h.digest()),len(key) )
            derived_key += h.digest()[:byte_copy_length]    #this is the Derived key
            if len(key)<=len(derived_key):
                break
        return  derived_key
        
    def check_signatures(self, encrypted_cookie:bytes) -> bool:
        self.derived_validation_key = self.derive_key_from_purpose(self.validation_key, self.validation_purpose_padded)
        # need to work only on bytes
        encrypted_cookie_bytes =bytes.fromhex(encrypted_cookie)

        # the signature is appended to the end so the first half of the cookie is the body
        self.cookie_body = encrypted_cookie_bytes[:-self.sig_len]

        # last part of the cookie is the signatuer / hash
        self.cookie_hash = encrypted_cookie_bytes[-self.sig_len:]

        # if we take the dervived validation key and hash the cookie body we should get the cookie signature /hash
        # basically i am sayin hash the first part of the cookie should equal the last part of the cookie
        hv =hmac.HMAC(bytes(bytearray(self.derived_validation_key)), self.cookie_body, self.algo)
        return(self.cookie_hash == hv.digest())
    
    def decrypt_cookie(self, encrypted_cookie:bytes) -> bytes:
        # if the signature matched in the cookie then we can decrypt the cookie
        encrypted_cookie_bytes =bytes.fromhex(encrypted_cookie)
        
        # the inital vector is the first part of the cookie
        initial_vectors =encrypted_cookie_bytes[:16]
        derived_decryption_key = self.derive_key_from_purpose(self.decryption_key, self.decryption_purpose_padded)
        
        # using the initial vector and the derived key we can decrypt the cookie
        cypher = AES.new(bytes(bytearray(derived_decryption_key)), AES.MODE_CBC, initial_vectors)
        decrypted_cookie =unpad(cypher.decrypt(self.cookie_body[16:]), 16)
        return decrypted_cookie
    
    def deserialize_ticket(self, decrypted_cookie:bytes) -> dict:

        # microsoft has taken the bits of the data and rammed them all together we need to parse them back out
        # the first 0-19 bits are rigidly spoke for after the bits are strings of varying lengths that are defined by the first bit
        # of the string section
        ticket ={}
        ticket["version"] = decrypted_cookie[0]
        ticket["ticket_version"] = decrypted_cookie[1]
        ticket["issued"]=self.convert_int64_to_date(decrypted_cookie[2:10])
        ticket["expiration"]= self.convert_int64_to_date(decrypted_cookie[11:19])
        ticket["persistence"]= decrypted_cookie[19]

        # we are now parsing a variable length string so lets just forget the first part of the ticket
        remaining_cookie = decrypted_cookie[20:]
        ticket["name"], str_end = self.convert_string_data(remaining_cookie)
        remaining_cookie =remaining_cookie[str_end:]
        ticket["user_data"], str_end = self.convert_string_data(remaining_cookie)
        return ticket
        
    @staticmethod
    def convert_int64_to_date(int_date:int)-> dt.datetime:
        date_int = int.from_bytes(int_date , byteorder="little", signed=True)
        date_sec = date_int/10_000_000
        utc_datetime = dt.datetime(1,1,1, tzinfo=dt.timezone.utc) +dt.timedelta(seconds=date_sec)

        return utc_datetime
    
    @staticmethod
    def convert_string_data(remaining_cookie:bytes) -> Tuple[str, int]:
        # the first bit is the lenght of the charators in the string
        bytes_to_read = remaining_cookie[0]*2
        # we start reading the sting at index 1 or the second bit
        str_start =1
        str_end = bytes_to_read +str_start
        # remove all the emptys
        data =(remaining_cookie[str_start:str_end ]).replace(b"\x00",b"")

        return data , str_end 

if __name__ =="__main__":
    fd =FormAuthDecrypt(
        description_key_hex="",
        validation_key_hex="",
        encryption_type=Encryption.HMACSHA512, compatibility=CompatibilityMode.FRAMWORK45
    )
    cookie =''
    if (fd.check_signatures(encrypted_cookie=cookie)):
        decrypted_cookie =fd.decrypt_cookie(encrypted_cookie= cookie)
        ticket =fd.deserialize_ticket(decrypted_cookie=decrypted_cookie)
        print(ticket)