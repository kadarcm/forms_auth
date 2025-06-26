import datetime as dt
from typing import Tuple

class FormsAuthTicket():
        
    def __init__(self,version, ticket_version, issued, expiration, persistence, name, user_data):
        self.version=version
        self.ticket_version=ticket_version
        self.issued=issued
        self.expiration =expiration
        self.persistence =persistence
        self.name = name
        self.user_data =user_data
    
    @classmethod
    def from_empty(cls):
        return cls(version="", ticket_version= "", issued="", expiration="", persistence="", name="", user_data="")
        
    def deserialize_ticket(self, decrypted_cookie:bytes) -> dict: 

        # microsoft has taken the bits of the data and rammed them all together we need to parse them back out
        # the first 0-19 bits are rigidly spoke for after the bits are strings of varying lengths that are defined by the first bit
        # of the string section
    
        self.version = decrypted_cookie[0]
        self.ticket_version  = decrypted_cookie[1]
        self.issued =self.convert_int64_to_date(decrypted_cookie[2:10])
        self.expiration = self.convert_int64_to_date(decrypted_cookie[11:19])
        self.persistence = decrypted_cookie[19]

        # we are now parsing a variable length string so lets just forget the first part of the ticket
        remaining_cookie = decrypted_cookie[20:]
        self.name, str_end = self.convert_string_data(remaining_cookie)
        remaining_cookie =remaining_cookie[str_end:]
        self.user_data, str_end = self.convert_string_data(remaining_cookie)
        
    
    def __repr__(self):
        return str({
            "version":self.version,
            "ticket_version":self.ticket_version,
            "name":self.name,
            "issued":self.issued,
            "expires":self.expiration,
            "user_data":self.user_data            
            })
        
    
    def __str__(self):
        return(f"forms ticket named {self.name}")

    
    def serialize_ticket(self) -> bytes: 
        
        return_bytes =b""
        return_bytes += int(self.version).to_bytes()
        return_bytes += int(self.ticket_version).to_bytes()
        return_bytes += self.convert_date_to_bytes(self.issued)
        return_bytes += b"\x00" + self.convert_date_to_bytes(self.expiration)
        return_bytes += bool(self.persistence).to_bytes()
        return_bytes += self.convert_string_to_bytes(self.name)
        return_bytes += self.convert_string_to_bytes(self.user_data)
        return return_bytes
    
    @staticmethod
    def convert_int64_to_date(int_date:int)-> dt.datetime:
        date_int = int.from_bytes(int_date , byteorder="little", signed=True)
        date_sec = date_int/10_000_000
        utc_datetime = dt.datetime(1,1,1, tzinfo=dt.timezone.utc) +dt.timedelta(seconds=date_sec)

        return utc_datetime
    
    @staticmethod
    def convert_date_to_bytes(date:dt.datetime)-> bytes:
        date_int = int(date.timestamp()*10_000_000)
        return date_int.to_bytes(byteorder="little", signed=True, length=8)
    
    @staticmethod
    def convert_string_data(remaining_cookie:bytes) -> Tuple[str, int]:
        # the first bit is the length of the characters in the string
        bytes_to_read = remaining_cookie[0]*2
        # we start reading the sting at index 1 or the second bit
        str_start =1
        str_end = bytes_to_read +str_start
        # remove all the empties
        data =(remaining_cookie[str_start:str_end ]).replace(b"\x00",b"")

        return str(data) , str_end
    
    @staticmethod
    def convert_string_to_bytes(data:str) -> bytes:
        padded_data ="\0".join(data) + "\0"
        bytes_to_write =len(data).to_bytes() + padded_data.encode()
        return bytes_to_write

if __name__=="__main__":
    my_ticket = FormsAuthTicket(1,1,
                    dt.datetime.now(), dt.datetime.now()+ dt.timedelta(days=1),
                    False, "ChrisKadar", "this is my favorite user data")
    print(my_ticket)
    print(repr(my_ticket))
    my_ticket_serialized = my_ticket.serialize_ticket()
    print(my_ticket_serialized)
    new_ticket = FormsAuthTicket.from_empty()
    print(new_ticket)
    print(repr(new_ticket))
    new_ticket.deserialize_ticket(my_ticket_serialized)
    print(new_ticket)
    print(repr(new_ticket))
    

