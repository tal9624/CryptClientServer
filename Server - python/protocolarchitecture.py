import binascii
from clientsdatabase import DatabaseHandler
import uuid
import cryptography as crypt
import os

HEADER_RESPONSE_LENGTH = 7
NAME_LENGTH = 255
PKEY_LENGTH = 160
CLIENT_ID_LENGTH = 16
CONTENT_SIZE = 4
FILE_NAME = 255
BODY_2103 = 279
FILE_PATH = "./data/"

dbg = True

class Connection:
    def __init__(self, client_id):
        self.client_id = client_id
        self.file_fail_count = 0
        self.file_name = ""

conn_dict = {}  # key: client_id, value:Connection instance
def log(*messages):
    if dbg:
        print(messages)

class Codec:
    def __init__(self, header_dict, payload):
        self.header_dict = header_dict
        self.payload = payload
        self.db = DatabaseHandler.get_instance()

    def decode_head(data):
        uuid_int = int.from_bytes(data[:16], 'big')

        header_dict = {
            "CLIENT_ID": uuid.UUID(int=uuid_int),
            "VERSION": int.from_bytes(data[16:17], 'big'),
            "CODE": int.from_bytes(data[17:19], 'big'),
            "PAYLOAD_SIZE": int.from_bytes(data[19:], 'big')}
        return header_dict

    def encode_head(self, code, payload, payload_size):
        ''' encode the header and its payload '''
        d_size = payload_size.to_bytes(4, 'big')
        data = bytearray(HEADER_RESPONSE_LENGTH + payload_size)
        data[0] = 3  # version
        data[1] = (code >> 8)  ## high bits of code
        data[2] = (code & 0x000000FF)  ### low bits of code
        data[3] = d_size[0]
        data[4] = d_size[1]
        data[5] = d_size[2]
        data[6] = d_size[3]
        
        for i in range(payload_size):
            data[i + HEADER_RESPONSE_LENGTH] = payload[i]
        return data

    def codec_factory(header_dict, payload):
        codec_dict = {1025: Registration, 1026: ExchangeKeys,
                      1027: Reconnection, 1028: GetFile, 1029: FileCRCResponse,
                      1030: ResendFile, 1031: CancelFile}
        try:
            codec = codec_dict[header_dict["CODE"]](header_dict, payload)
            print("found codec for", header_dict["CODE"])
            return codec
        except:
            return None

    def process_request(self):
        pass

    def get_client_details(self):
        clients_result = self.db.get_client_by_id(str(self.header_dict["CLIENT_ID"].int))
        if clients_result == None: return None
        return clients_result[0]

    def encode_client_id(self):
        bytes_client_id = self.header_dict["CLIENT_ID"].int.to_bytes(16, 'big')
        return bytes_client_id


class Registration(Codec):
    def __init__(self, header_dict, payload):
        super().__init__(header_dict, payload)

    def process_request(self):
        name = self.payload.decode().rstrip('\x00')
        print("handle_1025 =>", name)
        if len(name) == 0:
            print("1025 error: name len == 0")
            return self.encode_head(2101, bytearray(0), 0)
        response = self.create_client(name)
        if response == False:
            print("1025 error: response is false")
            return self.encode_head(2101, bytearray(0), 0)
        else:
            client_connection = Connection(response)
            conn_dict[response] = client_connection
            bytel = response.to_bytes(16, 'big')
            return self.encode_head(2100, bytel, 16)

    def create_client(self, name):
        client_uuid = uuid.uuid4()
        log('generated clientid', client_uuid)
        client_id = client_uuid.int

        res = self.db.get_client_by_name(name)
        if len(res) > 0:
            return False
        log("inserting", client_id)
        self.db.insert_client(str(client_id), name, '', '', '')
        return client_id

    def __str__(self) -> str:
        return "1025"


class ExchangeKeys(Codec):
    def __init__(self, header_dict, payload):
        super().__init__(header_dict, payload)

    def process_request(self):
        log("process_request 1026 =>")
        name = self.payload[:255].decode().rstrip('\x00')
        public_key = self.payload[NAME_LENGTH:NAME_LENGTH + PKEY_LENGTH]
        aes_key = crypt.create_AESKey()
        encrypted_aes_key = crypt.encrypt_aes_with_rsa(aes_key, public_key)
        self.db.update_public_key(name, public_key, aes_key)

        client_data = self.db.get_client_by_id(str(self.header_dict["CLIENT_ID"].int))
        # send encrypted_aes_key to client
        aes_len = len(encrypted_aes_key)

        #add to cache
        client_connection = Connection(self.header_dict["CLIENT_ID"].hex)
        conn_dict[self.header_dict["CLIENT_ID"].hex] = client_connection

        response = bytearray(CLIENT_ID_LENGTH + aes_len)

        bclient_id = self.encode_client_id()
        for i in range(len(bclient_id)):
            response[i] = bclient_id[i]

        for i in range(aes_len):
            response[i + CLIENT_ID_LENGTH] = encrypted_aes_key[i]

        return self.encode_head(2102, response, CLIENT_ID_LENGTH + aes_len)


class Reconnection(Codec):
    def __init__(self, header_dict, payload):
        super().__init__(header_dict, payload)

    def process_request(self):
        name = self.payload.decode().rstrip('\x00')
        print("process_request 1027 =>", name)
        if len(name) == 0 or self.header_dict["CLIENT_ID"] == None:
            return self.encode_head(2106, self.header_dict["CLIENT_ID"].encode(), len(self.header_dict["CLIENT_ID"]))

        clients_result = self.db.get_client_by_id(str(self.header_dict["CLIENT_ID"].int))
        client_data = clients_result[0]
        print(self.header_dict["CLIENT_ID"].hex)

        # if we did not find clientId or public key send 2106 with clientId (empty if does not exist
        if client_data == False:
            return self.encode_head(2106, self.header_dict["CLIENT_ID"].encode(), len(self.header_dict["CLIENT_ID"]))

        encrypted_aes_key = crypt.encrypt_aes_with_rsa(client_data["AES"], client_data["PublicKey"])
        if self.header_dict["CLIENT_ID"].hex not in conn_dict:
            client_connection = Connection(self.header_dict["CLIENT_ID"].hex)
            conn_dict[self.header_dict["CLIENT_ID"].hex] = client_connection
        
        aes_len = len(encrypted_aes_key)
        response = bytearray(CLIENT_ID_LENGTH + aes_len)
        bclient_id = self.encode_client_id()
        for i in range(len(bclient_id)):
            response[i] = bclient_id[i]
        for i in range(aes_len):
            response[i + CLIENT_ID_LENGTH] = encrypted_aes_key[i]
        return self.encode_head(2105, response, CLIENT_ID_LENGTH + aes_len)


class GetFile(Codec):
    def __init__(self, header_dict, payload):
        super().__init__(header_dict, payload)

    def process_request(self):
        ## receive the file and Decrypt
        client_connection = conn_dict[self.header_dict["CLIENT_ID"].hex]
        if client_connection.file_fail_count >= 4:
            print("fail count is ", client_connection.file_fail_count)
            del conn_dict[self.header_dict["CLIENT_ID"].hex]
            # send 2107
            return self.encode_head(2107, bytearray(0), 0)
        client_data = self.get_client_details()

        #read file name
        file_name = self.payload[CONTENT_SIZE:FILE_NAME].decode().rstrip('\x00')
        #decrypt file data
        decrypted_data = crypt.decrypt_file_with_public_key(client_data["AES"], self.payload[CONTENT_SIZE+FILE_NAME:])
        # calc crc
        crc = crc32(decrypted_data)
        
        file_path = FILE_PATH + file_name

        # save file to file system
        with open(file_path, "wb") as file:
            file.write(decrypted_data)
        content_size = 0

        # instance of connection representing client data
        client_connection = conn_dict[self.header_dict["CLIENT_ID"].hex]
        client_connection.file_name = file_path

        response = bytearray(BODY_2103)
        bclient_id = self.encode_client_id()
        for i in range(len(bclient_id)):
            response[i] = bclient_id[i]

        response[CLIENT_ID_LENGTH] = (content_size & 0xFF000000)
        response[CLIENT_ID_LENGTH + 1] = (content_size & 0x00FF0000)
        response[CLIENT_ID_LENGTH + 2] = (content_size & 0x0000FF00)
        response[CLIENT_ID_LENGTH + 3] = (content_size & 0x000000FF)
        b_file_name = file_name.encode()
        for i in range(len(b_file_name)):  ## send the file name
            response[i + CLIENT_ID_LENGTH + CONTENT_SIZE] = b_file_name[i]
        #   Send the CRC to the client
        b_crc = crc.to_bytes(4, 'big')
        response[CLIENT_ID_LENGTH + CONTENT_SIZE + FILE_NAME] = b_crc[0]
        response[CLIENT_ID_LENGTH + CONTENT_SIZE + FILE_NAME + 1] = b_crc[1]
        response[CLIENT_ID_LENGTH + CONTENT_SIZE + FILE_NAME + 2] = b_crc[2]
        response[CLIENT_ID_LENGTH + CONTENT_SIZE + FILE_NAME + 3] = b_crc[3]

        return self.encode_head(2103, response, len(response))


class FileCRCResponse(Codec):
    def __init__(self, header_dict, payload):
        super().__init__(header_dict, payload)

    def process_request(self):
        file_name = self.payload[:FILE_NAME].decode().rstrip('\x00')
        # insert file into database
        self.db.insert_files(id, file_name, FILE_PATH, 1)
        response = bytearray(CLIENT_ID_LENGTH)
        for i in range(len(self.header_dict["CLIENT_ID"])):
            response[i] = self.header_dict["CLIENT_ID"][i]
        return self.encode_head(2104, response, len(response))


class ResendFile(Codec):
    def __init__(self, header_dict, payload):
        super().__init__(header_dict, payload)

    def process_request(self):
        # increment retries by 1
        client_connection = conn_dict[
            self.header_dict["CLIENT_ID"].hex]  # instance of connection representing client data
        client_connection.file_fail_count += 1
        print("deleting file ", client_connection.file_name)
        # os.remove(FILE_PATH + client_connection.file_name)
        os.remove(client_connection.file_name)
        # insert file into database
        id = self.header_dict["CLIENT_ID"]
        self.db.insert_files(id, client_connection.file_name, FILE_PATH, 0)


class CancelFile(Codec):
    def __init__(self, header_dict, payload):
        super().__init__(header_dict, payload)

    def process_request(self):
        client_connection = conn_dict[
            self.header_dict["CLIENT_ID"].hex]  # instance of connection representing client data
        os.remove(FILE_PATH + client_connection.file_name)
        del conn_dict[self.header_dict["CLIENT_ID"].hex]
        # insert file into database
        self.db.insert_files(id, client_connection.file_name, FILE_PATH, 0)
        conn_dict.pop(self.header_dict["CLIENT_ID"].hex)  # end session



# CRC CALCULATION #
"""
This module implements the cksum command found in most UNIXes in pure
python.

The constants and routine are cribbed from the POSIX man page
"""
import sys

crctab = [ 0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9, 0x130476dc,
        0x17c56b6b, 0x1a864db2, 0x1e475005, 0x2608edb8, 0x22c9f00f,
        0x2f8ad6d6, 0x2b4bcb61, 0x350c9b64, 0x31cd86d3, 0x3c8ea00a,
        0x384fbdbd, 0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
        0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75, 0x6a1936c8,
        0x6ed82b7f, 0x639b0da6, 0x675a1011, 0x791d4014, 0x7ddc5da3,
        0x709f7b7a, 0x745e66cd, 0x9823b6e0, 0x9ce2ab57, 0x91a18d8e,
        0x95609039, 0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
        0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81, 0xad2f2d84,
        0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d, 0xd4326d90, 0xd0f37027,
        0xddb056fe, 0xd9714b49, 0xc7361b4c, 0xc3f706fb, 0xceb42022,
        0xca753d95, 0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
        0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d, 0x34867077,
        0x30476dc0, 0x3d044b19, 0x39c556ae, 0x278206ab, 0x23431b1c,
        0x2e003dc5, 0x2ac12072, 0x128e9dcf, 0x164f8078, 0x1b0ca6a1,
        0x1fcdbb16, 0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
        0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde, 0x6b93dddb,
        0x6f52c06c, 0x6211e6b5, 0x66d0fb02, 0x5e9f46bf, 0x5a5e5b08,
        0x571d7dd1, 0x53dc6066, 0x4d9b3063, 0x495a2dd4, 0x44190b0d,
        0x40d816ba, 0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
        0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692, 0x8aad2b2f,
        0x8e6c3698, 0x832f1041, 0x87ee0df6, 0x99a95df3, 0x9d684044,
        0x902b669d, 0x94ea7b2a, 0xe0b41de7, 0xe4750050, 0xe9362689,
        0xedf73b3e, 0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
        0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686, 0xd5b88683,
        0xd1799b34, 0xdc3abded, 0xd8fba05a, 0x690ce0ee, 0x6dcdfd59,
        0x608edb80, 0x644fc637, 0x7a089632, 0x7ec98b85, 0x738aad5c,
        0x774bb0eb, 0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
        0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53, 0x251d3b9e,
        0x21dc2629, 0x2c9f00f0, 0x285e1d47, 0x36194d42, 0x32d850f5,
        0x3f9b762c, 0x3b5a6b9b, 0x0315d626, 0x07d4cb91, 0x0a97ed48,
        0x0e56f0ff, 0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
        0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7, 0xe22b20d2,
        0xe6ea3d65, 0xeba91bbc, 0xef68060b, 0xd727bbb6, 0xd3e6a601,
        0xdea580d8, 0xda649d6f, 0xc423cd6a, 0xc0e2d0dd, 0xcda1f604,
        0xc960ebb3, 0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
        0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b, 0x9b3660c6,
        0x9ff77d71, 0x92b45ba8, 0x9675461f, 0x8832161a, 0x8cf30bad,
        0x81b02d74, 0x857130c3, 0x5d8a9099, 0x594b8d2e, 0x5408abf7,
        0x50c9b640, 0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
        0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8, 0x68860bfd,
        0x6c47164a, 0x61043093, 0x65c52d24, 0x119b4be9, 0x155a565e,
        0x18197087, 0x1cd86d30, 0x029f3d35, 0x065e2082, 0x0b1d065b,
        0x0fdc1bec, 0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
        0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654, 0xc5a92679,
        0xc1683bce, 0xcc2b1d17, 0xc8ea00a0, 0xd6ad50a5, 0xd26c4d12,
        0xdf2f6bcb, 0xdbee767c, 0xe3a1cbc1, 0xe760d676, 0xea23f0af,
        0xeee2ed18, 0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
        0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0, 0x9abc8bd5,
        0x9e7d9662, 0x933eb0bb, 0x97ffad0c, 0xafb010b1, 0xab710d06,
        0xa6322bdf, 0xa2f33668, 0xbcb4666d, 0xb8757bda, 0xb5365d03,
        0xb1f740b4 ]

UNSIGNED = lambda n: n & 0xffffffff

def crc32(b):
    n = len(b)
    i = c = s = 0
    for ch in b:
        tabidx = (s>>24)^ch
        s = UNSIGNED((s << 8)) ^ crctab[tabidx]

    while n:
        c = n & 0o377
        n = n >> 8
        s = UNSIGNED(s << 8) ^ crctab[(s >> 24) ^ c]
    return UNSIGNED(~s)