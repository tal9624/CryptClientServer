# Tal Mizrahi 316520782

import selectors
import socket
import protocolarchitecture as proto

# **** Global and CONSTANTS **** #
conn = None
port = 1357
dbg = True
HEADER_LENGTH = 23

class Server:

    def __init__(self,HOST,port):
        self.HOST= HOST
        self.port = port
        self.sel = selectors.DefaultSelector()
        self.client_dict = {}

    def accept(self,sock, mask):
        client_conn, addr = sock.accept()
        print('accepted', client_conn, 'from', addr)
        client_conn.setblocking(False)
        self.client_dict[client_conn] = {}
        self.sel.register(client_conn, selectors.EVENT_READ, self.read_header)

    def read_header(self, client_conn, mask):
        header = client_conn.recv(HEADER_LENGTH) # read header from network

        header_dict = proto.Codec.decode_head(header)  # decode header to a dictionary
        print("header_dict", header_dict)

        # if code == 1029 or code == 1031 flow ended, close socket
        if header_dict["CODE"] == 1029 or header_dict["CODE"] == 1031 or header_dict["CODE"] == 0:
            print(f"read received {header_dict['CODE']}, closing")
            self.sel.unregister(client_conn)
            client_conn.close()
            return

        self.client_dict[client_conn] = header_dict
        self.sel.unregister(client_conn)
        self.sel.register(client_conn, selectors.EVENT_READ, self.read_payload)

    def read_payload(self, client_conn, mask):
        header_dict = self.client_dict[client_conn]
        payload = client_conn.recv(header_dict["PAYLOAD_SIZE"])  # read body from network

        # call codec factory to return specialized Codec sub-class instance
        codec = proto.Codec.codec_factory(header_dict, payload)
        if codec == None:
            print(f"read received invalid code {header_dict['CODE']}, closing")
            self.sel.unregister(client_conn)
            client_conn.close()
            return

        response = codec.process_request()
        if response != None: client_conn.send(response)
        self.sel.unregister(client_conn)
        self.sel.register(client_conn, selectors.EVENT_READ, self.read_header)

    def run_server(self):
        # creating a server socket in order to listen in self.

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as _socket:
            _socket.bind((self.HOST, self.port))  # connect the server to the computer
            _socket.listen()
            print("server listening on", self.HOST, self.port)
            _socket.setblocking(False)
            self.sel.register(_socket, selectors.EVENT_READ, self.accept)
            while True:
                events = self.sel.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)


def main():
    #DatabaseHandler.get_instance()
    with open("port.info", "r") as file:
        try:
            temp = int(file.read())
            print(temp)
            if temp > 1000 and temp < 65536:
                port = temp
        except:
            print("warning , file 'port.info' is not good")


    HOST = "127.0.0.1"
    server = Server(HOST,port)
    server.run_server()


if __name__ == "__main__":
    main()