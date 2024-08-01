#include "Protocol.h" // Includes the definition of the Protocol class used for encoding and decoding messages
#include <files.h> // Possibly related to file operations (exact operations depend on the actual content of this header)
#include "RSAWrapper.h" // For RSA encryption and decryption
#include <vector> // For using vector container
#include <cstdint> // For fixed-width integers
#include <boost/algorithm/hex.hpp> // For hexadecimal encoding and decoding

// Definition of file names used for various purposes
#define ME_INFO "me.info"
#define PRIVATE_KEY "priv.key"
#define TRANSFER_INFO "transfer.info"
#define STRING std::string // Defining STRING as an alias for std::string

// The Flow class manages the client's communication with the server, including signup, connection, and file transfer operations.
class Flow
{
private:
	// Sends data units (Protocol Data Units) to the server. Overloaded to handle different data types.
	inline void send_pdu(std::string data, int len)
	{
		boost::asio::write(socket, boost::asio::buffer(data, len));
	}
	// Overloaded function to send PDU for different data types
	inline void send_pdu(unsigned char* data, int len)
	{
		boost::asio::write(socket, boost::asio::buffer(data, len));
	}
	// Overloaded function to send PDU for headers
	inline void send_pdu(request_header* data, int len)
	{
		boost::asio::write(socket, boost::asio::buffer(data, len));
	}
	// Receives data units from the server.
	inline void receive_pdu(unsigned char* payload, int len)
	{
		boost::asio::read(socket,boost::asio::buffer(payload, len));
	}

	// Utility function to print data in hexadecimal format for debugging.
	inline void hexify(const unsigned char* buffer, unsigned int length)
	{
		std::ios::fmtflags f(std::cout.flags());
		std::cout << std::hex;

		for (size_t i = 0; i < length; i++)
			std::cout << std::setfill('0') << std::setw(2) << (0xFF & buffer[i]) << (((i + 1) % 16 == 0) ? "\n" : " ");
		std::cout << std::endl;
		std::cout.flags(f);
	}

public:
	// Constructor: Initializes the client, possibly reads initial data from files, and prepares the network socket.
	Flow(STRING ip_port, STRING name, STRING client_id, STRING file_path, STRING base64_private_key);	// constructor read data from files and initialize socket
	Flow(STRING ip_port, STRING name, STRING client_id, STRING file_path);	// constructor read data from files and initialize socket
	int signup();			// Handles the client's signup process.
	int connect();			// Manages the client's connection process
	int send_file();		// Handles the process of sending a file to the server.
	int file_handler();	// Manages file transmission, including retries if necessary.
	std::string getName();	// Getter for the client's name.
	void setName(std::string name);	// Setter for the client's name.
private:
	// Encodes a buffer into a hexadecimal string.
	std::string encode_hex(const uint8_t* buffer, const size_t size);

	// Decodes a hexadecimal string into a regular string.
	std::string decode_hex(const std::string& hexString);

	// Decodes a base64-encoded string into a regular string.
	std::string decode_base64(const std::string& str);

	// Encodes a regular string into a base64 string.
	std::string encode_base64(const std::string& str);

	// Writes the client's information and keys to a file.
	void write_my_info(STRING name, STRING aes, STRING privKey);
	// Reads the client's information from a file.
	void read_my_info();
	// Writes the encryption keys to a file.
	void write_keys();

	// Private member variables

	std::string name;			// Name of the user/client
	std::string client_id;		// UUID for the client
	std::string aes;			// AES encryption key
	std::string file_path;		// Path to the file being transferred
	uint32_t crc_table[256];	// Lookup table for CRC computation

	RSAPrivateWrapper rsa_key;	// RSA key wrapper
	std::string public_key;		// Public key string
	std::string private_key;	// Private key string

	int resend_count;	// Count for resending files
	Protocol proto;	// Protocol handler
	boost::asio::io_context io_context; // ASIO IO context
	tcp::socket socket;	// Socket for network communication

	// Utility function to print data in a byte-wise format. Useful for debugging.
	inline void bytify(unsigned char* payload, int len)
	{
		for (int i = 0; i < len; i++)std::cout << std::hex << (((uint8_t)payload[i]) < 0xF ? "0" : "") << (unsigned short)payload[i] << " ";
	}
};

