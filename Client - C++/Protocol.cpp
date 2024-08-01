#include "Protocol.h"


// Encodes the given file name into an unsigned char array.
// Method to encode the file name; currently only allocates memory without actual encoding.
unsigned char* Protocol::encode_file(char* name)
{
	unsigned char* p_name = new unsigned char[NAME_LENGTH]; // Allocates memory for file name.
	return p_name; // Returns pointer to the allocated memory.
}

// Decodes the CRC value from the payload. 
// Method to decode the CRC value from a given payload; currently returns an empty string, no actual decoding.
std::string Protocol::decode_crc(unsigned char* payload)
{
	std::string crc; // Placeholder for CRC value.
	return crc; // Returns an empty string.
}

// Encodes the given name into an unsigned char array.
// Method to encode a user's name; currently only allocates memory without actual encoding.
unsigned char* Protocol::encode_name(std::string name)
{
	unsigned char* p_name = new unsigned char[NAME_LENGTH]; // Allocates memory for user's name.
	return p_name; // Returns pointer to the allocated memory.
}

// Decodes the name from the payload.
// Method to decode a user's name from a given payload; currently returns an empty string, no actual decoding.
std::string Protocol::decode_name(unsigned char* payload)
{
	std::string name; // Placeholder for user's name.
	return name; // Returns an empty string.
}

// Method to encode a client's UUID into an array of bytes.
unsigned char* Protocol::encode_client_id(boost::uuids::uuid client_id)
{
	unsigned char c_client_id[ID_LENGTH]; // Buffer for client's UUID.
	std::copy(client_id.begin(), client_id.end(), c_client_id); // Copies UUID to the buffer.
	return c_client_id; // Returns the filled buffer.
}

// Method to decode a client's UUID from a given payload.
boost::uuids::uuid Protocol::decode_client_id(unsigned char* payload)
{
	boost::uuids::uuid client_id; // Placeholder for client's UUID.
	std::memcpy(&client_id, payload, ID_LENGTH); // Copies data from payload to UUID placeholder.
	return client_id; // Returns the UUID.
}
// Overloaded method to decode a client's UUID from a string to a byte array.
void Protocol::decode_client_id(std::string id, uint8_t* out)
{
	std::copy(id.begin(), id.end(), out); // Copies string ID to the byte array.
}
// Overloaded method to decode a client's UUID from a payload with an additional parameter; currently returns an empty string, no actual decoding.
std::string Protocol::decode_client_id(unsigned char* payload, int y)
{
    std::string client_id; // Placeholder for client's UUID.
    std::memcpy(&client_id, payload, ID_LENGTH); // Copies data from payload to string placeholder.
    return client_id; // Returns the client ID.
}

// Method to encode a public key into an array of bytes.
unsigned char* Protocol::encode_public_key(std::string public_key)
{
	//bytify()
	unsigned char buff[PUBLIC_KEY_LEN]; // Buffer for public key.
	memset(buff, 0, PUBLIC_KEY_LEN); // Initializes buffer with zeros.
	std::copy(public_key.begin(), public_key.end(), buff); // Copies public key to the buffer.
	return buff; // Returns the filled buffer.
}

// Method to decode AES key from a given payload and print its hexadecimal representation; allocates memory for the AES key.
char* Protocol::decode_aes(unsigned char* payload, int len)
{
	//<< std::setfill('0') << std::setw(2)
	char* p_aes = new char[len]; // Allocates memory for AES key.

	std::memcpy(p_aes, payload, len); // Copies payload to AES buffer.
	return p_aes; // Returns pointer to AES key.
}

// Method to decode the size of content from a given payload.
int Protocol::decode_content_size(unsigned char* payload)
{
	int content_size = calc_to_int(payload, 0); // Converts bytes from payload to integer.
	return content_size; // Returns the content size.
}

// Method to decode a file name from a given payload.
std::string Protocol::decode_file_name(unsigned char* payload)
{
	std::string file_name = std::string(reinterpret_cast<char*>(payload), FILE_NAME_LENGTH); // Interprets payload as string.
	return file_name; // Returns the file name.
}


// Decodes the CRC value from the payload. 
// Method to decode the CRC value from a given payload; 
unsigned int Protocol::decode_check_sum(unsigned char* payload) {
	int check_sum = calc_to_int(payload, 0); // Converts bytes from payload to integer.
	return check_sum; // Returns the checksum.
}

// Method to encode header information into a request_header structure.
request_header* Protocol::encode_header(std::string client_id, int payload_size, int code)
{
	request_header* header = new request_header(); // Allocates memory for header structure.
	memset(header->client_id, 0, ID_LENGTH); // Initializes client_id in header with zeros.
	std::copy(client_id.begin(), client_id.end(), header->client_id); // Copies client ID to the header.
	header->version = 3; // Sets protocol version.
	header->code[0] = code >> 8; // Sets higher part of the code.
	header->code[1] = code & 0x000000FF; // Sets lower part of the code.

	// Sets payload size in bytes.
	header->payload_size[0] = payload_size >> 24;
	header->payload_size[1] = payload_size >> 16;
	header->payload_size[2] = payload_size >> 8;
	header->payload_size[3] = payload_size & 0xFF;

	// Debug information: prints the header content.
	std::cout << "sending header: " << "\n";
	unsigned short s_code = ((unsigned char)header->code[0]) << 8 | ((unsigned char)header->code[1]);
	std::cout << "\tversion " << (int)header->version << std::endl;
	std::cout << "\tcode " << std::dec << s_code << std::endl;
	unsigned int size = calc_to_int((unsigned char*)header->payload_size, 0);
	std::cout << "\tlen " << size << std::endl;
	std::cout << "\tclient_id ";
	bytify((unsigned char*)header->client_id, client_id.length());
	std::cout << std::endl;

	return header; // Returns pointer to the filled header structure.
}

// Method to decode header information from a socket response into a response_header structure.
response_header Protocol::decode_header(tcp::socket& s)
{
	unsigned char reply[RESPONSE_HEADER]; // Buffer for socket reply.
	response_header rs; // Placeholder for response header.
	size_t reply_length = boost::asio::read(s, boost::asio::buffer(reply, RESPONSE_HEADER)); // Reads reply from socket.

	// Debug information: prints the received header content.
	std::cout << "received header: " << "\n";
	std::cout << "\tversion " << (int)reply[0] << std::endl;
	rs.version = reply[0]; // Sets version in response structure.
	rs.code = ((unsigned char)reply[1]) << 8 | ((unsigned char)reply[2]); // Sets code in response structure.
	std::cout << "\tcode " << std::dec << rs.code << std::endl;
	rs.payload_size = calc_to_int(reply, 3); // Sets payload size in response structure.
	std::cout << "\tlen " << rs.payload_size << std::endl;

	return rs; // Returns the filled response header.
}