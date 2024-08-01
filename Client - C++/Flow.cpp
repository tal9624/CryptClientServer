#include "Flow.h" // Includes the definition of the Flow class, which manages client communication and file transfer.
#include "AESWrapper.h" // For AES encryption and decryption functionalities.

// Constructor for the Flow class, initializes various member variables and establishes a network connection.
Flow::Flow(STRING ip_port, STRING name,STRING client_id, STRING file_path, STRING base64_private_key)
	:resend_count(0),name(name), client_id(client_id),file_path(file_path), 
	io_context(),socket(io_context),rsa_key(decode_base64(base64_private_key))
{
	// Parse server IP and port from the provided string.
	size_t delimiterPos = ip_port.find(":");
	STRING server_ip = ip_port.substr(0, delimiterPos);
	STRING server_port = ip_port.substr(delimiterPos + 1);
	// Establish a connection to the server.
	tcp::resolver resolver(io_context);
	boost::asio::connect(socket, resolver.resolve(server_ip, server_port));

	// Retrieve public and private keys from the RSA key object.
	public_key = rsa_key.getPublicKey();
	private_key = rsa_key.getPrivateKey();
}

Flow::Flow(STRING ip_port, STRING name, STRING client_id, STRING file_path)
	:resend_count(0), name(name), client_id(client_id), file_path(file_path),
	io_context(), socket(io_context)
{
	// Parse server IP and port from the provided string.
	size_t delimiterPos = ip_port.find(":");
	STRING server_ip = ip_port.substr(0, delimiterPos);
	STRING server_port = ip_port.substr(delimiterPos + 1);
	// Establish a connection to the server.
	tcp::resolver resolver(io_context);
	boost::asio::connect(socket, resolver.resolve(server_ip, server_port));

	// Retrieve public and private keys from the RSA key object.
	public_key = rsa_key.getPublicKey();
	private_key = rsa_key.getPrivateKey();
}


// Function to handle the signup process by sending appropriate requests and handling responses.
int Flow::signup()
{
	// Prepare and send a 1025 request to the server.
	request_header* request_1025 = proto.encode_header("", NAME_LENGTH, REQUEST_CODE_1025);

	send_pdu(request_1025, sizeof(request_header)); // Send the 1025 request header.
	send_pdu(name, NAME_LENGTH); // Send the actual payload (the client's name).
	std::cout << "sent 1025 name=" << name << std::endl;

	// Receive and handle the response from the server.
	response_header res_1025 = proto.decode_header(socket); // Read the response header from the server.
	if (res_1025.code == RESPONSE_CODE_2101 || res_1025.code != RESPONSE_CODE_2100) // Check if the server sent a 2101 (error) or anything other than a 2100 (OK) response.
	{
		return res_1025.code; // If an unexpected response code is received, return it for further handling.
	}
	// If the response is successful, read the client ID from the response.
	unsigned char* payload_res_1025 = new unsigned char[res_1025.payload_size]; // Allocate memory for the response payload.
	receive_pdu(payload_res_1025, res_1025.payload_size); // Read the response payload from the server.

	// Decode the client ID and print it.
	client_id = encode_hex(payload_res_1025, ID_LENGTH); // Convert the client ID from binary to hexadecimal form for easier handling and printing.
	std::cout << "client_id is: " << client_id << std::endl;

	delete[] payload_res_1025; // Free the memory allocated for the response payload.
	delete request_1025; // Free the memory allocated for the 1025 request header.

	write_my_info(name, client_id, encode_base64(private_key)); // Save the client's information (name, client ID, and private key) to a local file for persistence.

	// ***** send 1026 ***** //
	// Prepare and send a 1026 request to the server.
	int payload_size = PUBLIC_KEY_LEN + NAME_LENGTH; // The size of the 1026 request payload is the sum of the lengths of the public key and the client's name.
	std::string str_client_id; // Declare a string to hold the client ID in hexadecimal form.
	request_header* req_1026 = proto.encode_header(decode_hex(client_id), payload_size, REQUEST_CODE_1026); // Create a 1026 request header with the client ID and the calculated payload size.
	send_pdu(req_1026, sizeof(request_header)); // Send the 1026 request header.



	unsigned char* pkey = new unsigned char[PUBLIC_KEY_LEN]; // Allocate memory for the public key.
	memset(pkey, 0, PUBLIC_KEY_LEN); // Initialize the public key memory with zeros.
	std::memcpy(pkey, rsa_key.getPublicKey((char*)pkey, PUBLIC_KEY_LEN), PUBLIC_KEY_LEN); // Copy the actual public key into the allocated memory.
	bytify(pkey, PUBLIC_KEY_LEN); // Convert the public key from binary to hexadecimal form for easier handling and printing.
	unsigned char payload__req_1026[PUBLIC_KEY_LEN + NAME_LENGTH]; // Declare a buffer for the 1026 request payload.
	memset(payload__req_1026, 0, payload_size); // Initialize the payload buffer with zeros.
	std::copy(name.begin(), name.end(), payload__req_1026); // Copy the client's name into the beginning of the payload buffer.


	std::memcpy(&payload__req_1026[NAME_LENGTH], pkey, PUBLIC_KEY_LEN); // Copy the public key into the payload buffer, after the client's name.
	send_pdu(payload__req_1026, payload_size); // Send the 1026 request payload.
	std::cout << "sent 1026" << std::endl;

		// analyze code 2102 or 2107 
	delete[]pkey;  // Free the memory allocated for the public key.

	std::cout << "reading 1026 response" << std::endl;
	response_header res_1026 = proto.decode_header(socket);	// Read the response header from the server.

	// code verification
	if (res_1026.code == RESPONSE_CODE_2107 || res_1026.code != RESPONSE_CODE_2102) { // Check if the server sent a 2107 (error) or anything other than a 2102 (OK) response.
		std::cout << "error occured" << std::endl;
		throw std::invalid_argument("request 1026 recieved invalid code " + res_1026.code); // If an unexpected response code is received, throw an exception.
	}

	unsigned char* payload_res_1026 = new unsigned char[res_1026.payload_size]; // Allocate memory for the response payload.
	int payload_1026_size = res_1026.payload_size; // Store the size of the response payload for easier reference.
	receive_pdu(payload_res_1026, res_1026.payload_size); // Read the response payload from the server.


	// decode client_id
	client_id = encode_hex(payload_res_1026, ID_LENGTH); // Convert the client ID from binary to hexadecimal form for easier handling and printing.
	uint8_t cid[ID_LENGTH]; // Declare a buffer for the client ID in binary form.
	std::memcpy(cid, payload_res_1026, ID_LENGTH); // Copy the client ID from the response payload into the buffer.
	std::cout << "client_id is: " << client_id << std::endl;
	std::cout << "cid is: " << std::endl;
	std::cout << "encoded is: " << decode_hex(client_id) << std::endl;
	bytify(cid, ID_LENGTH); // Convert the client ID from binary to hexadecimal form for easier handling and printing, and print it.

	int aes_len = res_1026.payload_size - ID_LENGTH; // Calculate the length of the AES key in the response payload.
	char* enc_aes = proto.decode_aes(&payload_res_1026[ID_LENGTH], aes_len); // Decrypt the AES key from the response payload.

	aes = rsa_key.decrypt((char*)enc_aes, aes_len); // Decrypt the AES key using the client's private RSA key.

	delete[] payload_res_1026; // Free the memory allocated for the response payload.
	payload_res_1026 = nullptr; // Ensure the pointer is set to nullptr to avoid potential use-after-free errors.
	delete[] enc_aes; // Free the memory allocated for the decrypted AES key.
	enc_aes = nullptr; // Ensure the pointer is set to nullptr to avoid potential use-after-free errors.
	return res_1026.code; // Return the response code for further handling.
}

// Function to handle the connection process by sending appropriate requests and handling responses.
int Flow::connect()
{
	std::cout << "sending 1027" << client_id << std::endl;
	request_header* request_1027 = proto.encode_header(decode_hex(client_id), NAME_LENGTH, REQUEST_CODE_1027); // Create a 1027 request header with the client ID and a payload size equal to NAME_LENGTH.

	send_pdu(request_1027, sizeof(request_header));	// Send the 1027 request header.
	send_pdu(name, NAME_LENGTH); // Send the actual payload (the client's name).
	std::cout << "sent 1027" << std::endl;

	// Reading the response for the 1027 request.
	std::cout << "reading 1027 response" << std::endl;
	response_header rs = proto.decode_header(socket); // Decode the response header from the server.

	// Verify the response code. The expected response code is 2105. If it's 2107 or anything other than 2105, an error has occurred.
	if (rs.code == RESPONSE_CODE_2107 || rs.code != RESPONSE_CODE_2105) {
		std::cout << "error occurred" << std::endl;
		return rs.code; // Return the error code.
	}
	// If the response code is 2105, process the payload.
	unsigned char* payload_res_1027 = new unsigned char[rs.payload_size]; // Allocate memory for the payload.
	receive_pdu(payload_res_1027, rs.payload_size); // Receive the payload from the server.


	// Decode the client ID from the payload.
	client_id = encode_hex(payload_res_1027, ID_LENGTH); // The client ID is expected to be the first part of the payload.
	std::cout << "client_id is: " << client_id << std::endl;


	// TODO: Implement a check to verify that the received client ID matches the expected client ID.

	// Decode the AES key sent by the server. It's located after the client ID in the payload.
	int aes_len = rs.payload_size - ID_LENGTH; // Calculate the length of the AES key.
	char* enc_aes = proto.decode_aes(&payload_res_1027[ID_LENGTH], aes_len); // Decrypt the AES key.

	// Decrypt the AES key using the RSA private key.
	aes = rsa_key.decrypt((char*)enc_aes, aes_len); // The decrypted AES key is stored for future use.

	// Cleanup and function exit.
	std::cout << "end connect" << std::endl;
	delete[] payload_res_1027; // Free the memory allocated for the payload.
	delete request_1027; // Free the memory allocated for the request header.
	return rs.code; // Return the response code (should be 2105 if everything went fine).

}
// Function to handle file transfers with error checking and retries.
int Flow::file_handler()
{
	std::cout << "start file_handler" << std::endl;
	// The file transfer will be attempted multiple times (up to FORTH_TRY times) in case of errors.
	while (resend_count < FORTH_TRY)
	{
		std::cout << "resend_count is " << resend_count << std::endl;
		unsigned int local_crc = send_file(); // Send the file and calculate its CRC checksum.

		// If the file is not found or another error occurred in send_file(), terminate the file_handler.
		if (local_crc == -1) {
			return 0;
		}

		// Receive and process the server's response after sending the file.
		response_header rs = proto.decode_header(socket); // Read the response header from the server.

		// If the response code is not 2103 (acknowledgment of file receipt) or it's 2107 (error), handle the error.
		if (rs.code == RESPONSE_CODE_2107 || rs.code != RESPONSE_CODE_2103)
		{
			return rs.code; // Return the response code for further handling.
		}

		// If the response code is 2103, process the response payload.
		unsigned char* payload = new unsigned char[rs.payload_size]; // Allocate memory for the response payload.
		receive_pdu(payload, rs.payload_size); // Receive the payload from the server.
		int content_size = proto.decode_content_size(&payload[ID_LENGTH]); // Extract the content size from the payload.
		std::string file_name = proto.decode_file_name(&payload[ID_LENGTH + CONTENT_SIZE_LENGTH]); // Extract the file name from the payload.

		// Calculate and receive the CRC checksum from the server.
		unsigned int crc = proto.decode_check_sum(&payload[ID_LENGTH +
			CONTENT_SIZE_LENGTH + FILE_NAME_LENGTH]); // Extract the CRC checksum from the payload.
		std::cout << "\treceived CRC " << crc << std::endl;

		// response with 1029 if crc match
		// If the local CRC matches the server's CRC, the file was transmitted successfully.
		if (crc == local_crc) {
			std::cout << "sending 1029" << std::endl; // Sending a 1029 message (acknowledgment of successful file receipt).
			request_header* request_1029 = proto.encode_header(decode_hex(client_id), FILE_NAME_LENGTH,
				REQUEST_CODE_1029); // Prepare the 1029 request header.
			send_pdu(request_1029, sizeof(request_header)); // Send the 1029 request header.
			send_pdu(file_path, FILE_NAME_LENGTH); // Send the file path as additional data.
			delete request_1029; // Free the memory allocated for the request header.
			return REQUEST_CODE_END_SUCCESS; // Return a special code indicating successful transfer.
		}

		resend_count++; // Increment the resend count because the CRC didn't match.

		// If CRC doesn't match and it's the 4th attempt, send a 1031 message (failure after maximum retries).
		if (resend_count == FORTH_TRY)
		{
			std::cout << "sending 1031" << std::endl; // Sending a 1031 message (acknowledgment of failed file transfer after retries).
			request_header* request_1031 = proto.encode_header(decode_hex(this->client_id), FILE_NAME_LENGTH,
				REQUEST_CODE_1031); // Prepare the 1031 request header.
			send_pdu(request_1031, sizeof(request_header)); // Send the 1031 request header.
			send_pdu(file_path, FILE_NAME_LENGTH); // Send the file path as additional data.
			delete request_1031; // Free the memory allocated for the request header.
			return REQUEST_CODE_END_FAILURE; // Return a special code indicating failed transfer after maximum attempts.
		}

		// If CRC doesn't match and it's not the 4th attempt yet, send a 1030 message (request for retransmission).
		std::cout << "sending 1030" << std::endl; // Sending a 1030 message (request for retransmission due to CRC mismatch).
		request_header* request_1030 = proto.encode_header(decode_hex(this->client_id), FILE_NAME_LENGTH,
			REQUEST_CODE_1030); // Prepare the 1030 request header.
		send_pdu(request_1030, sizeof(request_header)); // Send the 1030 request header.
		send_pdu(file_path, FILE_NAME_LENGTH); // Send the file path as additional data.
		delete request_1030; // Free the memory allocated for the request header.
	}
	std::cout << "end file_handler" << std::endl;
	return REQUEST_CODE_END_FAILURE; // If the loop exits, return a code indicating a failed transfer.
}
// Function responsible for sending a file over the network.
int Flow::send_file()
{
	std::cout << "start 1028" << std::endl; // Indicate the beginning of the 1028 process (file transfer).
	request_header* requested; // Declare a pointer for the request header.

	// Read the file content as binary.
	std::ifstream data_file(file_path, std::ios::binary); // Open the file in binary mode.
	// If the file cannot be opened, log an error message and return -1.
	if (!(data_file.is_open()))
	{
		std::cout << "aborting because file " << file_path << " not found" << std::endl;
		return -1; // File not found or couldn't be opened.
	}
	size_t fileNameIndex = file_path.find_last_of("\\");
	std::string fileName;
	if (fileNameIndex == -1)
		fileName = file_path;
	else
		fileName = file_path.substr(fileNameIndex + 1, file_path.size() - fileNameIndex);

	// Initialize a vector and copy the file content into the vector.
	std::vector<unsigned char> data_vector(std::istreambuf_iterator<char>(data_file), {}); // Read the entire file into a vector.
	data_file.close(); // Close the file as we've finished reading its content.

	// Allocate memory for the file buffer and copy the content from the vector.
	unsigned char* file_buff = new unsigned char[data_vector.size()];
	for (int i = 0; i < data_vector.size(); i++)file_buff[i] = data_vector[i];

	//encrypt vector using AES using encrypt (vector o char*)
	// Encrypt the file content using AES.
	AESWrapper aesWrapper((unsigned char*)aes.c_str(), aes.length()); // Create an AESWrapper object with the AES key.
	std::string encrypted_file = aesWrapper.encrypt((char*)&data_vector[0], data_vector.size()); // Encrypt the file content.
	int content_size = encrypted_file.size(); // Get the size of the encrypted content.


	// Calculate the total payload size.
	size_t payloadSizeOfContent = CONTENT_SIZE_LENGTH + FILE_NAME_LENGTH + content_size;
	// Prepare the payload with the content size in the first 4 bytes followed by the encrypted file content.
	unsigned char* encrypted_buff = new unsigned char[payloadSizeOfContent];
	std::memset(encrypted_buff, 0, payloadSizeOfContent);
	// The 1st 4 bytes of the payload are the file size.
	encrypted_buff[0] = content_size >> 24;
	encrypted_buff[1] = content_size >> 16;
	encrypted_buff[2] = content_size >> 8;
	encrypted_buff[3] = content_size & 0xFF;
	//TODO copy  fileName
	std::copy(fileName.begin(), fileName.end(), &encrypted_buff[CONTENT_SIZE_LENGTH]);

	// Copy the encrypted file content into the payload buffer.
	for (int i = 0; i < content_size; i++)encrypted_buff[CONTENT_SIZE_LENGTH + FILE_NAME_LENGTH + i] = encrypted_file[i];
	
	// Prepare the request header for the 1028 message (file transfer).
	requested = proto.encode_header(decode_hex(this->client_id), payloadSizeOfContent, REQUEST_CODE_1028);

	// Send the request header.
	send_pdu(requested, sizeof(request_header));
	// Send the payload (file content).
	boost::asio::write(socket, boost::asio::buffer(encrypted_buff, payloadSizeOfContent));

	// Calculate the CRC32 checksum of the original file content for data integrity verification.
	size_t file_size = data_vector.size();
	unsigned int local_crc = proto.crc32((char*)file_buff, file_size); //crc32(data_vector);
	// Cleanup memory allocations.
	delete[] encrypted_buff;
	delete[] file_buff;
	delete requested;
	// Log the calculated CRC checksum for debugging purposes.
	std::cout << "\tcalculated CRC: " << std::dec << local_crc << std::endl;
	std::cout << "end 1028" << std::endl; // Indicate the end of the 1028 process.
	return local_crc; // Return the calculated CRC checksum.
}

// Getter for the 'name' field.
std::string Flow::getName()
{
	return name; // Return the value of the 'name' field.
}
// Setter for the 'name' field.
void Flow::setName(std::string name)
{
	this->name = name; // Set the value of the 'name' field.
}

/**
 * Try to convert bytes to hex string representation.
 * Return empty string upon failure.
 */
 // Method to convert bytes to a hexadecimal string representation. If an error occurs, returns an empty string.
std::string Flow::encode_hex(const uint8_t* buffer, const size_t size)
{
	if (size == 0 || buffer == nullptr)
		return ""; // If the input is invalid, return an empty string.
	const std::string byteString(buffer, buffer + size); // Convert the byte buffer to a std::string.
	if (byteString.empty())
		return ""; // If the conversion failed, return an empty string.
	try
	{
		return boost::algorithm::hex(byteString); // Try to convert the byte string to hexadecimal format.
	}
	catch (...)
	{
		return ""; // In case of conversion failure, return an empty string.
	}
}

// Method to convert a hexadecimal string to bytes. If an error occurs, returns an empty string.
std::string Flow::decode_hex(const std::string& hexString)
{
	if (hexString.empty())
		return ""; // If the input is empty, return an empty string.
	try
	{
		return boost::algorithm::unhex(hexString); // Try to convert the hexadecimal string to bytes.
	}
	catch (...)
	{
		return ""; // In case of conversion failure, return an empty string.
	}
}

// Method to encode a string to base64. Mainly used for encoding binary data for transmission over protocols that are designed to deal with textual data.
std::string Flow::encode_base64(const std::string& str)
{
	std::string encoded; // Declare a string to hold the encoded data.
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded) // Encode the input string in base64 and store it in the 'encoded' string.
		)
	);

	return encoded; // Return the base64-encoded string.
}

// Method to decode a base64 string. This is the reverse of the encode_base64 method and it converts base64-encoded data back to its original form.
std::string Flow::decode_base64(const std::string& str)
{
	if (str.length() == 0)return "";
	std::string decoded; // Declare a string to hold the decoded data.
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decoded) // Decode the base64 string and store it in the 'decoded' string.
		)
	);

	return decoded; // Return the decoded string.
}
// Function to write client information to a file. This can be useful for maintaining state between different runs of the application.
void Flow::write_my_info(STRING name, STRING aes, STRING privKey)
{
	std::ofstream my_info_out(ME_INFO); // Open the 'ME_INFO' file for writing.
	if (my_info_out.is_open()) // Check if the file was successfully opened.
	{
		// If the file is open, write the client information to it.
		my_info_out << name << std::endl; // Write the client's name.
		my_info_out << std::dec << aes << std::endl; // Write the AES key in decimal format.
		my_info_out << privKey << std::endl; // Write the private key.
		my_info_out.close(); // Close the file.
	}
}
// Function to write the private key to a file. This is used for storing the client's private key persistently.
void Flow::write_keys()
{
	std::ofstream my_info_out(PRIVATE_KEY); // Open the 'PRIVATE_KEY' file for writing.
	if (my_info_out.is_open()) // Check if the file was successfully opened.
	{
		// If the file is open, write the base64-encoded private key to it.
		my_info_out << encode_base64(private_key) << std::endl;
		my_info_out.close(); // Close the file.
	}
}


