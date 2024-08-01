#include <cstdlib>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <rsa.h>
#include <osrng.h>
#include <files.h>
#include "flow.h"


#define STRING std::string

// Define constants for file names where user information and transfer logs will be stored.
#define ME_INFO "me.info"
#define TRANSFER_INFO "transfer.info"

// == Main function, the entry point of the application ==>
int main(int argc, char* argv[])
{
	const int max_length = 1024;
	
	// Declare variables to store various parameters and configurations.
	std::string ip_port, name, file_path, client_id, hex_private_key;
	std::stringstream buffer;
	unsigned char my_info_exists = 0; // Flag to check if the user information already exists.

	// Client initialization block.
	try {
		// Open and read the transfer information file.
		std::ifstream transfer_info(TRANSFER_INFO);
		if (transfer_info.is_open())
		{
			// Read server IP and port, client name, and file path from the transfer info file.
			std::getline(transfer_info, ip_port);    // e.g., 127.0.0.1:5500, 168.176.10.101:5500
			std::getline(transfer_info, name);
			std::getline(transfer_info, file_path);
			transfer_info.close(); // Always close the file after operations are done.
		}
		else {
			// If the transfer info file is not valid or missing, report an error and throw an exception.
			std::cout << "invalid transfer.info file" << std::endl;
			throw std::invalid_argument("invalid transfer.info file ");
		}
		// Open and read the client information file.
		std::ifstream me_info(ME_INFO);
		if (me_info.is_open())
		{
			// Read client name, ID, and private key from the client info file.
			std::getline(me_info, name);
			std::getline(me_info, client_id);
			buffer << me_info.rdbuf(); // Read the rest of the data into a stringstream.
			me_info.close(); // Always close the file after operations are done.
			my_info_exists = 1; // Set the flag indicating the client info exists.
		}
		// Log the initiation of the client with its name.
		std::cout << "Starting client " << name << std::endl;

		// Create a Flow object with the information read from the files.
		Flow* flow = NULL;
		if(my_info_exists == 1)
			flow = new Flow(ip_port, name, client_id, file_path, buffer.str());
		else
			flow = new Flow(ip_port, name, client_id, file_path);
		int response_code = -1;

		// If this client has existing information, try to connect to the server.
		if (my_info_exists == 1)    // existing client
		{
			response_code = flow->connect();        // Initiates the connection process (sends a 1027 request).
			// If the server responds with an error, log it and exit the application.
			if (response_code == RESPONSE_CODE_2107)
			{
				std::cout << "server error, exiting app" << std::endl;
				delete flow;
				return 0;
			}
		}
		// If this is a new client or the server requested signup, initiate the signup process.
		if (my_info_exists == 0 || response_code == RESPONSE_CODE_2106)
		{
			response_code = flow->signup(); // Initiates the signup process.
			// Handle different server responses for the signup process.
			if (response_code == RESPONSE_CODE_2101)
			{
				// If signup fails due to a username issue, log it and exit the application.
				std::cout << "signup failed, please fix the username. exiting app" << std::endl;
				delete flow;
				return 0;
			}
			else if (response_code == RESPONSE_CODE_2107)
			{
				// If the server encounters an error, log it and exit the application.
				std::cout << "server error, exiting app" << std::endl;
				delete flow;
				return 0;
			}
		}

		// Initiate the file transfer process.
		response_code = flow->file_handler();
		// Handle different server responses for the file transfer process.
		if (response_code == RESPONSE_CODE_2107)
		{
			// If the server encounters an error, log it and exit the application.
			std::cout << "server error, exiting app" << std::endl;
			delete flow;
			return 0;
		}
		else if (response_code == REQUEST_CODE_END_SUCCESS)
		{
			// If the file is successfully sent, log it and exit the application.
			std::cout << "file sent successfully" << std::endl;
			delete flow;
			return 0;
		}
		else if (response_code == REQUEST_CODE_END_FAILURE)
		{
			// If the file transfer fails, log it and exit the application.
			std::cout << "failed to send file. exiting app" << std::endl;
			delete flow;
			return 0;
		}

		// Default return if none of the conditions above are met.
		delete flow;
		return 0;	
	}
	// Exception handling block.
	catch (std::exception& e)
	{
		std::cerr << "Exception:" << e.what() << "\n";
	}	
}
