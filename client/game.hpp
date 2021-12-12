#pragma once
#include <cstdint>
#include <string>

namespace game
{
	namespace process
	{
		/* Process ID */
		uint32_t process_id		= 0;
		/* Base address of Apex Legends*/
		uint64_t base_address	= 0;
		
		/* Name of the Apex Legends executable and window */
		std::string process_name		= "r5apex.exe";
		std::string game_window_name	= "Apex Legends";


		/* Wait for the game to open and get its process ID and base address*/
		bool attach();

		/* Simple wrapper around read_vm from custom comms implementation*/
		template <typename T>
		T read(uint64_t address);

		/* Simple wrapper around write_vm */
		template <typename T>
		void write(uint64_t address, T value);
	}
}