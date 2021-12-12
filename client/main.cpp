#include "mapper.hpp"
#include "game.hpp"

int main(const int argc, char** argv)
{
	/* A driver has to be specified as an argument */
	if (argc != 2 || std::filesystem::path(argv[1]).extension().string().compare(".sys"))
	{
		std::cout << "[-] Incorrect usage" << std::endl;
		return -1;
	}

	/* Initiate all driver related stuff */
	if (!NT_SUCCESS(mapper::comms::init(argv[1])))
	{
		printf("[-] Failed to initialize driver. Exiting program now!\n");
		getchar();
		return -1;
	}

	uint32_t process_id = utils::get_process_id(L"notepad.exe");
	printf("[+] Process ID: %d\n", process_id);

	uint64_t base_address = mapper::comms::get_base_address(process_id);
	printf("[+] Base Address 0x%llx\n", base_address);

	getchar();

	mapper::comms::unload_payload();
}