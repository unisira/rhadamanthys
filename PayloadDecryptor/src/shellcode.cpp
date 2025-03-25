#include <fstream>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <winnt.h>

template <typename R = void *, typename P, typename O>
constexpr R RVA(const P ptr, O offset) noexcept
{
	static_assert(std::is_integral<O>::value, "RVA - Offset type must be integral");
	return (R)((uintptr_t)(ptr) + offset);
}

std::vector<uint8_t> readFile(const std::string &filename)
{
	std::ifstream file(filename, std::ios::binary);
	return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void writeFile(const std::string &filename, const std::vector<uint8_t> &data)
{
	std::ofstream file(filename, std::ios::binary);
	file.write(reinterpret_cast<const char *>(data.data()), data.size());
}

// Returns a vector of bytes representing the integer value in `S`
std::vector<uint8_t> fromBytes(const std::string &S, int Radix = 10)
{
	std::vector<uint8_t> Bytes;
	for (int i = 0; i < S.size(); i += 2)
		Bytes.push_back((uint8_t)std::stoull(S.substr(i, 2), nullptr, Radix));
	return Bytes;
}

int main()
{
	std::string Shellcode = "9090554889C84889D54989CA4531C95756534883EC08C70100000000C7410400000000"
				"45884A084183C1014983C2014181F90001000075EB488DB9000100004531D2664531C9EB"
				"3641BA0100000031F60FB658080FB6142E8D3413468D0C0E450FB6C94D63D9420FB67419"
				"08408870084883C00142885C19084839F8740E4539D07EC54963F24183C201EBC44883C4"
				"085B5E5F5DC389C056534883EC084585C0448B11448B49047E4E4183E8014A8D74020141"
				"83C2014181E2FF0000004963DA0FB6441908468D0C08450FB6C94D63D9460FB644190844"
				"884419084288441908418D04000FB6C00FB644010830024883C2014839F275BB44891144"
				"8949044883C4085B5EC3";
	int ShellcodeEntry1 = 0;
	int ShellcodeEntry2 = Shellcode.find("89C0") / 2;
	std::cout << std::hex;
	std::cout << "Entry 1: " << ShellcodeEntry1 << "\n";
	std::cout << "Entry 2: " << ShellcodeEntry2 << "\n";
	std::vector<uint8_t> ShellcodeBytes = fromBytes(Shellcode, 16);

	// Shellcode entry type:
	// Argument 1: RC4 context
	// Argument 2: Buffer
	// Argument 3: Buffer length
	// Argument 4: Unused?
	using ShellcodeEntryTy = void (*)(void *, void *, int, int);

	void *ShellcodeBuf = VirtualAlloc(nullptr, ShellcodeBytes.size(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!ShellcodeBuf) {
		std::cerr << "Failed to allocate shellcode buffer!\n";
		return 1;
	}

	std::memcpy(ShellcodeBuf, ShellcodeBytes.data(), ShellcodeBytes.size());

	std::vector<uint8_t> Payload = readFile("script_compd_payload.bin");

	unsigned char Context[272] = {};
	unsigned char Key[] = "847461425732";
	RVA<ShellcodeEntryTy>(ShellcodeBuf, ShellcodeEntry1)(Context, Key, sizeof(Key) - 1, 0);
	RVA<ShellcodeEntryTy>(ShellcodeBuf, ShellcodeEntry2)(Context, Payload.data(), Payload.size(), 0);
	writeFile("decrypted_payload_rev.bin", Payload);
	return 0;
}
