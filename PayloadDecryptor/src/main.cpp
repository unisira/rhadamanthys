#include <Windows.h>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memoryapi.h>
#include <string>
#include <vector>
#include <winnt.h>
#include <ntstatus.h>

typedef NTSTATUS(__stdcall *_RtlCompressBuffer)(
    USHORT CompressionFormatAndEngine, PUCHAR UncompressedBuffer,
    ULONG UncompressedBufferSize, PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize, ULONG UncompressedChunkSize,
    PULONG FinalCompressedSize, PVOID WorkSpace);

typedef NTSTATUS(__stdcall *_RtlDecompressBuffer)(USHORT CompressionFormat,
                                                  PUCHAR UncompressedBuffer,
                                                  ULONG UncompressedBufferSize,
                                                  PUCHAR CompressedBuffer,
                                                  ULONG CompressedBufferSize,
                                                  PULONG FinalUncompressedSize);

typedef NTSTATUS(__stdcall *_RtlDecompressFragment)(
    USHORT CompressionFormat, PUCHAR UncompressedBuffer,
    ULONG UncompressedBufferSize, PUCHAR CompressedBuffer,
    ULONG CompressedBufferSize, ULONG FragmentOffset,
    PULONG FinalUncompressedSize, PVOID Workspace);

typedef NTSTATUS(__stdcall *_RtlDecompressBufferEx)(
    _In_ USHORT CompressionFormat, _Out_ PUCHAR UncompressedBuffer,
    _In_ ULONG UncompressedBufferSize, _In_ PUCHAR CompressedBuffer,
    _In_ ULONG CompressedBufferSize, _Out_ PULONG FinalUncompressedSize,
    _In_ PVOID WorkSpace);

typedef NTSTATUS(__stdcall *_RtlGetCompressionWorkSpaceSize)(
    USHORT CompressionFormatAndEngine, PULONG CompressBufferWorkSpaceSize,
    PULONG CompressFragmentWorkSpaceSize);

typedef struct _RtlCompression {
  _RtlCompressBuffer RtlCompressBuffer;
  _RtlDecompressBuffer RtlDecompressBuffer;
  _RtlDecompressFragment RtlDecompressFragment;
  _RtlDecompressBufferEx RtlDecompressBufferEx;
  _RtlGetCompressionWorkSpaceSize RtlGetCompressionWorkSpaceSize;
} RtlCompressionFuncs;

int GetCompressionFunctions(RtlCompressionFuncs *funcs) {
  DWORD Status = ERROR_SUCCESS;
  HMODULE Ntdll;

  /* Open up a handle to ntdll so that we can find the compression API fucntions
   */
  if ((Ntdll = GetModuleHandleA("ntdll.dll")) == NULL) {
    perror("[!] Unable to loadlibrary ntdll.dll");
    Status = GetLastError();
    goto exit;
  }

  /* Get the addresses of the compression functions */
  if (((funcs->RtlCompressBuffer = (_RtlCompressBuffer)GetProcAddress(
            Ntdll, "RtlCompressBuffer")) == NULL) ||
      ((funcs->RtlDecompressBuffer = (_RtlDecompressBuffer)GetProcAddress(
            Ntdll, "RtlDecompressBuffer")) == NULL) ||
      ((funcs->RtlDecompressBufferEx = (_RtlDecompressBufferEx)GetProcAddress(
            Ntdll, "RtlDecompressBufferEx")) == NULL) ||
      ((funcs->RtlDecompressFragment = (_RtlDecompressFragment)GetProcAddress(
            Ntdll, "RtlDecompressFragment")) == NULL) ||
      ((funcs->RtlGetCompressionWorkSpaceSize =
            (_RtlGetCompressionWorkSpaceSize)GetProcAddress(
                Ntdll, "RtlGetCompressionWorkSpaceSize")) == NULL)) {
    perror("[!] Unable to locate Rtl Compression functions\n");
    Status = GetLastError();
    goto exit;
  }

exit:
  return Status;
}

struct PayloadCtx {
  int int0;
  int int4;
  char keys[256];
};

void stage_1_better(PayloadCtx *Ctx, char *DecryptKeyBuf,
                    int64_t DecryptKeyLen) {
  Ctx->int0 = 0;
  Ctx->int4 = 0;
  for (int i = 0; i < 256; i++)
    Ctx->keys[i] = i;
}

void stage_2(PayloadCtx *a1, char *a2, int a3, int *a4) {
  __int64 result; // rax
  int dword0;     // r10d
  int dword4;     // r9d
  char *v7;       // rsi
  char v8;        // al
  char v9;        // r8

  result = (unsigned int)result;
  dword0 = a1->int0;
  dword4 = a1->int4;
  if (a3 > 0) {
    v7 = &a2[a3];
    do {
      dword0 = (unsigned __int8)(dword0 + 1);
      v8 = a1->keys[dword0];
      dword4 = (unsigned __int8)(v8 + dword4);
      v9 = a1->keys[dword4];
      a1->keys[dword0] = v9;
      a1->keys[dword4] = v8;
      result = (unsigned __int8)a1->keys[(unsigned __int8)(v9 + v8)];
      *a2++ ^= result;
    } while (a2 != v7);
  }
  a1->int0 = dword0;
  a1->int4 = dword4;
}

void stage_1(PayloadCtx *Buffer, char *DecryptKeyBuf, int64_t DecryptKeyLen) {
  PayloadCtx *result; // rax
  PayloadCtx *v5;     // r10
  int v6;             // r9d
  int v7;             // r10d
  int v8;             // r9d
  __int64 v9;         // rsi
  char v10;           // bl

  result = Buffer;
  v5 = Buffer;
  v6 = 0;
  Buffer->int0 = 0;
  Buffer->int4 = 0;
  do {
    v5->keys[0] = v6++;
    v5 = (PayloadCtx *)((char *)v5 + 1);
  } while (v6 != 256);
  v7 = 0;
  v8 = 0;
  do {
    if ((int)DecryptKeyLen <= v7) {
      v7 = 1;
      v9 = 0LL;
    } else {
      v9 = v7++;
    }
    v10 = result->keys[0];
    v8 = (unsigned __int8)(v10 + DecryptKeyBuf[v9] + v8);
    result->keys[0] = Buffer->keys[v8];
    result = (PayloadCtx *)((char *)result + 1);
    Buffer->keys[v8] = v10;
  } while (result != (PayloadCtx *)&Buffer->keys[248]);
}

std::vector<char> FromHex(const std::string &S) {
  std::vector<char> Bytes;
  for (int i = 0; i < S.size(); i += 2)
    Bytes.push_back(std::stoi(S.substr(i, 2), nullptr, 16));
  return Bytes;
}

#define RVA_PTR(Addr, Offs) ((PVOID)((PCHAR)Addr + (INT64)(Offs)))

std::vector<uint8_t> readFile(const std::string &filename) {
  std::ifstream file(filename, std::ios::binary);
  return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
}

int main() {
  RtlCompressionFuncs Funcs;
  GetCompressionFunctions(&Funcs);

  std::vector<uint8_t> DecryptedPayload =
      readFile("decrypted_payload_rev.bin");

  std::vector<char> decompbuffer(DecryptedPayload.size() * 16);
  ULONG BufferWorkspaceSize = 0;
  ULONG FragmentWorkspaceSize = 0;
  Funcs.RtlGetCompressionWorkSpaceSize(2, &BufferWorkspaceSize,
                                       &FragmentWorkspaceSize);

  std::cout << std::hex;
  std::vector<char> workspace(FragmentWorkspaceSize);
  std::cout << "going to decompress stufff\n";
  std::cout << (int64_t)Funcs.RtlGetCompressionWorkSpaceSize << "\n";
  ULONG FinalSize = 0;
  auto Y = Funcs.RtlDecompressFragment(
      2, (unsigned char *)decompbuffer.data(), decompbuffer.size(),
      (unsigned char *)DecryptedPayload.data(), DecryptedPayload.size(), 0,
      &FinalSize, workspace.data());
  std::cout << "decompressed stufff\n";
  std::cout << Y << "\n";
  std::cout << FinalSize << "\n";
  std::cout << decompbuffer.size() << "\n";
  int attempts = 0;
  while (Y == STATUS_BAD_COMPRESSION_BUFFER && attempts < 100) {
    attempts += 1;
    decompbuffer.resize(FinalSize);
    auto Y = Funcs.RtlDecompressFragment(
      2, (unsigned char *)decompbuffer.data(), decompbuffer.size(),
      (unsigned char *)DecryptedPayload.data(), DecryptedPayload.size(), 0,
      &FinalSize, workspace.data());
  }
  std::cout << std::dec;
  std::cout << "Atttempts: " << attempts << "\n";
  std::ofstream file("processed_payload.bin", std::ios::binary);
  if (!file) {
    return 1;
  }

  decompbuffer.resize(FinalSize);
  file.write(decompbuffer.data(), decompbuffer.size());
  if (!file) {
    std::cerr << "Error: Failed to write buffer to file" << std::endl;
    return 1;
  }

  file.close();

  return 0;
}
