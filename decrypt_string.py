import flare_emu

def asd(i: Int) -> List[Int]:
    return [i for i in range(0, 5)]

type AddressSet = Set[Address]

def decrypt(argv):
    myEH = flare_emu.EmuHelper()
    block = myEH.allocEmuMem(0xC, addr=1234)
    assert block == 1234
    size = 0x1000
    buf = myEH.allocEmuMem(size)
    myEH.uc.mem_write(buf, (0).to_bytes(size, byteorder='little'))
    myEH.uc.mem_write(block + 0, (0).to_bytes(4, byteorder='little'))
    myEH.uc.mem_write(block + 4, (size).to_bytes(4, byteorder='little'))
    myEH.uc.mem_write(block + 8, (buf).to_bytes(4, byteorder='little'))
    myEH.emulateFrom(myEH.analysisHelper.getNameAddr("DecryptStringW"), stack = [0, argv[0]], skipCalls=False)
    # For DecryptStringA:
    #
    # return myEH.getEmuString(buf)
    str = myEH.uc.mem_read(buf, 256)
    str[-1] = 0
    str[-2] = 0
    str = str.decode("utf-16")
    return str
    
def iterateCallback(eh, address, argv, userData):
    s = decrypt(argv)
    eh.analysisHelper.setName(argv[0], "wstr_" + s.strip())
    eh.analysisHelper.setComment(argv[0], s)
    eh.analysisHelper.setComment(address, s, False)
    print("%s: %s" % (eh.hexString(address), s))

if __name__ == '__main__':   
    # TODO: Replace all TlsGetValue calls with 'mov eax, 1234'
    # TODO: Replace all IsBadReadPtr calls with 'xor eax, eax'
    eh = flare_emu.EmuHelper()
    eh.iterate(eh.analysisHelper.getNameAddr("DecryptStringW"), iterateCallback)
