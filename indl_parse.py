indl_file_data = bytearray(open('./indl.data','rb').read())
npos = 0x18
maps = {}
while npos < 0x307be4:
    debug_info = int.from_bytes(indl_file_data[npos:npos+4],'little')
    rdebug_info = int.from_bytes(indl_file_data[npos+4:npos+8],'little')
    rsize = int.from_bytes(indl_file_data[npos+8:npos+0xc],'little')
    ropcodes = indl_file_data[npos+0xc:npos+0xc+rsize]
    npos+= (0xc+rsize)
    if debug_info in maps:
        print(debug_info)
        print('strange')
    maps[debug_info] = {}
    maps[debug_info]['real_debug_info'] = rdebug_info
    maps[debug_info]['real_size'] =  rsize
    maps[debug_info]['encopcodes'] = ropcodes.hex()

import json
print(len(maps))
# json.dump(maps,open('xiaoji_opcodes.json','w+'))