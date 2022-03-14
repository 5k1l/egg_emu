
import json
import re
from unicodedata import name
from opcodes_tables import *
import opcodes_tables
class ivmp():
    def __init__(self, file_name) -> None:
        self.file_name = file_name
        self.file_data = bytearray(open(file_name, 'rb').read())
        self.parse_unknow1()
        self.parse_str()
        self.parse_unknow2()
        self.parse_fields()
        self.parse_method_info()
        self.parse_vmp_code()
        self.parse_switch()
        self.parse_jvm_field()
    def read_int(self, off, size):
        return int.from_bytes(self.file_data[off:off+size], 'little')

    def read_str(self, off):
        lens = 0
        while self.file_data[off]:
            lens += 1
            off += 1
        return self.file_data[off-lens:off].decode()

    def parse_unknow1(self):
        unknow_1_off = self.read_int(0x30, 8)
        unknow_1_cnt = self.read_int(0x38, 8)
        self.unknow1_list = {}
        for i in range(unknow_1_cnt):
            self.unknow1_list[i] = self.read_int(unknow_1_off+i*4, 4)

    def parse_str(self):
        str_list_off = self.read_int(0x40, 8)
        str_list_cnt = self.read_int(0x48, 8)
        self.str_map = {}
        for i in range(str_list_cnt):
            self.str_map[i] = self.read_str(str_list_off+self.read_int(str_list_off + i*4, 4))

    def parse_unknow2(self):
        unknow_2_off = self.read_int(0x50, 8)
        unknow_2_cnt = self.read_int(0x58, 8)
        self.unknow2_list = {}
        for i in range(unknow_2_cnt):
            self.unknow2_list[i] = self.read_int(unknow_2_off+i*4, 4)

    def parse_fields(self):
        fields_off = self.read_int(0x60, 8)
        fields_cnt = self.read_int(0x68, 8)
        self.fields_map = {}
        for i in range(fields_cnt):
            field_map = {}
            field_map['cls_name'] = self.str_map[self.read_int(fields_off + 0xc*i, 4)]
            field_map['field_name'] = self.str_map[self.read_int(fields_off + 0xc*i + 4, 4)]
            field_map['type_name'] = self.str_map[self.read_int(fields_off + 0xc*i + 8, 4)]
            self.fields_map[i] = field_map

    def parse_method_info(self):
        method_info_off = self.read_int(0x70, 8)
        method_info_cnt = self.read_int(0x78, 8)
        self.method_info = {}
        for i in range(method_info_cnt):
            method = {}
            method['cls_name'] = self.str_map[self.read_int(method_info_off + 0x14 * i, 4)]
            method['methodname'] = self.str_map[self.read_int(method_info_off + 0x14 * i + 4, 4)]
            method['signature'] = self.str_map[self.read_int(method_info_off + 0x14 * i + 8, 4)]
            method['shorty'] = self.str_map[self.read_int(method_info_off + 0x14 * i + 0xc, 4)]
            method['unknow_field'] = self.read_int(method_info_off + 0x14 * i + 0x10, 4)
            self.method_info[i] = method

    def parse_vmp_code(self):
        vmp_method_off = self.read_int(0x80, 8)
        vmp_method_cnt = self.read_int(0x88, 8)
        self.vmp_method = {}
        for i in range(vmp_method_cnt):
            vmethod = {}
            vmethod['method_info'] = self.method_info[self.read_int(vmp_method_off + 0xc * i, 4)]
            code_off = self.read_int(vmp_method_off + 0xc * i + 4, 4) + vmp_method_off
            vmethod['code_off'] = code_off 
            code_len = self.read_int(code_off+0xc,4)*3
            vmethod['code_len'] = code_len
            vmethod['code'] = self.file_data[code_off : code_off + code_len + 0x10] 
            vmethod['unknow'] = self.read_int(vmp_method_off + 0xc * i + 0x8, 4)
            self.vmp_method[i] = vmethod

    def parse_switch(self):
        switch_off = self.read_int(0x90, 8)
        switch_cnt = self.read_int(0x98, 8)
        self.switch_map = {}
        for i in range(switch_cnt):
            self.switch_map[i] = switch_off + self.read_int(switch_off + 4 * i, 4)

    def parse_jvm_field(self):
        self.jvm_fields_map = {}
        for l in open('./cookie_9555904_field.csv').readlines():
            result = re.findall('field_id\[(\d+)\],(.+?) (.+?),',l)
            if result:
                result = result[0]
                self.jvm_fields_map[result[-1]] = int(result[0])


v = ivmp('./ivmp.data')
opcodes_tables.vmp_helper = v
