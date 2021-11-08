#
# Copyright (C) 2021 GrammaTech, Inc.
#
# This code is licensed under the MIT license. See the LICENSE file in
# the project root for license terms.
#
# This project is sponsored by the Office of Naval Research, One Liberty
# Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
# N68335-17-C-0700.  The content of the information does not necessarily
# reflect the position or policy of the Government and no official
# endorsement should be inferred.
#

import gtirb
from gtirb_test_helpers import (
    add_code_block,
    add_data_block,
    add_data_section,
    add_edge,
    add_elf_symbol_info,
    add_function,
    add_proxy_block,
    add_symbol,
    add_text_section,
    create_test_module,
    set_all_blocks_alignment,
)


def test_create_module():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.PE, gtirb.Module.ISA.ARM
    )
    assert ir
    assert m.ir is ir
    assert m.name
    assert m.isa == gtirb.Module.ISA.ARM
    assert m.file_format == gtirb.Module.FileFormat.PE
    assert m.byte_order == gtirb.Module.ByteOrder.Little
    assert m.aux_data


def test_create_module_with_binary_type():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF,
        gtirb.Module.ISA.X64,
        binary_type=("DYN",),
        byte_order=gtirb.Module.ByteOrder.Big,
    )
    assert ir
    assert m.ir is ir
    assert m.name
    assert m.isa == gtirb.Module.ISA.X64
    assert m.file_format == gtirb.Module.FileFormat.ELF
    assert m.byte_order == gtirb.Module.ByteOrder.Big
    assert m.aux_data
    assert m.aux_data["binaryType"].data == ["DYN"]


def test_add_text_section():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    s, bi = add_text_section(m)
    assert s.name == ".text"
    assert bi.section is s
    assert bi.size == 0
    assert bi.contents == b""
    assert not bi.address


def test_add_text_section_with_address():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    s, bi = add_text_section(m, address=0x1000)
    assert s.name == ".text"
    assert bi.section is s
    assert bi.size == 0
    assert bi.contents == b""
    assert bi.address == 0x1000


def test_add_data_section():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    s, bi = add_data_section(m)
    assert s.name == ".data"
    assert bi.section is s
    assert bi.size == 0
    assert bi.contents == b""
    assert not bi.address


def test_add_data_section_with_address():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    s, bi = add_data_section(m, address=0x1000)
    assert s.name == ".data"
    assert bi.section is s
    assert bi.size == 0
    assert bi.contents == b""
    assert bi.address == 0x1000


def test_add_code_block():
    _, m = create_test_module(
        isa=gtirb.Module.ISA.X64, file_format=gtirb.Module.FileFormat.ELF
    )
    _, bi = add_text_section(m)
    b1 = add_code_block(bi, b"\xC3")
    assert bi.size == 1
    assert bi.contents == b"\xC3"
    assert not bi.symbolic_expressions
    assert isinstance(b1, gtirb.CodeBlock)
    assert b1.byte_interval is bi
    assert b1.offset == 0
    assert b1.size == 1

    expr = gtirb.SymAddrConst(0, gtirb.Symbol("hi"))
    b2 = add_code_block(bi, b"\x90\x90\xE8\x00\x00\x00\x00", {3: expr})
    assert bi.size == 8
    assert bi.contents == b"\xC3\x90\x90\xE8\x00\x00\x00\x00"
    assert bi.symbolic_expressions == {4: expr}
    assert isinstance(b2, gtirb.CodeBlock)
    assert b2.byte_interval is bi
    assert b2.offset == 1
    assert b2.size == 7


def test_add_data_block():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_data_section(m)
    b1 = add_data_block(bi, b"\xC3")
    assert bi.size == 1
    assert bi.contents == b"\xC3"
    assert not bi.symbolic_expressions
    assert isinstance(b1, gtirb.DataBlock)
    assert b1.byte_interval is bi
    assert b1.offset == 0
    assert b1.size == 1

    expr = gtirb.SymAddrConst(0, gtirb.Symbol("hi"))
    b2 = add_data_block(bi, b"\x90\x90\xE8\x00\x00\x00\x00", {3: expr})
    assert bi.size == 8
    assert bi.contents == b"\xC3\x90\x90\xE8\x00\x00\x00\x00"
    assert bi.symbolic_expressions == {4: expr}
    assert isinstance(b2, gtirb.DataBlock)
    assert b2.byte_interval is bi
    assert b2.offset == 1
    assert b2.size == 7


def test_add_proxy_block():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    b1 = add_proxy_block(m)
    assert b1.module is m

    b2 = add_proxy_block(m)
    assert b1 is not b2
    assert b2.module is m


def test_add_symbol():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    proxy = add_proxy_block(m)
    sym = add_symbol(m, "hi", proxy)
    assert sym.module == m
    assert sym.name == "hi"
    assert sym.referent is proxy


def test_add_elf_symbol_info():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    sym = add_symbol(m, "hi")
    add_elf_symbol_info(m, sym, 100, "FUNC", "GLOBAL", "DEFAULT", 1)
    assert m.aux_data["elfSymbolInfo"].data == {
        sym: (100, "FUNC", "GLOBAL", "DEFAULT", 1)
    }


def test_add_function_with_name():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)
    b1 = add_code_block(bi, b"\x90")
    b2 = add_code_block(bi, b"\xC3")
    b3 = add_code_block(bi, b"\xCC")

    func_id = add_function(m, "hello", b1, {b2, b3})
    assert func_id
    (sym,) = m.symbols
    assert sym.name == "hello"
    assert sym.referent is b1
    assert m.aux_data["functionEntries"].data[func_id] == {b1}
    assert m.aux_data["functionBlocks"].data[func_id] == {b1, b2, b3}
    assert m.aux_data["functionNames"].data[func_id] == sym
    assert m.aux_data["elfSymbolInfo"].data[sym] == (
        0,
        "FUNC",
        "GLOBAL",
        "DEFAULT",
        0,
    )


def test_add_function_with_symbol():
    _, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)
    b1 = add_code_block(bi, b"\x90")
    b2 = add_code_block(bi, b"\xC3")
    b3 = add_code_block(bi, b"\xCC")
    sym = add_symbol(m, "hello", b1)

    func_id = add_function(m, sym, b1, {b2, b3})
    assert func_id
    assert m.aux_data["functionEntries"].data[func_id] == {b1}
    assert m.aux_data["functionBlocks"].data[func_id] == {b1, b2, b3}
    assert m.aux_data["functionNames"].data[func_id] == sym
    assert m.aux_data["elfSymbolInfo"].data[sym] == (
        0,
        "FUNC",
        "GLOBAL",
        "DEFAULT",
        0,
    )


def test_add_edge():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)
    b1 = add_code_block(bi, b"\x90")
    b2 = add_code_block(bi, b"\xC3")

    edge = add_edge(
        ir.cfg, b1, b2, gtirb.Edge.Type.Branch, conditional=True, direct=False
    )
    assert edge in ir.cfg
    assert edge.source is b1
    assert edge.target is b2
    assert edge.label
    assert edge.label.type == gtirb.Edge.Type.Branch
    assert edge.label.conditional
    assert not edge.label.direct


def test_set_all_blocks_alignment():
    ir, m = create_test_module(
        gtirb.Module.FileFormat.ELF, gtirb.Module.ISA.X64
    )
    _, bi = add_text_section(m)
    b1 = add_code_block(bi, b"\x90")
    b2 = add_code_block(bi, b"\xC3")
    b3 = add_code_block(bi, b"\xCC")

    set_all_blocks_alignment(m, 1)
    assert m.aux_data["alignment"].data == {b1: 1, b2: 1, b3: 1}
