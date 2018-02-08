// ConsoleApplication3.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "windows.h"


__int64 sub_4006D5(__int64 a1, signed int a2, signed int a3)
{
  char v3; // ST1B_1@2
  __int64 result; // rax@3
  signed int i; // [sp+1Ch] [bp-4h]@1

  for ( i = 0; ; ++i )
  {
    result = a2 / 2;                            // result = 12
    if ( (signed int)result <= i )
      break;
    v3 = *(BYTE *)(i + a1);
    *(BYTE *)(a1 + i) = *(BYTE *)(a2 - i - a3 / 2 - 1LL + a1);
    *(BYTE *)(a1 + a2 - i - a3 / 2 - 1LL) = v3;
  }
  return result;
}

int _tmain(int argc, _TCHAR* argv[])
{
	char buf[0x28];
	char xorbytes[] = "\\|Gq\\@?BelTtK5L`\\|D`d42;";
	char *outbuf = buf+0x18;
	strcpy_s(buf,0x28,";%#848N!0Z?7'%23]/5#1\"YX");
	for (int i = 0;i<strlen(xorbytes);i++){
		xorbytes[i] ^= 6;
	}
	for (int i = 0;i<0x17;i++){
		if(buf[i]-32 <= 31){
			buf[i] -= 32;
		}
	}
	sub_4006D5((__int64)buf,24,12);
	for (int i = 0;i<strlen(xorbytes);i++){
		outbuf[i] = buf[i] ^ xorbytes[i];
	}
	return 0;
}



