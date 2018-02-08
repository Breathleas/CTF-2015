import string

#data = [1,2,3,4,5]


def setbit(p,pos,value):
    cpos = pos / 8
    bpos = pos % 8
    p[cpos] &= ~(1 << bpos)
    p[cpos] |= value << bpos
    return


def getbit(p,pos):
    cpos = pos / 8
    bpos = pos % 8
    return (p[cpos] >> bpos) & 1


def encode(data,buf):
    table = string.printable.strip()
    m_len = len(data)
    for i in range(m_len):
        data[i] = table.index(chr(data[i]))+1
    for i in range(m_len*6):
        j = i / 6 * 8 + i % 6
        setbit(buf, i, getbit(data,j))
    return buf

def decode(data,buf1,buf2):
    table = string.printable.strip()
    m_len = len(data)
    m_list = range(0,m_len*8)
    for i in range(m_len*6):
        j = i / 6 * 8 + i % 6
        setbit(buf1, j, getbit(data,i))
        m_list[j] = 1
    for i in range(m_len):
        if(buf1[i] > 0 and buf1[i] <= len(table)):
            buf2[i] = buf1[i]
            buf2[i] |= 0x40
            if(buf2[i] > 0 and buf2[i] <= len(table)):
                buf2[i] = table[buf2[i]-1]
            else:
                buf2[i] = ord(' ')
            buf1[i] = table[buf1[i]-1]

fin = open('flag.txt','r')
s = fin.read().strip()
ss = []
sss = []
for c in s:
    ss.append(ord(c))
    sss.append(0)
ssss = encode(ss,sss)

fin = open('flag.enc','rb')
s = fin.read()
ss = []
sss1 = []
sss2 = []
for c in s:
    ss.append(ord(c))
    sss1.append(0)
    sss2.append(0)
ssss = decode(ss,sss1,sss2)
print ssss
