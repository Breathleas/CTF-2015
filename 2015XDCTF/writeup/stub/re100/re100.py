from string import ascii_lowercase, punctuation, digits, whitespace
import gdb
import sys

gdb.execute("file ./ac50b48c8f69253e14ae833da9de2ade")
p = gdb.inferiors()[0]
gdb.execute("set height 0")

#get rid of ptrace anti-debugging
gdb.execute("tb *0x40091d")
gdb.execute("r")
gdb.execute("set $rip=0x400933")

#get rid of getchar
gdb.execute("tb *0x040093D")
gdb.execute("c")
gdb.execute("set $eax=1")
gdb.execute("set $rip=0x400942")

#first get the result of 'Z'*12
#so we can later determine what index matches to what index
original = '$' * 12
p.write_memory(0x0601328, original)
gdb.execute("b *0x400A66")
gdb.execute("c")
template = str(p.read_memory(0x601310, 24))
goal = str(p.read_memory(0x6012A0, 24))
goal = "".join([chr(ord(c) ^ 7) for c in goal])
assert(len(goal) == 24)

solution = ""
for i in range(12):
	gdb.execute("set $eax=1")
	gdb.execute("set $rip=0x400942")
	p.write_memory(0x0601328, original[:i] + '#' + original[i + 1:])
	gdb.execute("c")
	
	#find the index that changes
	result = str(p.read_memory(0x601310, 24))
	indices = [j for j in range(24) if result[j] != template[j]]
	
	for c in ascii_lowercase + punctuation + digits + whitespace:
		gdb.execute("set $eax=1")
		gdb.execute("set $rip=0x400942")
		p.write_memory(0x0601328, original[:i] + c + original[i + 1:])
		gdb.execute("c")
		result = str(p.read_memory(0x601310, 24))

		if result[indices[0]] == goal[indices[0]]:
			print "[+] Found character %d: %c" % (i, c)
			solution += c

			#make sure all the other indices match too
			for index in indices:
				if result[index] != goal[index]:
					print "[-] Something's wrong ..."
					raw_input()
			break

	if len(solution) != i + 1:
		solution += "_"
		print indices
		print "[-] No character found for index %d" % i

print "[+] Flag: %s" % solution
