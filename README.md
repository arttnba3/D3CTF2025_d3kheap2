# D^3CTF 2025 - Pwn - d3kheap2

"Once I was seven years old my arttnba3 told me"

"go make yourself some d3kheap or you'll be lonely"

"Soon I'll be 60 years old will I think the kernel pwn is cold"

"Or will I have a lot of baby heap who can sign me in"

> Copyright(c) 2025 <ディーキューブ・シーティーエフ カーネル Pwn 製作委員会>
> 
> Author: arttnba3 @ L-team x Ele3tronic x D^3CTF


## 0x00. Introduction

A very easy kernel pwn challenge that does not need to spend too many efforts on the reverse engineering. The challenge provides us with a kernel module named d3kheap2.ko , which has only the function of allocating and freeing objects from an isolated kmem\_cache d3kheap2\_cache. The vulnerability is that we can free an object twice due to the misconfiguration of the initialization of the reference count, which is similar to the [d3kheap](https://github.com/arttnba3/D3CTF2022_d3kheap).

```c
static long d3kheap2_ioctl(struct file*filp, unsigned int cmd, unsigned long arg)
{
    struct d3kheap2_ureq ureq;
    long res = 0;

    spin_lock(&d3kheap2_globl_lock);

    if (copy_from_user(&ureq, (void*) arg, sizeof(ureq))) {
        logger_error("Unable to copy request from userland!\n");
        res = -EFAULT;
        goto out;
    }

    if (ureq.idx >= D3KHEAP2_BUF_NR) {
        logger_error("Got invalid request from userland!\n");
        res = -EINVAL;
        goto out;
    }

    switch (cmd) {
    case D3KHEAP2_OBJ_ALLOC:
        if (d3kheap2_bufs[ureq.idx].buffer) {
            logger_error(
                "Expected slot [%d] has already been occupied!\n",
                ureq.idx
            );
            res = -EPERM;
            break;
        }

        d3kheap2_bufs[ureq.idx].buffer = kmem_cache_alloc(
            d3kheap2_cachep,
            GFP_KERNEL | __GFP_ZERO
        );
        if (!d3kheap2_bufs[ureq.idx].buffer) {
            logger_error("Failed to alloc new buffer on expected slot!\n");
            res = -ENOMEM;
            break;
        }

        /* vulnerability here */
        atomic_set(&d3kheap2_bufs[ureq.idx].ref_count, 1);
        atomic_inc(&d3kheap2_bufs[ureq.idx].ref_count);

        logger_info(
            "Successfully allocate new buffer for slot [%d].\n",
            ureq.idx
        );

        break;
    case D3KHEAP2_OBJ_FREE:
        if (!d3kheap2_bufs[ureq.idx].buffer) {
            logger_error(
                "Expected slot [%d] had not been allocated!\n",
                ureq.idx
            );
            res = -EPERM;
            break;
        }

        if (atomic_read(&d3kheap2_bufs[ureq.idx].ref_count) <= 0) {
            logger_error("You're not allowed to free a free slot!");
            res = -EPERM;
            break;
        }

        atomic_dec(&d3kheap2_bufs[ureq.idx].ref_count);
        kmem_cache_free(d3kheap2_cachep, d3kheap2_bufs[ureq.idx].buffer);

        logger_info(
            "Successfully free existed buffer on slot [%d].\n",
            ureq.idx
        );

        break;
    case D3KHEAP2_OBJ_EDIT:
        logger_error(
            "🕊🕊🕊 This function hadn't been completed yet bcuz I'm a pigeon!\n"
        );
        break;
    case D3KHEAP2_OBJ_SHOW:
        logger_error(
            "🕊🕊🕊 This function hadn't been completed yet bcuz I'm a pigeon!\n"
        );
        break;
    default:
        logger_error("Got invalid request from userland!\n");
        res = -EINVAL;
        break;
    }

out:
    spin_unlock(&d3kheap2_globl_lock);

    return res;
}
```

## 0x01. Exploitation

As the victim object is in a dedicated `kmem_cache` , we have to think outside of the box. Hence here comes the cross-cache attack:

- Heap spray to allocate lots of challenge objects and then free them all to free the SLUB pages back to the BUDDY
- Heap spray to allocate the freed pages into another `kmem_cache` , here we choose the `system V IPC` as the victim at the first stage
- Free the dangling pointer to challenge object to create UAF on `msg_msgseg` and allocate again to get two reference on the same object
- Free one of the reference and reallocate that as `pipe_buffer`, whose GFP flag is the same with `msg_msgseg` , both of them are allocated from `kmalloc-cg` (if the `CONFIG_SLAB_BUCKETS` is **DISABLED**)
- Manipulate `msg_msgseg` and `pipe_buffer` to gain the arbitrary read & write capability in the kernel space

Hence we have our final exploitation in the file `exp.c` in this repository. The  final successful rate for this is at approximately `99.32%` (result after more than 1024 times automatic local test), which I think is stable enough : )

> Note that you can improve the speed on uploading the exploit to the remote environment by minimizing the binary with `musl-gcc` (I use `x86_64-gentoo-linux-musl-gcc` in my test) or purely assembly code if you have enough time :)

## 0xFF. Last but not least...

The introduction is modified from one of my favourite song when I was not [7 years](https://www.youtube.com/watch?v=LHCob76kigA) old but 15 years old, which will always remind me a lot about my teenage years. I hope that this could remind you about how further the Linux kernel exploitation step out compared to the old [d3kheap](https://github.com/arttnba3/D3CTF2022_d3kheap) in D^3CTF 2022. With the amazing cross-cache attack we can almost exploit every UAF and DF vulnerabilities by transfering the SLUB pages from one `kmem_cache` to another. That's the reason why I named it as `d3kheap2` : **Solution upgration from limited one for d3kheap's easy double free to general one for d3kheap2's lunatic double free**.

Although the core technique for this challenge this is not a new technique in 2025 (which can even be backed to at least [2022](https://i.blackhat.com/USA-22/Thursday/US-22-WANG-Ret2page-The-Art-of-Exploiting-Use-After-Free-Vulnerabilities-in-the-Dedicated-Cache.pdf), but I don't know whether it's the oldest public one), but cross-cache attack is not common in CTF in the past few years. Therefore I choose to present this technique in this year's D^3CTF, as I'm busy in 2024 and do not present anything at that year, and in 2023 I've presented [something else](https://github.com/arttnba3/D3CTF2023_d3kcache) (which was **plagiarized** one year later on [BlackHat USA 2024](https://i.blackhat.com/BH-US-24/Presentations/US24-Qian-PageJack-A-Powerful-Exploit-Technique-With-Page-Level-UAF-Thursday.pdf) by a student called [Jiayi Hu](https://github.com/Lotuhu) who participated in that competition).

Another reason I finally chose the cross-cache attack is that _I did not have too much time on completing these challenges._ As I've graduated from my undergraduate, I did not pay too much attention on how my junior schoolmates prepared for this year's D^3CTF, and get to know that almost no pwn challenges were created j**ust at about 10 days before the competition started** . Therefore I have to stand out to rush to create the pwn challenges with almost nothing new in research in my mind to make sure the competition can be held normally as past years. **Sorry and I apologize that I didn't bring something that is as same cool as the d3kcache in 2023.** But luckily I still have something special for you, which is how I manipulate with `msg_msg` and `pipe_buffer` : _tricky but useful gadgets you may be love in_.

And if you pay enough attention to the kernel itself, you may notice that I didn't enable the `CONFIG_SLAB_BUCKETS` configuration as what [d3kshrm](https://github.com/arttnba3/D3CTF2025_d3kshrm)'s kernel does, which is a mitigation against the heap spraying. Although it is not difficult to bypass this mitigation by doing the full heap spraying instead of doing the precise object allocation, as the D^3CTF this year is only planned to be 24 hours, I hope that this challenge could be the one for you to do the "sign in" for pwn easily, just like the old introduction of `d3kheap` back to D^3CTF 2022. Therefore this challenge is originally designed to not be with an extremely high difficulty.

For the final result of this challenge, most of players had adopted the expected solution, which is to do the cross-cache attack as my expectation. I'm happy to see that many of participated CTFers have known how to take advantage of such advanced techniques to do the exploitation, which can be thought to be the general approach for almost arbitrary heap vulnerabilities. As the cross-cache attack has been widely used in recent years, I'm convince that this must be or even have already become the base strategy and the standard start point for doing the Linux kernel exploitation towards heap vulnerabilities. There is a pity is that I FORGOT to turn the `CONFIG_MEMCG` on to separate `GFP_KERNEL` and `GFP_KERNEL_ACCOUNT` into different `kmem_cache`, as you can see that I have adopted a multi-stage exploitation that manipulate with `msg_msg` and `pipe_buffer` heavily, while some players just simply use the `sk_buff` to read and write the UAF pipe_buffer directly. Another pity is that the team [We_0wn_y0u](https://w0y.at/) who got the first blood for d3kheap2 had ONLY done the d3kheap2 in the D^3CTF 2025 and seems to be disappeared after that, and I temporarily don't know their detailed solution.

Now let's talk about those **State-Of-The-Art academic techniques** like Dirty PageTable ([SLUBStick](https://www.usenix.org/conference/usenixsecurity24/presentation/maar-slubstick), _I don't know why we have two names here and I'm still not sure whether the author is the same_ , as the original blog of the Dirty PageTable had been removed, and I did not have to much time to distinguish) and [DirtyPage](https://www.usenix.org/conference/usenixsecurity24/presentation/guo-ziyi) (also named Page Spray by its authors) **whose base technique is also the cross-cache attack** : Are they powerful and capable enough to be used in this challenge? The answer seems to be NOT EASY, as such approaches are designed for different vulnerability patterns.

- For the SLUBStick, we will need additional capabilities to do the **UAF write** for at least several times, which require us to construct complex and multi-stage cross-cache page freeing and reclaiming, rising the difficulty of constructing the exploitation to a high level while lower down the usability and stability. 
- DirtyPage says that "it takes a further step" by confusing the object counting on a SLUB (refer to its `Figure 1: Page Spray Exploit Model for Double Free.`), however it is **useless** to overwrite an object with no functionalities. In my opinion it might be more capable for attacking those kernel objects with specific functionalities (like `file` or `pipe_buffer`?), but if the target object lacks enough capabilities for the later attacking stages, such exploitation might not be able to be applied.

Hence, **pure cross-cache attack might be more capable and usable for d3kheap2 in my thoughts** , but anyway thanks to them for developing such powerful exploitation techniques that have brought our views to another different aspect.

Another point is that assistant techniques like timing side-channel attack to predict the time of allocating SLUB pages like the Pspray do not have too much effects for the general kernel heap exploitation not limited to the `d3kheap2`. A core reason is that with the existence of mitigation like `CONFIG_RANDOM_KMALLOC_CACHES` in the kernel mainline, it does not mean to be important for us to know whether ONE NEW SLUB pages has been allocated. As our object allocation will always comes from different dedicated pools randomly, doing the heap spray with approximate estimation seems to be the only capable solution, and doing the precise allocation has become almost impossible. Though this mitigation was not enabled in the `d3kheap2`, I still want to talk about something more related to the real-world exploitation. Hope that you will not mind : )

Though I still have many thoughts about the Linux kernel exploitation, but it seems that this passage has become too long at this moment, so let's just stop here. Anyway I would like to thank everyone who has participated in this CTF and has tried to solve my challenge, no matter you've got the flag or not. I'm still so sorry that I did not present you with something as cool as the [d3kcache](https://github.com/arttnba3/D3CTF2023_d3kcache) due to multiple reasons including limited time, hope that you will not mind : )
