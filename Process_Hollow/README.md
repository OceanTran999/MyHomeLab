# Process Hollowing
- During studying at University of Information Technology(UIT) as an InfoSec student, I find that Process Hollowing is an interesting technique for attackers when handling with anti-virus applications. This repository will be my opinion and observation during doing the lab.

> [!NOTE]
> This lab will have some images that have different address because I ran many times.

**What is process hollowing?**
- Before digging into the lab, first we need to know what is this technique. Thinking simple, process hollowing is the technique that allows attackers to be able to inject the malicious code to the suspended benign process to evade the detection.

**Analyzing**
- This lab I used `Window API`, Visual Studio and `x86`.
- First, I created a benign process `calc.exe` using the `CreateProcessA()` with the `CREATE_SUSPENDED` flag to make this process in the suspended state, and create a malicious file `MessageBox.exe` with `CreateFileA()` to inject the code to the target process.

<div style="text-align: center;">
  
  ![ProExplorer1](https://github.com/user-attachments/assets/02dfaa76-2025-4ee7-826c-74382d12545e)
  
</div>

- Next, we will write the malicious to the memory. But before doing that, we need to know the size of the malicious file, `GetFileSize()` can handle that. After getting the size, using `VirtualAlloc()` to allocate in the memory. The `VirtualAlloc()` will return the value of `EAX` register, which is the allocated address. Looking 2 images below, the first image is the address that allocated and saved in `EAX` register, the second image is the base address(`0x190000`) in the allocated memory that has `0x00` value after calling `VirtualAlloc()`.

<div style="text-align: center;">
  
![VirtualAlloc_Reg](https://github.com/user-attachments/assets/2ca4960b-7165-4604-a2f1-12d96c94e186)

</div>

![VirtualAlloc_Mem](https://github.com/user-attachments/assets/24d0cf9f-b7a5-40b6-b053-edecfe5c55e3)


- After allocating, the next step is to bring the malicious code to the memory being allocated using the `ReadFile()` function. You can see the image below, the `0x190000` address, which is the base address of allocated memory now is changed.

<div style="text-align: center;">
![mem_success](https://github.com/user-attachments/assets/40d3d90e-ad47-44a5-a13c-941c3aab7242)
</div>

- Now, we just get the malicious code written in the memory, and switch the contend of the benign process to this code.
- First, we need to know the `Image Base Address` of the target process so that we can start know where to write the headers, sections, etc of the malicious file. After searching Google I found that `Process Environment Block(PEB)` contains information of a process for the Operating System. And the offset of `ImageBaseAddress` in PEB is `0x08` in 32-bit, `0x10` in 64-bit.
- When calling `GetThreadContext()`, the data of the process will save to the `CONTEXT` variable. The address of PEB is saved in the `EBX` register, so when add `+0x08` we will get the value of `ImageBaseAddress`. Image below, the value of `ImageBaseAddress` is `0x1C0000`, using `HxD` we can see the code of the `calc.exe`.

<div style="text-align: center;">
![tar_IBA](https://github.com/user-attachments/assets/996f2612-b81d-48d9-b16b-7f012014b675)
</div>

- We are now getting into the target process's code, now we have to replace it with the malicious code. We will call `ZwUnmapViewOfSection()`, but not directly, we have to call this function through the Dynammic Link Library(DLL). The image below is the value of `0x190000` after unmapping.

<div style="text-align: center;">
![unmap_IBA](https://github.com/user-attachments/assets/62d8525a-8e57-4740-b702-8b29c982d929)
</div>

- In this step, we will continue allocating, but this time we will allocate in the target process using `VirtualAllocEx()`. And of course, knowing the size for allocating is necessary, in the `IMAGE_NT_HEADER` class has the `OptionalHeader` field which contains the value of `SizeOfImage`, this is the size of the malicious file. To access the `IMAGE_NT_HEADER` of the PE file, we will first create the pointer points to the `IMAGE_DOS_HEADER`, then add with the value of `e_lfanew` field, which is the offset of the PE file (Relative Virtual Address). Remember, we have to provide full (RWX) permissions so that the malicious can run inside the process. The image below is the value `0x00` of the `ImageBaseAddress` after calling `VirutalAllocEx()`.

<div style="text-align: center;">
![virtualallocex](https://github.com/user-attachments/assets/efce4ac5-be8d-4e7e-8a62-2a748c8ef9f6)
</div>

- The last step is injecting the malware to the allocated address using `WriteProcessMemory()`, writing the Header is simple but writing all Sections can be a little bit complicated, first we have to know the number of sections using `NumberOfSections` in the `IMAGE_NT_HEADER`, then making the loop to write all the sections with `PIMAGE_SECTION_HEADER`, the attribute `PointerOfRawData` is the pointer points to the contend of each section, the `SizeOfRawData` is the size of each section. After successfully injected, we have to change the address of target process's entry point, and make it point to the malicious code's entry point, then using `ResumeThread()` to resume the process. The benign process is now running the malicious code.

<div style="text-align: center;">
![inject_code](https://github.com/user-attachments/assets/55a1f54f-c4f4-4cd3-8528-e39f22b915ce)
</div>

- We can see that there is the `cmd.exe` beneath the `calc.exe`, this is the `MessageBox.exe` which we assumed as the malware at first of the lab, and the notification will show the message ;)

<div style="text-align: center;">
![ProExplorer2](https://github.com/user-attachments/assets/6ade0978-344e-4ca9-82de-06918d021862)
</div>

<div style="text-align: center;">
![Done](https://github.com/user-attachments/assets/d360fad7-8b2e-4b0d-a4b3-8a854fd103b7)
</div>

# References
+ https://learn.microsoft.com/en-us/archive/msdn-magazine/2002/february/inside-windows-win32-portable-executable-file-format-in-detail
+ https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
+ https://github.com/m0n0ph1/Process-Hollowing
+ https://stackoverflow.com/questions/17513363/for-what-do-i-need-to-use-virtualalloc-virtualallocex
+ https://void-stack.github.io/blog/post-Exploring-PEB/
+ https://metehan-bulut.medium.com/understanding-the-process-environment-block-peb-for-malware-analysis-26315453793f
+ https://github.com/Faran-17/Windows-Internals/blob/main/Processes%20and%20Jobs/Processes/PEB%20-%20Part%201.md
+ https://stackoverflow.com/questions/21368429/error-code-487-error-invalid-address-when-using-virtualallocex
