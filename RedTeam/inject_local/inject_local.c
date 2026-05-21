// gcc inject_local.c -o inject_local.exe

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

// display error message for last error code
VOID xstrerror (PCHAR fmt, ...){
    PCHAR  error=NULL;
    va_list arglist;
    CHAR   buffer[1024];
    DWORD   dwError=GetLastError();
    
    va_start(arglist, fmt);
    vsnprintf(buffer, ARRAYSIZE(buffer), fmt, arglist);
    va_end (arglist);
    
    if (FormatMessage (
          FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
          NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
          (LPSTR)&error, 0, NULL))
    {
      printf("  [ %s : %s\n", buffer, error);
      LocalFree (error);
    } else {
      printf("  [ %s error : %08lX\n", buffer, dwError);
    }
}

BOOL injectPIC(LPVOID code, DWORD codeLen) {
    LPVOID  cs;
    DWORD   t;
    
    // 1. allocate read-write (RW) memory for payload
    printf("  [ allocating memory for payload.\n");
    cs=VirtualAlloc(NULL, codeLen, 
      MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (cs == NULL) {
      printf("  [ unable to allocate memory.\n");
      return FALSE;
    }
    
    printf("  [ writing code to 0x%p.\n", cs);
    // 2. copy the payload to remote memory
    memcpy(cs, code, codeLen);
    //WriteProcessMemory(hp, cs, code, codeLen, &wr); 
    VirtualProtect(cs, codeLen, PAGE_EXECUTE_READ, &t);
    
    printf("  [ press any key to continue.\n");
    getchar();
    
    // 3. execute payload in remote process
    printf("  [ jumping to shellcode.\n");
    void (*function)();
    function = (void (*)())cs;
    function(); // invoke the shellcode and block until complete

    printf("  [ shellcode completed execution.\n");
    printf("  [ press any key to continue.\n");
    getchar();

    return TRUE;
}

DWORD getdata(PCHAR path, LPVOID *data){
    HANDLE hf;
    DWORD  len,rd=0;
    
    // 1. open the file
    hf=CreateFile(path, GENERIC_READ, 0, 0,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      
    if(hf!=INVALID_HANDLE_VALUE){
      // get file size
      len=GetFileSize(hf, 0);
      // allocate memory
      *data=malloc(len + 16);
      // read file contents into memory
      ReadFile(hf, *data, len, &rd, 0);
      CloseHandle(hf);
    }
    return rd;
}

int main(int argc, char *argv[]){
    LPVOID code;
    SIZE_T code_len;

    if (argc != 2){
      printf("\n  [ usage: inject <loader.bin>\n");
      return 0;
    }
    
    // pic
    code_len = getdata(argv[1], &code);
    if(code_len == 0) {
      printf("  [ unable to read payload.\n");
      return 0;
    }
    injectPIC(code, code_len);
    free(code);
    return 0;
}
