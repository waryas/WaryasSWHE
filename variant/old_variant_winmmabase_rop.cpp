#include <windows.h> 
#include <stdio.h>
#include <psapi.h>
#include <shlobj.h> 
#include <stdint.h>
#include <winternl.h>
#include <consoleapi.h>

#define NTHEADER(ImgBase) PIMAGE_NT_HEADERS64(PIMAGE_DOS_HEADER(ImgBase)->e_lfanew + uint64_t(ImgBase))
#define SET_BIT(Val, Num, Up) { if(Up) { Val |= (1 << Num); } else { Val &= ~(1 << Num); } }
#define IS_BIT_SET(Val, Num) (Val & (1 << Num))

#define SHARED_MEM_MMIO_STRUCT 0x200
#define SHARED_MEM_SHADOW_VMT 0x300
#define SHARED_MEM_COMMAND_BUFFER 0x700
#define SHARED_MEM_STACK_OFFSET 0x800
#define SHARED_MEM_STACK_PLACEHOLDER_OFFSET (SHARED_MEM_STACK_OFFSET - 8)

#pragma comment(lib, "ntdll.lib")

class CProcess
{
public:
    DWORD ThreadID{};
    DWORD ProcessID{};
    HWND ProcessHwnd{};
    uintptr_t peb{};
    uintptr_t discord_base{};
    uintptr_t discord_framebuffer{};
    uintptr_t base{};

    bool Initialize(const wchar_t* WindowName, const wchar_t* ClassName = 0)
    {
        ProcessHwnd = FindWindowW(ClassName, WindowName);
        if (!ProcessHwnd) return false;

        ThreadID = GetWindowThreadProcessId(ProcessHwnd, &ProcessID);
        return ThreadID != 0;
    }
    
};



class CExploit
{
private:
    CProcess *ProcessData{};



    HMODULE winmm{};
    FARPROC mmio_rename{};

    uint64_t SharedCount{};

    uint64_t PopRCX{};
    uint64_t PopRDX{};
    uint64_t PopRAX{};
    uint64_t PopRSP{};
    uint64_t MovRax_RCX{};

    uint64_t ReadRCX_RAX{};

    uint64_t WriteRCX_RDX{};
    uint64_t WriteRDX_RCX{};
    uint64_t WriteRCX_RAX{};

    uint64_t AddRSP_58{};
    uint64_t AddRCX_RBP{};
    uint64_t PushRAX_PopRSP{};

    bool LegacyWin10;

    uint32_t ShellCursor{};

    const char* ModulesToCheck[114] = { "ntdll.dll", "kernel32.dll", "user32.dll", "ws2_32.dll", "shell32.dll", "dxgi.dll", "crypt32.dll", "advapi32.dll", "ole32.dll", "secur32.dll", "psapi.dll", "rasadhlp.dll", "msctf.dll", "ntasn1.dll", "SHCore.dll", "avifil32.dll", "cryptsp.dll", "wbemsvc.dll", "winmmbase.dll",  "combase.dll", "dwmapi.dll", "powrprof.dll", "ncrypt.dll", "MMDevAPI.dll", "msvcp_win.dll", "propsys.dll", "CoreMessaging.dll", "cryptbase.dll", "IPHLPAPI.DLL", "drvstore.dll", "gdi32full.dll", "version.dll",  "midimap.dll", "coloradapterclient.dll", "wininet.dll", "Windows.UI.dll", "cryptnet.dll", "wbemcomn.dll", "bcrypt.dll", "mscms.dll", "schannel.dll", "userenv.dll", "amsi.dll", "rsaenh.dll", "ucrtbase.dll", "msvfw32.dll", "d3d11.dll", "devobj.dll", "dhcpcsvc6.dll", "wintrust.dll", "xinput1_3.dll", "mswsock.dll", "wdmaud.drv", "sxs.dll", "bcryptprimitives.dll", "ncryptsslp.dll", "gdi32.dll", "normaliz.dll", "clbcatq.dll", "fastprox.dll", "profapi.dll", "win32u.dll", "avrt.dll", "NapiNSP.dll", "WinTypes.dll", "pnrpnsp.dll", "CoreUIComponents.dll", "D3DCompiler_43.dll", "umpdc.dll", "XAudio2_9.dll", "KernelBase.dll", "ntmarta.dll", "sspicli.dll", "kernel.appcore.dll", "dhcpcsvc.dll", "ksuser.dll", "InputHost.dll", "msvcrt.dll", "imm32.dll", "AudioSes.dll", "dnsapi.dll", "wshbth.dll", "mskeyprotect.dll", "msacm32.dll", "twinapi.appcore.dll", "wbemprox.dll", "oleaut32.dll", "msasn1.dll", "winrnr.dll", "hid.dll", "setupapi.dll", "dsound.dll", "windows.storage.dll", "dbghelp.dll", "WindowManagementAPI.dll", "nlaapi.dll", "ResourcePolicyClient.dll", "comctl32.dll", "msacm32.drv", "dbgcore.dll", "imagehlp.dll", "rpcrt4.dll", "FWPUCLNT.DLL", "DXCore.dll", "uxtheme.dll", "TextInputFramework.dll", "winmm.dll", "Windows.Internal.Graphics.Display.DisplayColorManagement.dll", "Wldap32.dll", "shlwapi.dll", "wldp.dll", "sechost.dll", "nsi.dll" };

    bool FindSharedMemory(HANDLE hProcess, uint64_t* MemoryOut, uint64_t* SharedCountOut)
    {
        uint8_t* Address{};
        MEMORY_BASIC_INFORMATION Mbi{};
        bool found = false;
        while (true)
        {
            if (!VirtualQueryEx(hProcess, Address, &Mbi, sizeof(Mbi)))
                break;

            if (hProcess != GetCurrentProcess() && Mbi.State == MEM_COMMIT && Mbi.Protect == PAGE_READONLY && Mbi.RegionSize == 0x1000 && Mbi.Type == MEM_IMAGE) {
                char filename[1024]{};
                K32GetMappedFileNameA(hProcess, Mbi.BaseAddress, filename, sizeof(filename));
                if (strstr(filename, "DiscordHook64"))
                    ProcessData->discord_base = (uintptr_t)Address;
                else if (strstr(filename, "r5apex.exe"))
                    ProcessData->base = (uintptr_t)Address;
            }
            else if (Mbi.State == MEM_COMMIT && Mbi.Protect == PAGE_READWRITE && Mbi.RegionSize == 0x3201000 && Mbi.Type == MEM_MAPPED) {
                ProcessData->discord_framebuffer = (uintptr_t)Address;
            }
            else if (!found && Mbi.State == MEM_COMMIT && Mbi.Protect == PAGE_READWRITE && Mbi.RegionSize == 0x1000 && Mbi.Type == MEM_MAPPED)
            {
                PSAPI_WORKING_SET_EX_INFORMATION WsInfo{};
                WsInfo.VirtualAddress = Mbi.BaseAddress;

                if (QueryWorkingSetEx(hProcess, &WsInfo, sizeof(WsInfo)))
                {
                    if (hProcess == HANDLE(-1))
                    {
                        *MemoryOut = uint64_t(Mbi.BaseAddress);
                        *SharedCountOut = WsInfo.VirtualAttributes.ShareCount;
                        found = true;
                        
                    }
                    else if (WsInfo.VirtualAttributes.ShareCount == *SharedCountOut)
                    {
                        
                        *MemoryOut = uint64_t(Mbi.BaseAddress);
                        found = true;
                    }
                }
            }

            Address += Mbi.RegionSize;
        }

        return found;
    }




    template<int SigLenT>
    uint64_t FindROPSignatureInModule(const char* ModuleName, const char(&Signature)[SigLenT])
    {
        const int SigLen = SigLenT - 1;

        uint64_t ModuleBase = uint64_t(GetModuleHandleA(ModuleName));
        if (!ModuleBase)
        {
            ModuleBase = uint64_t(LoadLibraryA(ModuleName));
            if (!ModuleBase)
            {
                printf("Failed to load module[%s]\n", ModuleName);
                return 0;
            }
        }

        PIMAGE_NT_HEADERS64 NtHdr = NTHEADER(ModuleBase);
        PIMAGE_SECTION_HEADER SectionHdr = IMAGE_FIRST_SECTION(NtHdr);
        for (int i = 0; i < NtHdr->FileHeader.NumberOfSections; i++, SectionHdr++)
        {
            if (SectionHdr->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
                continue;

            if (!(SectionHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE))
                continue;

            for (uint32_t u = 0; u < SectionHdr->Misc.VirtualSize - SigLen; u++)
            {
                uint64_t Addr = ModuleBase + SectionHdr->VirtualAddress + u;
                if (memcmp((void*)Addr, Signature, SigLen) == 0)
                {
                    return Addr;
                }
            }
        }

        return 0;
    }

    template<int SigLenT>
    bool FindGadget(uint64_t* Out, const char* ModuleName, const char(&Signature)[SigLenT])
    {
        if (*Out)
            return true;
        *Out = FindROPSignatureInModule(ModuleName, Signature);
        return *Out;
    }


public:

    uint64_t LocalSharedMemory{};
    uint64_t RemoteSharedMemory{};
    uint64_t RemoteProcessBase{};
    void InsertChain(uint64_t Val1, uint64_t Val2, bool Need2 = true)
    {
        *(volatile uint64_t*)(LocalSharedMemory + ShellCursor) = Val1;
        ShellCursor += 8;

        if (Need2)
        {
            *(volatile uint64_t*)(LocalSharedMemory + ShellCursor) = Val2;
            ShellCursor += 8;
        }
    }

    void ResetCursor()
    {
        ShellCursor = SHARED_MEM_STACK_OFFSET;
    }

    void FixupControlFlow()
    {
        if (!LegacyWin10)
        {
            InsertChain(PopRCX, -0x71);
            InsertChain(AddRCX_RBP, MovRax_RCX);
            InsertChain(PushRAX_PopRSP, 0, false);
        }
        else
        {
            InsertChain(PopRAX, -0x71);
            InsertChain(AddRCX_RBP, PushRAX_PopRSP);
        }
    }

    void Hijack()
    {
        Sleep(0);
        ShowWindow(ProcessData->ProcessHwnd, 0);
        auto craftedinfo =  (MMIOINFO*)(LocalSharedMemory + SHARED_MEM_MMIO_STRUCT);
        memset(craftedinfo, 0, sizeof(*craftedinfo));
        craftedinfo->dwFlags =  0x1000000;
        craftedinfo->pIOProc = (LPMMIOPROC)(AddRSP_58);
        craftedinfo->pchBuffer = (HPSTR)(PopRSP);
        craftedinfo->pchNext = (HPSTR)(RemoteSharedMemory + SHARED_MEM_STACK_OFFSET);

        auto hhook = SetWindowsHookExA(WH_SHELL, (HOOKPROC)(mmio_rename), winmm, ProcessData->ThreadID);
        SendMessage(ProcessData->ProcessHwnd, WM_APPCOMMAND, 0, RemoteSharedMemory + SHARED_MEM_MMIO_STRUCT);
        UnhookWindowsHookEx(hhook);
       
        memset((void*)(LocalSharedMemory + SHARED_MEM_STACK_OFFSET), 0, 0x1000 - SHARED_MEM_STACK_OFFSET);
        Sleep(0);
        ShowWindow(ProcessData->ProcessHwnd, 1);
    }

    uint64_t ReadU64(uint64_t Address)
    {
        ResetCursor();

        {
            InsertChain(PopRCX, Address);
            InsertChain(ReadRCX_RAX, 0, false);
            InsertChain(PopRCX, RemoteSharedMemory + SHARED_MEM_STACK_PLACEHOLDER_OFFSET);
            InsertChain(WriteRCX_RAX, 0, false);
        }

        FixupControlFlow();
        Hijack();

        return *(volatile uint64_t*)(LocalSharedMemory + SHARED_MEM_STACK_PLACEHOLDER_OFFSET);
    }

    void WriteU64(uint64_t Address, uint64_t Value)
    {
        ResetCursor();

        {
            InsertChain(PopRAX, Value);
            InsertChain(PopRCX, Address);
            InsertChain(WriteRCX_RAX, 0, false);
        }

        FixupControlFlow();
        Hijack();
    }



    bool CloneAndReplaceVMT(uint64_t vtbl, size_t size) {

        //Because of stack size issue and to be on the safe space, we don't allow Shadowing VMT bigger than 280 bytes.
        if (size > 0x3f0)
            return false;

        auto orig_vtbl = ReadU64(vtbl);
        if (!orig_vtbl)
            return false;

        if (orig_vtbl != RemoteSharedMemory + SHARED_MEM_SHADOW_VMT)
        {
            ResetCursor();
            bool leftover = false;

            for (int i = 0; i < size; i += 8) {
                
                InsertChain(PopRCX, orig_vtbl + i);
                InsertChain(ReadRCX_RAX, PopRCX);
                InsertChain(RemoteSharedMemory + SHARED_MEM_SHADOW_VMT + i, WriteRCX_RAX);
                leftover = true;
                if (i && (i % 0x140 == 0)) {
                    FixupControlFlow();
                    Hijack();
                    Sleep(1);
                    ResetCursor();
                    leftover = false;
                }
            }
            if (leftover) {
                FixupControlFlow();
                Hijack();
            }
            WriteU64(ProcessData->base + 0x16F1230, RemoteSharedMemory + SHARED_MEM_SHADOW_VMT);
            return true;

        }


        return false;
    }


    // Every write 8 bytes uses 40 bytes of stack and we have 2000 bytes of stack to work with
    // So we can at most write 400 bytes at once
    void WriteData(uint64_t Address, BYTE* Data, size_t size)
    {
        if (size >= 400)
            return;

        ResetCursor();

        for(int i = 0;i < size; i+= 8)
        {
            InsertChain(PopRAX, *(uint64_t*)(Data+i));
            InsertChain(PopRCX, Address+i);
            InsertChain(WriteRCX_RAX, 0, false);
        }

        FixupControlFlow();
        Hijack();
    }

    bool Initialize(CProcess* Proc)
    {
        ProcessData = Proc;

        winmm = LoadLibraryA("winmmbase.dll");
        mmio_rename = GetProcAddress(winmm, "mmioRenameW");

        // Load shared mem.
        {
            char Path[MAX_PATH];
            SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, SHGFP_TYPE_CURRENT, Path);
        }

        // Locate shared memory in our client.
        if (!FindSharedMemory(HANDLE(-1), &LocalSharedMemory, &SharedCount))
        {
            printf("Failed to find shared memory in current process\n");
            return false;
        }

        // Locate shared memory in target process.
        {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, ProcessData->ProcessID);
            if (hProcess == INVALID_HANDLE_VALUE)
            {
                printf("Failed to open process[%d] error[%d]\n", ProcessData->ProcessID, GetLastError());
                return false;
            }

            if (!FindSharedMemory(hProcess, &RemoteSharedMemory, &SharedCount))
            {
                CloseHandle(hProcess);
                printf("Failed to find shared memory in target process\n");
                return false;
            }
            PROCESS_BASIC_INFORMATION pbi{};
            NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), 0);
            ProcessData->peb = (uintptr_t)pbi.PebBaseAddress;
            CloseHandle(hProcess);
        }

        // Find gadgets.
        {
            bool AllGadgetsFound = false;
            uint16_t LoadBitMap = 0;
            for (int i = 0; i < ARRAYSIZE(ModulesToCheck); i++)
            {
                const char* ModuleName = ModulesToCheck[i];
                SET_BIT(LoadBitMap, 0, FindGadget(&PopRCX, ModuleName, "\x59\xC3"));
                SET_BIT(LoadBitMap, 1, FindGadget(&PopRDX, ModuleName, "\x5A\xC3"));
                SET_BIT(LoadBitMap, 2, FindGadget(&PopRAX, ModuleName, "\x58\xC3"));
                SET_BIT(LoadBitMap, 3, FindGadget(&PopRSP, ModuleName, "\x5C\xC3"));

                SET_BIT(LoadBitMap, 4, FindGadget(&WriteRCX_RDX, ModuleName, "\x48\x89\x11\xC3"));
                SET_BIT(LoadBitMap, 5, FindGadget(&ReadRCX_RAX, ModuleName, "\x48\x8B\x01\xC3"));
                SET_BIT(LoadBitMap, 6, FindGadget(&WriteRDX_RCX, ModuleName, "\x48\x89\x0A\xC3"));
                SET_BIT(LoadBitMap, 7, FindGadget(&WriteRCX_RAX, ModuleName, "\x48\x89\x01\xC3"));

                SET_BIT(LoadBitMap, 8, FindGadget(&AddRSP_58, ModuleName, "\x48\x83\xC4\x58\xC3"));
                SET_BIT(LoadBitMap, 9, FindGadget(&AddRCX_RBP, ModuleName, "\x48\x01\xE9\xC3"));
                if (!AddRCX_RBP)
                {
                    SET_BIT(LoadBitMap, 9, FindGadget(&AddRCX_RBP, ModuleName, "\x48\x01\xE8\xC3"));
                    if (AddRCX_RBP)
                        LegacyWin10 = true;
                }

                SET_BIT(LoadBitMap, 10, FindGadget(&PushRAX_PopRSP, ModuleName, "\x50\x5C\xC3"));
                SET_BIT(LoadBitMap, 11, FindGadget(&MovRax_RCX, ModuleName, "\x51\x58\xC3"));

                if (LoadBitMap == 0xFFF)
                {
                    AllGadgetsFound = true;
                    break;
                }
            }

            if (!AllGadgetsFound)
            {
                printf("Failed to find some gadgets\n");
                __debugbreak();
                return false;
            }
        }
        /*
        if (ProcessData->peb)
            ProcessData->base = ReadU64(ProcessData->peb + 0x10);
            */
        return true;
    }
};

#define READ 1
#define WRITE 2


class CIpc {
public:

    struct command {
        uint64_t lock{}; // 0
        uint64_t operation{}; // 8
        uint64_t val1{}; // 0x10 - READ : addr to read from         | WRITE : value to write
        uint64_t val2{}; // 0x18 - READ : where the read value goes | WRITE : address to write to
    };

    inline static command* cmd{};

    static bool Setup(CProcess& proc, CExploit& exploit) {

        /*
        * 
        * 
        * 
        * 
        */
        /*
        auto installed = exploit.CloneAndReplaceVMT(proc.base + 0x16F1230, 0x1B8);

        if (installed) {

            uintptr_t dh64_present_tramp = exploit.ReadU64(proc.discord_base + 0xE9090);

            if (!dh64_present_tramp)
                return false;

            uintptr_t dh64_rwx = dh64_present_tramp & 0xFFFFFFFFFFFFF000;

            BYTE ipc_shellcode[] = { 0x49, 0xBA, 0xAF, 0xFF, 0x7A, 0x1F, 0xBF, 0x01, 0x00, 0x00, 0xFF, 0xB0, 0xD8, 0x00, 0x00, 0x00, 0x41, 0x80, 0x3A, 0x00, 0x74, 0x2B, 0x41, 0x8A, 0x42, 0x08, 0x3C, 0x01, 0x75, 0x0D, 0x49, 0x8B, 0x42, 0x10, 0x48, 0x8B, 0x00, 0x49, 0x89, 0x42, 0x18, 0xEB, 0x0F, 0x3C, 0x02, 0x75, 0xE1, 0x49, 0x8B, 0x42, 0x10, 0x4D, 0x8B, 0x5A, 0x18, 0x49, 0x89, 0x03, 0x41, 0xC6, 0x42, 0x08, 0x00, 0xEB, 0xCF, 0xC3 };

            uint64_t command_buffer = exploit.RemoteSharedMemory + SHARED_MEM_COMMAND_BUFFER;


            cmd = (command*)(exploit.LocalSharedMemory + SHARED_MEM_COMMAND_BUFFER);
            cmd->lock = 0;
            cmd->operation = 0;
            cmd->val1 = 0;
            cmd->val2 = 0;
            memcpy(ipc_shellcode + 2, &command_buffer, sizeof(uint64_t));
            exploit.WriteData(dh64_rwx + 0x12, (BYTE*)ipc_shellcode, sizeof(ipc_shellcode));
            *(uint64_t*)(exploit.LocalSharedMemory + SHARED_MEM_SHADOW_VMT + (27 * 8)) = *(uint64_t*)(exploit.LocalSharedMemory + SHARED_MEM_SHADOW_VMT + (25 * 8));
            *(uint64_t*)(exploit.LocalSharedMemory + SHARED_MEM_SHADOW_VMT + (26 * 8)) = dh64_rwx + 0x12;
            *(uint64_t*)(exploit.LocalSharedMemory + SHARED_MEM_SHADOW_VMT + (25 * 8)) = proc.base + 0x2feaab;


        }
        else {
                        cmd = (command*)(exploit.LocalSharedMemory + SHARED_MEM_COMMAND_BUFFER);
            cmd->lock = 0;
            cmd->operation = 0;
            cmd->val1 = 0;
            cmd->val2 = 0;
        }
        */

        uintptr_t dh64_present_tramp = exploit.ReadU64(proc.discord_base + 0xE9090);

        if (!dh64_present_tramp)
            return false;

        uintptr_t dh64_rwx = dh64_present_tramp & 0xFFFFFFFFFFFFF000;

        BYTE ipc_shellcode[] = {
            0x49, 0xBA, 0xAF, 0xFF, 0x7A, 0x1F, 0xBF, 0x01,
            0x00, 0x00, 0x49, 0x83, 0x3A, 0x00, 0x74, 0x36,
            0x49, 0x8B, 0x42, 0x08, 0x48, 0x83, 0xF8, 0x01,
            0x75, 0x0D, 0x49, 0x8B, 0x42, 0x10, 0x48, 0x8B,
            0x00, 0x49, 0x89, 0x42, 0x18, 0xEB, 0x15, 0x49,
            0x8B, 0x42, 0x08, 0x48, 0x83, 0xF8, 0x02, 0x75,
            0xD9, 0x49, 0x8B, 0x42, 0x10, 0x4D, 0x8B, 0x5A,
            0x18, 0x49, 0x89, 0x03, 0x49, 0xC7, 0x42, 0x08,
            0x00, 0x00, 0x00, 0x00, 0xEB, 0xC4, 0xE9, 0x00,
            0x00, 0x00, 0x00 };

        uint64_t command_buffer = exploit.RemoteSharedMemory + SHARED_MEM_COMMAND_BUFFER;
        uint32_t distance_to_present_tramp = dh64_present_tramp - (dh64_rwx + 0x12 + sizeof(ipc_shellcode));


        cmd = (command*)(exploit.LocalSharedMemory + SHARED_MEM_COMMAND_BUFFER);
        cmd->lock = 0;
        cmd->operation = 0;
        cmd->val1 = 0;
        cmd->val2 = 0;

        if (distance_to_present_tramp < 0x1000) { // If we relaunch, no need to overwrite it or it would crash because distance is going to be negative.
            memcpy(ipc_shellcode + 2, &command_buffer, sizeof(uint64_t));
            memcpy(ipc_shellcode + sizeof(ipc_shellcode) - 4, &distance_to_present_tramp, sizeof(uint32_t));
            Sleep(10);
            exploit.WriteData(dh64_rwx + 0x12, (BYTE*)ipc_shellcode, sizeof(ipc_shellcode));
            Sleep(10);
            exploit.WriteU64(proc.discord_base + 0xE9090, dh64_rwx + 0x12);
        }

        return true;
    }


    __forceinline static void LockFrame() {
        cmd->operation = 0;
        cmd->lock = 1;
    }

    __forceinline static void UnlockFrame() {
        cmd->operation = 0;
        cmd->lock = 0;
    }

    static uint64_t Read64(uintptr_t ptr) {
        cmd->val2 = 0;
        cmd->val1 = ptr;
        cmd->operation = READ;
        while (CIpc::cmd->operation == READ)
            _mm_pause();
        return cmd->val2;
    }

    static void Write64(uintptr_t ptr, uint64_t val) {
        cmd->val2 = ptr;
        cmd->val1 = val;
        cmd->operation = WRITE;
        while (CIpc::cmd->operation == WRITE)
            _mm_pause();
        return;
    }

    template <typename T>
    static T Read(uintptr_t ptr) {
        T ret{};
        int size_of_T = sizeof(T);

       
        int full_chunks = size_of_T / 8;
        int remaining_bytes = size_of_T % 8;

        for (int i = 0; i < full_chunks; i++) {
            auto tmp = Read64(ptr + (i * 8));
            memcpy(((char*)&ret) + (i * 8), &tmp, 8);
        }

        if (remaining_bytes > 0 || full_chunks == 0) {    
            auto tmp = Read64(ptr + (full_chunks * 8));
            memcpy(((char*)&ret) + (full_chunks * 8), &tmp, remaining_bytes);
        }

        return ret;
    }

    static void Cleanup() {
        if (cmd) {
            UnlockFrame();
            cmd->operation = 0;
            cmd->val1 = 0;
            cmd->val2 = 0;
        }
    }

};


#pragma pack(push, 1)
namespace DiscOverlay {
    typedef struct _Header
    {
        UINT Magic; //0
        uint64_t FrameCount; //4
        UINT Width; //12
        UINT Height; //16
    } Header;
};
#pragma pack(pop,1)






BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT)
        CIpc::Cleanup();
    return true;
}

void onExit() {
    CIpc::Cleanup();
}

/*
1FA 4000
*/

#include <vector>
#include <unordered_set>
#include "C:\Users\Generic\python\font_glyphs.h"

class FrameBuffer {
private:
    size_t width, height;
    std::vector<uint32_t> buffer; // Buffer now uses uint32_t for each pixel
    std::unordered_set<size_t> dirtyFlags;
    std::unordered_set<size_t> previous_dirtyFlags;

public:
    FrameBuffer(size_t w, size_t h) : width(w), height(h) {
        size_t totalPixels = w * h;
        buffer.resize(totalPixels, 0);
        size_t chunkCount = (totalPixels * sizeof(uint32_t) + 7) / 8;
        dirtyFlags.reserve(chunkCount);
        previous_dirtyFlags.reserve(chunkCount);
        clearBuffers();
    }

    void clearBuffers() {
        std::fill(buffer.begin(), buffer.end(), 0);
        dirtyFlags.clear();
        previous_dirtyFlags.clear();
    }

    void SetPixel(size_t x, size_t y, uint32_t color) {
        if (x >= width)
            return;
        if (y >= height)
            return;
        size_t index = y * width + x;
        size_t chunkIndex = (index * sizeof(uint32_t)) / 8;
        buffer[index] = color;
        dirtyFlags.insert(chunkIndex);
    }

    void UpdateDirtyFlags() {
        for (auto &i : previous_dirtyFlags)
            dirtyFlags.insert(i);
    }

    void Flush(CProcess& proc) {
        uintptr_t baseAddress = proc.discord_framebuffer + 20;

        UpdateDirtyFlags();
        previous_dirtyFlags.clear();

        uint64_t* currentBuffer = reinterpret_cast<uint64_t*>(buffer.data());
        int b = 0;


        for (auto &i : dirtyFlags) {
            size_t byteOffset = i * 8;
            CIpc::Write64(baseAddress + byteOffset, currentBuffer[i]);
            if (currentBuffer[i])
                previous_dirtyFlags.insert(i);
            currentBuffer[i] = 0;
            b++;
        }
        dirtyFlags.clear();
        

    }


    bool resize(size_t newWidth, size_t newHeight) {
        if (width != newWidth || height != newHeight) {
            width = newWidth;
            height = newHeight;
            size_t totalPixels = newWidth * newHeight;
            buffer.resize(totalPixels);
            size_t chunkCount = (totalPixels * sizeof(uint32_t) + 7) / 8;
            dirtyFlags.reserve(chunkCount);
            previous_dirtyFlags.reserve(chunkCount);
            clearBuffers();
            return true;
        }
        return false;
    }



    inline void DrawTexts(UINT x, UINT y, const char* text, uint32_t color, int drawOutline = 1) {
        UINT startX = x;
        int baselineY = y;  // Set to where you want the text baseline

        for (size_t i = 0; text[i] != '\0'; i++) {
            char c = text[i];
            if (c < 32 || c > 126) continue;

            const Glyph* glyph = &glyphs[c - 32];
            const unsigned char* bitmap = glyph->data;

            int glyphX = startX + glyph->offset_x;
            int glyphY = baselineY + glyph->offset_y;  // Adjust to place baseline correctly

            if (drawOutline) {
                uint32_t outlineColor = 0x000000;  // Assuming black color for the outline
                // Draw outline by setting pixels around each character pixel
                for (int row = 0; row < glyph->height; row++) {
                    for (int col = 0; col < glyph->width; col++) {
                        int bit = (bitmap[row * ((glyph->width + 7) / 8) + col / 8] >> (7 - (col % 8))) & 1;
                        if (bit) {
                            for (int dy = -1; dy <= 1; dy++) {
                                for (int dx = -1; dx <= 1; dx++) {
                                    if (dx != 0 || dy != 0) { // Avoid the center pixel
                                        SetPixel(glyphX + col + dx, glyphY + row + dy, outlineColor + 0xFF000000);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Draw the actual character
            for (int row = 0; row < glyph->height; row++) {
                for (int col = 0; col < glyph->width; col++) {
                    int bit = (bitmap[row * ((glyph->width + 7) / 8) + col / 8] >> (7 - (col % 8))) & 1;
                    if (bit) {
                        SetPixel(glyphX + col, glyphY + row, color);
                    }
                }
            }
            startX += glyph->width;  // Advance to the start of the next character
        }
    }




    inline void DrawLine(UINT x1, UINT y1, UINT x2, UINT y2, uint32_t color)
    {
        int dx = abs(static_cast<int>(x2 - x1)), sx = x1 < x2 ? 1 : -1;
        int dy = -abs(static_cast<int>(y2 - y1)), sy = y1 < y2 ? 1 : -1;
        int err = dx + dy, e2;

        while (true)
        {
            SetPixel(x1, y1, color);
            if (x1 == x2 && y1 == y2)
                break;
            e2 = 2 * err;
            if (e2 >= dy) { err += dy; x1 += sx; }
            if (e2 <= dx) { err += dx; y1 += sy; }
        }
    }

    inline void DrawRectangle(UINT x1, UINT y1, UINT width, UINT height, uint32_t color)
    {
        for (UINT x = x1; x < x1 + width; x++)
        {
            SetPixel(x, y1, color);
            SetPixel(x, y1 + height - 1, color);
        }

        for (UINT y = y1; y < y1 + height; y++)
        {
            SetPixel(x1, y, color);
            SetPixel(x1 + width - 1, y, color);
        }
    }

    inline void DrawCircle(UINT x0, UINT y0, UINT radius, uint32_t color)
    {
        int x = radius;
        int y = 0;
        int radiusError = 1 - x;

        while (x >= y)
        {
            SetPixel(x0 + x, y0 + y, color);
            SetPixel(x0 - x, y0 + y, color);
            SetPixel(x0 - x, y0 - y, color);
            SetPixel(x0 + x, y0 - y, color);
            SetPixel(x0 + y, y0 + x, color);
            SetPixel(x0 - y, y0 + x, color);
            SetPixel(x0 - y, y0 - x, color);
            SetPixel(x0 + y, y0 - x, color);

            y++;
            if (radiusError < 0)
            {
                radiusError += 2 * y + 1;
            }
            else
            {
                x--;
                radiusError += 2 * (y - x + 1);
            }
        }
    }

};

namespace Offset {

};

#pragma comment(lib, "winmm.lib")

int main()
{



    // Init
    {
        SetConsoleCtrlHandler(ConsoleHandler, TRUE);
        atexit(onExit);
    }

    CProcess ApexProcess{};
    CExploit Exploit{};

    if (!ApexProcess.Initialize(L"Apex Legends", L"Respawn001"))

    {
        printf("Apex is not running\n");
       // Sleep(5000);
       // return -1;
    }


    
    if (!Exploit.Initialize(&ApexProcess))
    {
        printf("Failed to load exploit\n");
        Sleep(5000);
        return -1;
    }

    if (!ApexProcess.discord_base) {
        printf("Discord overlay not enabled\n");
        Sleep(5000);
        return -1;
    }

    if (!ApexProcess.discord_framebuffer) {
        printf("ESP can't be enabled, no discord overlay found\n");
        Sleep(5000);
        return -1;
    }

    if (!CIpc::Setup(ApexProcess, Exploit)) {
        printf("Failed IPC setup\n");
        Sleep(5000);
        return -1;
    }


    Sleep(10);
    printf("starting...\n");

    FrameBuffer* fb = new FrameBuffer(1920, 1080);

   
    
    LARGE_INTEGER frequency;
    LARGE_INTEGER start;
    LARGE_INTEGER end;
    
    QueryPerformanceFrequency(&frequency);

   
    while (1) {
        /*
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&start);
        */
        QueryPerformanceCounter(&start);

        CIpc::LockFrame();

        auto overlay_header = CIpc::Read<DiscOverlay::Header>(ApexProcess.discord_framebuffer);
        overlay_header.FrameCount++;
        CIpc::Write64(ApexProcess.discord_framebuffer + 4, overlay_header.FrameCount);

   
        if (fb->resize(overlay_header.Width, overlay_header.Height))
            fb->Flush(ApexProcess);
        else {
            fb->DrawTexts(400, 400, "Just drawing with 0 handle or detection vector", 0xFFFFFFFF);
            fb->DrawCircle(500, 500, 5, 0xFFFFFFFF);
            fb->Flush(ApexProcess);
        }
       

        CIpc::UnlockFrame();

        
        QueryPerformanceCounter(&end);
        double duration = (end.QuadPart - start.QuadPart) * 1.0e3 / frequency.QuadPart;
        

        // Print the duration in milliseconds with four-digit accuracy using printf
        printf("Time taken: %.4f ms\n", duration);
        Sleep(0);

    }

    return 0;
}
