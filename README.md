## Unhooking is performed via indirect syscalls.
Leveraging NTAPI to grab NTDLL for unhooking without triggering "PspCreateProcessNotifyRoutine". We've been using this one for a while but I figured some people aren't familiar with how NTAPIs themselves can make a difference at times.

### Basically this variant doesn't trigger a process creation event, because the "process" we generate doesn't have really any information, no threads, no environment, any major thing, it's not even an .exe file (it is a PE). BUT! ntdll is clean-ly loaded, and the new process also doesn't show in Task Manager as well.


https://github.com/mansk1es/GhostFart/assets/74832816/221e7506-995a-460b-b6b8-f9f91354fd3d


![png](https://github.com/mansk1es/GhostFart/assets/74832816/0fc36261-45c2-4de9-ace3-1ce0b549594b)


We essentially perform the original technique idea with a few modifications that might be beneficial against more-aggressive automatic defense mechanisms (such as EDRs) -
1. We don't open ntdll handle on disk/KnownDlls, we open a handle to a benign PE.
2. We don't create a new process via win32 CreateProcess and CREATE_SUSPENDED flag, which notifies the callback because a thread is being created. When there are no threads the notification is not triggered.
3. The process we create doesn't have to be an .exe file, it can be any PE with its headers and sections. Those are a few of the checks that `NtCreateSection` performs when prompting the `SEC_IMAGE` flag. I might make a blog post about it.
4. It doesn't show on taskmanager which is kinda cool if you ask me.

## Why would you need unhooking if you already use indirect syscalls for executing NTAPI?
Well, one major reason is because your C2 might not use indirect syscalls for its actions, and we want to clear NTDLL for it.

## Credits
- Sektor7 - the original Perun's Fart.
- For this one Syswhispers3 asm stubs :D
