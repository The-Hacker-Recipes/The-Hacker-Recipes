---
authors: Jenaye, ShutdownRepo
category: evasion
---

# 🛠️ Dropper

> [!WARNING]
> This is a work-in-progress. It's indicated with the 🛠️ emoji in the page name or in the category name. Wanna help? Please reach out to me: [@_nwodtuhs](https://twitter.com/_nwodtuhs)

As for the loader, it is also possible to make a simple one, but the more complex it is, the more likely it is that the anti-virus will not see it

Knowing that an anti-virus compares the signature of our program and the signature of the functions with those of the malware, it is up to the attacker to use his imagination to disguise his program.

In the example below, the anti-virus will raise an alert:

```cpp
static void Main(string[] args)
{
 byte[] buf = new byte[xxx]{ 0x27, 0x3B, 0x38, 0x7D, 0xF4, 0x44 }
 IntPtr MyTests = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
 IntPtr addr = VirtualAllocEx(MyTests, IntPtr.Zero, (uint)buf.Length, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
 WriteProcessMemory(MyTests,xxxxx);
 IntPtr hThread = CreateRemoteThread(MyTests, xxxxxx);
}
```

But, if a sub function is added to create a thread as follow:

```cpp
static void CRT()
{
 IntPtr hThread = CreateRemoteThread(MyTests, xxxxxx);
}

static void Main(string[] args)
{
 byte[] buf = new byte[xxx]{ 0x27, 0x3B, 0x38, 0x7D, 0xF4, 0x44 }
 IntPtr MyTests = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
 IntPtr addr = VirtualAllocEx(MyTests, IntPtr.Zero, (uint)buf.Length, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
 WriteProcessMemory(MyTests,xxxxx);
 CRT()
}
```

By using the previous source code the anti-virus will have more difficulty to understand what is happening. The Russian doll technique can be a good trick to hide a malicious function.

> [!CAUTION]
> The fact of compiling several times will not give us a new signature, only the modification of the code has an impact

> [!CAUTION]
> Once the binary is ready to be executed, access to the internet should be cut in the test environment in order not to send the signature of the bypass to Microsoft or to the editor.

To optimize the probability to bypass the protections we will have to combine several techniques, for example encrypt the active load, de-activate Microsoft logs or choose a special way to inject the virus (cf [process injection](process-injection.md)).