# ProcessDoppelganging

Process doppelganging POC using direct system calls and dropbox as an external delivery channel for the payload.

Payload has to be a base64 encoded executable file, I use the following code to generate the payloads:

```C#
byte[] data = File.ReadAllBytes(@"C:\Path\to\file.exe");
string payload = Convert.ToBase64String(data);

File.WriteAllText("payload.txt", payload);
```
