# Ghost-Injector
Reflective PE Injector, which forces the remote process to read local memory instead of using WriteProcessMemory

Not tested on x64 yet.

Usage: 

1. Create a GHOSTWRITER context

2. Initialize it with InitGhostWriter

3. If all went well, you can now get a thread from any process
    in the system (create one if you will) and call PrepareThread on it
    
4. If GWPrepareThread succeeds, you can now use GWriteMemory and GWCall to do your thing
4.1 (optional) use the reflective injector with the prepared thread.

5. (optional) Once you've finished your work, you can use GWResumeThread 
    to restore it to its original state.
    
Note: If you use the included injector, the thread you provide will be used for executing
your payload, so calling GWResumeThread under such circumstances will be ineffective.
