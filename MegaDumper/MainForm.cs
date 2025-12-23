/*
 * Created by SharpDevelop.
 * User: Bogdan
 * Date: 11.10.2010
 * Time: 15:47
 * * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using ProcessUtils;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;
using WinEnumerator;

namespace Mega_Dumper
{
    /// <summary>
    /// Description of MainForm.
    /// </summary>
    public partial class MainForm : Form
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            UIntPtr nSize,
            out UIntPtr lpNumberOfBytesRead
        );

        // This is now the primary wrapper. It's safe for both x86 and x64.
        public static bool ReadProcessMemory(
            IntPtr hProcess,
            ulong lpBaseAddress,
            byte[] lpBuffer,
            uint nSize,
            ref uint lpNumberOfBytesRead
        )
        {
            bool ok = ReadProcessMemory(
                hProcess,
                new IntPtr((long)lpBaseAddress),
                lpBuffer,
                (UIntPtr)nSize,
                out UIntPtr bytesRead
            );

            lpNumberOfBytesRead = (uint)bytesRead;
            return ok;
        }


        // address -> IntPtr helper
        private static IntPtr AddrToIntPtr(ulong address)
        {
            return new IntPtr(unchecked((long)address));
        }

        private static bool ReadProcessMemoryW(IntPtr hProcess, ulong address, byte[] buffer, out uint bytesRead)
        {
            bool ok = ReadProcessMemory(hProcess, new IntPtr(unchecked((long)address)), buffer, (UIntPtr)buffer.Length, out UIntPtr read64);
            bytesRead = (uint)read64;
            return ok;
        }


        // wrapper: read with explicit length (UIntPtr)
        private static bool ReadProcessMemoryW(IntPtr hProcess, ulong address, byte[] buffer, UIntPtr size, out uint bytesRead)
        {
            bool ok = ReadProcessMemory(hProcess, AddrToIntPtr(address), buffer, size, out UIntPtr read64);
            bytesRead = (uint)read64;
            return ok;
        }
        public enum ProcessAccess
        {
            /// <summary>Enables usage of the process handle in the TerminateProcess function to terminate the process.</summary>
            Terminate = 0x1,
            /// <summary>Enables usage of the process handle in the CreateRemoteThread function to create a thread in the process.</summary>
            CreateThread = 0x2,
            /// <summary>Enables usage of the process handle in the VirtualProtectEx and WriteProcessMemory functions to modify the virtual memory of the process.</summary>
            VMOperation = 0x8,
            /// <summary>Enables usage of the process handle in the ReadProcessMemory function to' read from the virtual memory of the process.</summary>
            VMRead = 0x10,
            /// <summary>Enables usage of the process handle in the WriteProcessMemory function to write to the virtual memory of the process.</summary>
            VMWrite = 0x20,
            /// <summary>Enables usage of the process handle as either the source or target process in the DuplicateHandle function to duplicate a handle.</summary>
            DuplicateHandle = 0x40,
            /// <summary>Enables usage of the process handle in the SetPriorityClass function to set the priority class of the process.</summary>
            SetInformation = 0x200,
            /// <summary>Enables usage of the process handle in the GetExitCodeProcess and GetPriorityClass functions to read information from the process object.</summary>
            QueryInformation = 0x400,
            /// <summary>Enables usage of the process handle in any of the wait functions to wait for the process to terminate.</summary>
            Synchronize = 0x100000,
            /// <summary>Specifies all possible access flags for the process object.</summary>
            AllAccess = CreateThread | DuplicateHandle | QueryInformation | SetInformation | Terminate | VMOperation | VMRead | VMWrite | Synchronize
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_INFO
        {
            public ushort wProcessorArchitecture;
            public ushort wReserved;
            public uint dwPageSize;
            public IntPtr lpMinimumApplicationAddress;
            public IntPtr lpMaximumApplicationAddress;
            public UIntPtr dwActiveProcessorMask;
            public uint dwNumberOfProcessors;
            public uint dwProcessorType;
            public uint dwAllocationGranularity;
            public ushort wProcessorLevel;
            public ushort wProcessorRevision;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public ushort PartitionId;
            public IntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32")]
        public static extern void GetSystemInfo(ref SYSTEM_INFO pSI);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);


        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, int bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint PROCESS_TERMINATE = 0x0001;
        private const uint PROCESS_CREATE_THREAD = 0x0002;
        private const uint PROCESS_SET_SESSIONID = 0x0004;
        private const uint PROCESS_VM_OPERATION = 0x0008;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_DUP_HANDLE = 0x0040;
        private const uint PROCESS_CREATE_PROCESS = 0x0080;
        private const uint PROCESS_SET_QUOTA = 0x0100;
        private const uint PROCESS_SET_INFORMATION = 0x0200;
        private const uint PROCESS_QUERY_INFORMATION = 0x0400;

        // Memory state constants
        public const uint MEM_COMMIT = 0x1000;
        public const uint PAGE_NOACCESS = 0x01;
        public const uint PAGE_GUARD = 0x100;

        //inner enum used only internally
        [Flags]
        private enum SnapshotFlags : uint
        {
            HeapList = 0x00000001,
            Process = 0x00000002,
            Thread = 0x00000004,
            Module = 0x00000008,
            Module32 = 0x00000010,
            Inherit = 0x80000000,
            All = HeapList | Process | Thread | Module | Module32
        }
        //inner struct used only internally
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct PROCESSENTRY32
        {
            private const int MAX_PATH = 260;
            internal uint dwSize;
            internal uint cntUsage;
            internal uint th32ProcessID;
            internal IntPtr th32DefaultHeapID;
            internal uint th32ModuleID;
            internal uint cntThreads;
            internal uint th32ParentProcessID;
            internal int pcPriClassBase;
            internal uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
            internal string szExeFile;
        }

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern IntPtr CreateToolhelp32Snapshot([In] uint dwFlags, [In] uint th32ProcessID);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool Process32First([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool Process32Next([In] IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(IntPtr processHandle,
           int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, uint processInformationLength,
           out int returnLength);

        // Thread Access Rights
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetThreadContext")]
        private static extern bool GetThreadContext64(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "GetThreadContext")]
        private static extern bool GetThreadContext32(IntPtr hThread, ref CONTEXT32 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;
            public uint ContextFlags;
            public uint MxCsr;
            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;
            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;
            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;
            public ulong Rip;
            // ... vector registers omitted for brevity/relevance (we only need RIP) ...
            // Sufficient size buffer is needed if ContextFlags requests more.
            // But for simple Integer/Control, this matches standard layout until vector regs.
            // To be safe, we can add padding/dummy storage if GetThreadContext writes more.
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT32
        {
            public uint ContextFlags;
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            public FLOATING_SAVE_AREA FloatSave;
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint SegSs;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct FLOATING_SAVE_AREA
        {
            public uint ControlWord;
            public uint StatusWord;
            public uint TagWord;
            public uint ErrorOffset;
            public uint ErrorSelector;
            public uint DataOffset;
            public uint DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public uint Cr0NpxState;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        public MainForm()
        {
            //
            // The InitializeComponent() call is required for Windows Forms designer support.
            //
            InitializeComponent();

            //
            // TODO: Add constructor code after the InitializeComponent() call.
            //
        }

        #region New CLI Methods

        /// <summary>
        /// Performs a process dump from the command line, without UI interaction.
        /// </summary>
        /// <param name="processId">The ID of the process to dump.</param>
        /// <param name="outputDirectory">The root directory for the dump files.</param>
        /// <returns>A string indicating the result of the dump operation.</returns>
        public async Task<string> DumpProcessByIdCli(uint processId, string outputDirectory)
        {
            if (string.IsNullOrWhiteSpace(outputDirectory))
            {
                return "Error: Output directory must be provided.";
            }

            DUMP_DIRECTORIES ddirs = new() { root = outputDirectory };
            if (!CreateDirectoriesCli(ref ddirs))
            {
                return "Error: Could not create or access the output directory. Please check permissions and path.";
            }

            // The core dumping logic is already in DumpProcessLogic and is UI-agnostic.
            // Passed null for moduleMap as CLI might not need advanced naming or can be extended later
            string result = await Task.Run(() => DumpProcessLogic(processId, ddirs, true /* dumpNative */, true /* restoreFilename */, null));
            return result;
        }

        /// <summary>
        /// Creates dump directories without showing any UI dialogs. For CLI use.
        /// </summary>
        /// <param name="dpmdirs">The struct containing directory paths.</param>
        /// <returns>True if successful, false otherwise.</returns>
        public bool CreateDirectoriesCli(ref DUMP_DIRECTORIES dpmdirs)
        {
            SetDirectoriesPath(ref dpmdirs);
            try
            {
                Directory.CreateDirectory(dpmdirs.dumps);
                Directory.CreateDirectory(dpmdirs.nativedirname);
                Directory.CreateDirectory(dpmdirs.sysdirname);
                Directory.CreateDirectory(dpmdirs.unknowndirname);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Error] Failed to create directories: {ex.Message}");
                return false;
            }
        }
        #endregion

        private void Button1Click(object sender, EventArgs e)
        {
            Application.Exit();
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        public void OnTimerEvent(object source, EventArgs e)
        {
            uint[] oldproc = new uint[lvprocesslist.Items.Count];

            // get old list of process: 
            for (int i = 0; i < oldproc.Length; i++)
            {
                oldproc[i] = Convert.ToUInt32(lvprocesslist.Items[i].SubItems[1].Text);
            }

            uint[] processIds = new uint[0x200];
            int proccount = 0;

            try
            {
                IntPtr handleToSnapshot = IntPtr.Zero;
                PROCESSENTRY32 procEntry = new()
                {
                    dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32))
                };
                handleToSnapshot = CreateToolhelp32Snapshot((uint)SnapshotFlags.Process, 0);
                if (Process32First(handleToSnapshot, ref procEntry))
                {
                    do
                    {
                        bool isThere = false;

                        for (int i = 0; i < oldproc.Length; i++)
                        {
                            if (procEntry.th32ProcessID == oldproc[i])
                            {
                                isThere = true;
                                break;
                            }
                        }

                        // new process created ?
                        if (!isThere)
                        {
                            Process theProc = null;
                            string directoryName = "";
                            string processname = procEntry.szExeFile;
                            string isnet = "Unchecked";

                            try
                            {
                                theProc = Process.GetProcessById((int)procEntry.th32ProcessID);
                                if (theProc != null)  // Add null check here
                                {
                                    isnet = GetProcessType((int)procEntry.th32ProcessID);
                                }
                            }
                            catch
                            {
                                // Process.GetProcessById failed, theProc remains null
                            }

                            string rname = "";
                            try
                            {
                                // =================== FIX START ===================
                                // Check if theProc and its MainModule are not null before using them.
                                // This prevents a NullReferenceException for processes where the
                                // main module cannot be accessed (e.g., system processes, access denied).
                                if (theProc != null && theProc.MainModule != null)
                                {
                                    rname = theProc.MainModule.FileName.Replace("\\??\\", "");
                                    if (File.Exists(rname))
                                    {
                                        directoryName = Path.GetDirectoryName(rname);
                                    }
                                }
                                // =================== FIX END =====================
                            }
                            catch
                            {
                                // Catch exceptions that can occur when accessing MainModule,
                                // for example, Win32Exception for access denied.
                            }

                            // Close the process handle if it was successfully opened
                            if (theProc != null)
                            {
                                try
                                {
                                    theProc.Close();
                                }
                                catch
                                {
                                }
                            }

                            if (!File.Exists(rname) && Environment.OSVersion.Platform == PlatformID.Win32NT)
                            {
                                string newname = "";
                                try
                                {
                                    IntPtr hProcess =
                                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, procEntry.th32ProcessID);
                                    if (hProcess != IntPtr.Zero)
                                    {
                                        PROCESS_BASIC_INFORMATION pbi = new();
                                        int result = NtQueryInformationProcess(hProcess, 0, ref pbi, (uint)Marshal.SizeOf(pbi), out int bytesWritten);
                                        if (result >= 0)  // == 0 is OK
                                        {
                                            byte[] peb = new byte[472];
                                            uint BytesRead = 0;
                                            bool isok = ReadProcessMemory(hProcess, (ulong)pbi.PebBaseAddress, peb, (uint)peb.Length, ref BytesRead);
                                            if (isok)
                                            {
                                                // this is on all Windows NT version - including Windows 7/Vista
                                                IntPtr AProcessParameters = (IntPtr)BitConverter.ToInt32(peb, 016);

                                                byte[] ProcessParameters = new byte[72];
                                                isok = ReadProcessMemory(hProcess, (ulong)AProcessParameters, ProcessParameters, (uint)ProcessParameters.Length, ref BytesRead);
                                                if (isok)
                                                {
                                                    int aCurrentDirectory = BitConverter.ToInt32(ProcessParameters, 040);
                                                    byte[] Forread = new byte[2];
                                                    int size = 0;

                                                    do
                                                    {
                                                        isok = ReadProcessMemory(hProcess, (ulong)(aCurrentDirectory + size), Forread, 2, ref BytesRead);
                                                        size += 2;
                                                    }
                                                    while (isok && Forread[0] != 0);
                                                    size -= 2;
                                                    byte[] CurrentDirectory = new byte[size];
                                                    isok = ReadProcessMemory(hProcess, (ulong)aCurrentDirectory, CurrentDirectory, (uint)size, ref BytesRead);
                                                    newname = System.Text.Encoding.Unicode.GetString(CurrentDirectory);
                                                    if (newname.Length >= 3)
                                                    {
                                                        newname = newname.Replace("\\??\\", "");
                                                        directoryName = newname;
                                                    }
                                                }
                                            }
                                        }
                                        CloseHandle(hProcess);
                                    }
                                }
                                catch
                                {
                                }
                            }

                            // compute size:
                            Graphics g = lvprocesslist.CreateGraphics();
                            Font objFont = new("Microsoft Sans Serif", 8);
                            SizeF stringSize = new();
                            stringSize = g.MeasureString(processname, objFont);
                            int processlenght = (int)(stringSize.Width + (lvprocesslist.Margin.Horizontal * 2)) + 5;
                            stringSize = g.MeasureString(directoryName, objFont);
                            int directorylenght = (int)(stringSize.Width + (lvprocesslist.Margin.Horizontal * 2)) + 40;

                            if (processlenght > procname.Width)
                            {
                                procname.Width = processlenght;
                            }

                            if (directorylenght > location.Width)
                            {
                                location.Width = directorylenght;
                            }

                            string[] prcdetails = new string[] { processname, procEntry.th32ProcessID.ToString(), "", isnet, directoryName };
                            ListViewItem proc = new(prcdetails);
                            lvprocesslist.Items.Add(proc);
                        }
                        else
                        {
                            proccount++;
                            processIds[proccount] = procEntry.th32ProcessID;
                        }

                    } while (Process32Next(handleToSnapshot, ref procEntry));
                }
                CloseHandle(handleToSnapshot);
            }
            catch
            {
            }

            // check statut of old processes: 
            for (int i = 0; i < oldproc.Length; i++)
            {
                bool isThere = false;
                for (int j = 0; j < processIds.Length; j++)
                {
                    if (oldproc[i] == processIds[j])
                        isThere = true;
                }

                if (!isThere && lvprocesslist.Items.Count > i && lvprocesslist.Items[i].SubItems.Count > 2 && lvprocesslist.Items[i].SubItems[2].Text != "Killed")
                {
                    lvprocesslist.Items[i].SubItems[2].Text = "Killed";
                }
            }
        }

        private bool CheckAdvancedPEStructure(IntPtr hProcess, ulong baseAddress, int peOffset)
        {
            try
            {
                // Read PE headers for validation
                byte[] peHeaders = new byte[256];
                uint bytesRead = 0;

                // Read the PE header structure
                try
                {
                    if (ReadProcessMemory(hProcess, baseAddress + (uint)peOffset, peHeaders, 256, ref bytesRead) && bytesRead >= 24)
                    {
                        // Validate PE signature (already checked, but double-check)
                        if (peHeaders[0] != 0x50 || peHeaders[1] != 0x45) // "PE"
                            return false;

                        // Read COFF Header (IMAGE_FILE_HEADER)
                        short machine = BitConverter.ToInt16(peHeaders, 4);
                        short numberOfSections = BitConverter.ToInt16(peHeaders, 6);
                        short sizeOfOptionalHeader = BitConverter.ToInt16(peHeaders, 20);
                        short characteristics = BitConverter.ToInt16(peHeaders, 22);

                        // Validate machine type (x86, x64, ARM, etc.)
                        if (!IsValidMachineType((ushort)machine))
                            return false;

                        // Validate section count (reasonable range)
                        if (numberOfSections <= 0 || numberOfSections > 96)
                            return false;

                        // Validate optional header magic and size
                        ushort optHeaderMagic = BitConverter.ToUInt16(peHeaders, 24);
                        if (optHeaderMagic == 0x10B) // PE32
                        {
                            if (sizeOfOptionalHeader < 224) return false;
                        }
                        else if (optHeaderMagic == 0x20B) // PE32+
                        {
                            if (sizeOfOptionalHeader < 240) return false;
                        }
                        else
                        {
                            return false; // Unknown magic
                        }

                        // Check if it's an executable image
                        if ((characteristics & 0x0002) == 0) // IMAGE_FILE_EXECUTABLE_IMAGE not set
                        {
                            // Still might be valid if it's a DLL
                            if ((characteristics & 0x2000) == 0) // IMAGE_FILE_DLL not set either
                                return false;
                        }

                        return true;
                    }
                }
                catch (System.ComponentModel.Win32Exception)
                {
                }
                return false;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                return false;
            }
            catch
            {
                return false;
            }
        }

        private bool IsValidMachineType(ushort machine)
        {
            switch (machine)
            {
                case 0x014c: // x86
                case 0x8664: // x64
                case 0x01c0: // ARM
                case 0xaa64: // ARM64
                case 0x0200: // IA64
                case 0x01c4: // ARMNT
                    return true;
                default:
                    return false;
            }
        }

        public bool IsPEProcess(int processid)
        {
            try
            {
                // First try the simple approach
                if (SimplePECheck(processid))
                    return true;

                // Then try module enumeration 
                try
                {
                    ProcModule.ModuleInfo[] modules = ProcModule.GetModuleInfos(processid);

                    if (modules != null)
                    {
                        // Look for common executable extensions and system modules
                        for (int i = 0; i < modules.Length; i++)
                        {
                            if (!string.IsNullOrEmpty(modules[i].baseName))
                            {
                                string lowerfn = modules[i].baseName.ToLower();

                                // Check for PE file extensions
                                if (lowerfn.EndsWith(".exe") || lowerfn.EndsWith(".dll") ||
                                    lowerfn.EndsWith(".sys") || lowerfn.EndsWith(".ocx"))
                                    return true;

                                // Check for Windows system modules (indicates PE process)
                                if (lowerfn.Contains("kernel32.dll") || lowerfn.Contains("ntdll.dll") ||
                                    lowerfn.Contains("user32.dll") || lowerfn.Contains("advapi32.dll"))
                                    return true;
                            }
                        }
                    }
                }
                catch
                {
                    // Any other error in module enumeration
                }

                // Last resort: try memory scanning for PE headers
                try
                {
                    return SafePEMemoryCheck(processid);
                }
                catch
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }

        public string GetProcessType(int processid)
        {
            try
            {
                // Verify access rights first
                using (var p = Process.GetProcessById(processid))
                {
                    if (p == null) return "Unchecked";
                }
            }
            catch
            {
                return "Unchecked";
            }

            try
            {
                bool isNet = false;
                bool isPe = false;

                // check modules
                try
                {
                    ProcModule.ModuleInfo[] modules = ProcModule.GetModuleInfos(processid);
                    if (modules != null)
                    {
                        foreach (var m in modules)
                        {
                            if (string.IsNullOrEmpty(m.baseName)) continue;
                            string lower = m.baseName.ToLower();

                            if (lower.Contains("mscorlib.dll") || lower.Contains("clr.dll") || lower.Contains("coreclr.dll"))
                            {
                                isNet = true;
                                break;
                            }

                            if (lower.EndsWith(".exe") || lower.EndsWith(".dll") || lower.EndsWith(".sys"))
                                isPe = true;
                        }
                    }
                }
                catch { }

                if (isNet) return ".NET";

                // If not .NET, check if it's Native PE
                if (isPe || IsPEProcess(processid)) return "PE Native";

                return "Unchecked";
            }
            catch
            {
                return "Unchecked";
            }
        }

        private bool SimplePECheck(int processId)
        {
            try
            {
                Process process;
                try
                {
                    process = Process.GetProcessById(processId);
                }
                catch (ArgumentException)
                {
                    // Invalid pid
                    return false;
                }
                catch
                {
                    // Can't get the process -> treat as not PE
                    return false;
                }

                if (process == null)
                    return false;

                try
                {
                    // If the process has exited, it's not a running PE process.
                    if (process.HasExited)
                        return false;
                }
                catch
                {
                    // If we can't determine exited state, fall through and assume it's a PE process.
                }

                try
                {
                    // Accessing Handle is cheap compared to Modules/MainModule and typically doesn't hang.
                    var h = process.Handle;
                    if (h == IntPtr.Zero)
                        return false;

                    // We explicitly DO NOT touch process.MainModule or process.Modules here.
                    // If we can open a handle to the process, assume it's a PE process (per your permission to assume).
                    return true;
                }
                catch (Win32Exception)
                {
                    // Access denied or architecture mismatch — you allowed to assume in this case.
                    return true;
                }
                catch
                {
                    // Any other unexpected failure -> be conservative and assume false.
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }

        private bool SafePEMemoryCheck(int processId)
        {
            IntPtr hProcess = IntPtr.Zero;
            try
            {
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, (uint)processId);
                if (hProcess == IntPtr.Zero) return false;

                // Basic check - if we can access the process, assume it's PE
                return true;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                return false;
            }
            finally
            {
                if (hProcess != IntPtr.Zero)
                {
                    try { CloseHandle(hProcess); } catch { }
                }
            }
        }

        public Timer timer1;
        private void EnumProcesses()
        {
            if (timer1 == null)
            {
                timer1 = new Timer
                {
                    Interval = 100,
                    Enabled = true
                };
                timer1.Tick += OnTimerEvent;
            }

            lvprocesslist.Items.Clear();
            Process theProc = null;

            string directoryName = "";
            string processname = "";
            string isnet = "Unchecked";

            /*
            IMO the key difference is in priviledges requirements.
            I've seen cases in which EnumProcesses() would fail,
            but CreateToolhelp32Snapshot() ran perfectly well.
            */
            try
            {
                IntPtr handleToSnapshot = IntPtr.Zero;
                PROCESSENTRY32 procEntry = new()
                {
                    dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32))
                };
                handleToSnapshot = CreateToolhelp32Snapshot((uint)SnapshotFlags.Process, 0);
                if (Process32First(handleToSnapshot, ref procEntry))
                {
                    do
                    {
                        directoryName = "";
                        processname = procEntry.szExeFile;
                        const string statut = "";//exited
                        try
                        {
                            theProc = Process.GetProcessById((int)procEntry.th32ProcessID);

                            isnet = GetProcessType((int)procEntry.th32ProcessID);
                        }
                        catch
                        {
                        }

                        string rname = "";
                        try
                        {
                            if (theProc != null && theProc.MainModule != null)
                            {
                                rname = theProc.MainModule.FileName.Replace("\\??\\", "");
                                if (File.Exists(rname))
                                {
                                    directoryName = Path.GetDirectoryName(rname);
                                }
                            }
                        }
                        catch
                        {
                        }

                        if (theProc != null)
                        {
                            theProc.Close();
                        }


                        if (!File.Exists(rname) && Environment.OSVersion.Platform == PlatformID.Win32NT)
                        {
                            string newname = "";
                            try
                            {
                                IntPtr hProcess =
                                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, procEntry.th32ProcessID);
                                if (hProcess != IntPtr.Zero)
                                {
                                    PROCESS_BASIC_INFORMATION pbi = new();
                                    int result = NtQueryInformationProcess(hProcess, 0, ref pbi, (uint)Marshal.SizeOf(pbi), out int bytesWritten);
                                    if (result >= 0) // 0 is STATUS_SUCCESS
                                    {
                                        byte[] peb = new byte[472];
                                        uint bytesRead = 0;
                                        bool isok = ReadProcessMemory(hProcess, (ulong)pbi.PebBaseAddress, peb, (uint)peb.Length, ref bytesRead);
                                        if (isok)
                                        {
                                            // --- pointer-size-aware PEB -> ProcessParameters -> CurrentDirectory read ---
                                            int pebProcessParametersOffset = 16; // 0x10

                                            // Read ProcessParameters pointer from PEB depending on pointer size
                                            IntPtr processParametersPtr;
                                            if (IntPtr.Size == 8)
                                            {
                                                long pp = BitConverter.ToInt64(peb, pebProcessParametersOffset);
                                                processParametersPtr = new IntPtr(pp);
                                            }
                                            else
                                            {
                                                int pp = BitConverter.ToInt32(peb, pebProcessParametersOffset);
                                                processParametersPtr = new IntPtr(pp);
                                            }

                                            // Read a portion of RTL_USER_PROCESS_PARAMETERS (enough to get CurrentDirectory pointer)
                                            byte[] processParametersBuf = new byte[72];
                                            isok = ReadProcessMemory(hProcess, (ulong)processParametersPtr, processParametersBuf, (uint)processParametersBuf.Length, ref bytesRead);
                                            if (isok)
                                            {
                                                // Keep the offset you were using previously
                                                int processParametersCurrentDirectoryOffset = 40;
                                                IntPtr aCurrentDirectoryPtr;
                                                if (IntPtr.Size == 8)
                                                {
                                                    long tmp = BitConverter.ToInt64(processParametersBuf, processParametersCurrentDirectoryOffset);
                                                    aCurrentDirectoryPtr = new IntPtr(tmp);
                                                }
                                                else
                                                {
                                                    int tmp = BitConverter.ToInt32(processParametersBuf, processParametersCurrentDirectoryOffset);
                                                    aCurrentDirectoryPtr = new IntPtr(tmp);
                                                }

                                                if (aCurrentDirectoryPtr != IntPtr.Zero)
                                                {
                                                    long cdAddr = aCurrentDirectoryPtr.ToInt64();

                                                    // Probe to determine the length of the remote Unicode string (2 bytes per code unit)
                                                    byte[] probeBuf = new byte[2];
                                                    int size = 0;
                                                    while (true)
                                                    {
                                                        IntPtr probeAddr = new IntPtr(unchecked((long)(cdAddr + size)));
                                                        uint innerBytesRead = 0;
                                                        bool probeOk = ReadProcessMemory(hProcess, (ulong)probeAddr, probeBuf, 2, ref innerBytesRead);
                                                        if (!probeOk) break;
                                                        // stop when we hit a two-byte null (unicode terminator)
                                                        if (probeBuf[0] == 0 && probeBuf[1] == 0) break;
                                                        size += 2;
                                                        // guard against unreasonable lengths
                                                        if (size > 65536) break;
                                                    }

                                                    if (size > 0)
                                                    {
                                                        byte[] currentDirectory = new byte[size];
                                                        isok = ReadProcessMemory(hProcess, (ulong)cdAddr, currentDirectory, (uint)size, ref bytesRead);
                                                        if (isok)
                                                        {
                                                            // decode, normalize and assign
                                                            string dirCandidate = System.Text.Encoding.Unicode.GetString(currentDirectory);
                                                            if (!string.IsNullOrEmpty(dirCandidate) && dirCandidate.Length >= 3)
                                                            {
                                                                dirCandidate = dirCandidate.Replace("\\??\\", "");
                                                                directoryName = dirCandidate;
                                                                newname = dirCandidate;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    CloseHandle(hProcess);
                                }
                            }
                            catch
                            {
                                // swallow exceptions (as in original)
                            }
                        }

                        // compute size:
                        Graphics g = lvprocesslist.CreateGraphics();
                        Font objFont = new("Microsoft Sans Serif", 8);
                        SizeF stringSize = new();
                        stringSize = g.MeasureString(processname, objFont);
                        int processlenght = (int)(stringSize.Width + (lvprocesslist.Margin.Horizontal * 2)) + 5;
                        stringSize = g.MeasureString(directoryName, objFont);
                        int directorylenght = (int)(stringSize.Width + (lvprocesslist.Margin.Horizontal * 2)) + 40;

                        if (processlenght > procname.Width)
                        {
                            procname.Width = processlenght;
                        }

                        if (directorylenght > location.Width)
                        {
                            location.Width = directorylenght;
                        }

                        string[] prcdetails = new string[] { processname, procEntry.th32ProcessID.ToString(), statut, isnet, directoryName };
                        ListViewItem proc = new(prcdetails);
                        lvprocesslist.Items.Add(proc);

                    } while (Process32Next(handleToSnapshot, ref procEntry));
                }
                CloseHandle(handleToSnapshot);
            }
            catch
            {
            }
        }

        private void MainFormLoad(object sender, EventArgs e)
        {
            EnableDebuggerPrivileges();
            EnumProcesses();
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public long Luid;
            public int Attributes;
        }

        private const int SE_PRIVILEGE_ENABLED = 0x00000002;
        private const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
        private const int TOKEN_QUERY = 0x00000008;

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, ref int tokenhandle);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int LookupPrivilegeValue(string lpsystemname, string lpname, ref long lpLuid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int AdjustTokenPrivileges(int tokenhandle, int disableprivs, ref TOKEN_PRIVILEGES Newstate, int bufferlength, int PreivousState, int Returnlength);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int GetSecurityInfo(int HANDLE, int SE_OBJECT_TYPE, int SECURITY_INFORMATION, int psidOwner, int psidGroup, out IntPtr pDACL, IntPtr pSACL, out IntPtr pSecurityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern int SetSecurityInfo(int HANDLE, int SE_OBJECT_TYPE, int SECURITY_INFORMATION, int psidOwner, int psidGroup, IntPtr pDACL, IntPtr pSACL);

        internal void EnableDebuggerPrivileges()
        {
            try
            {
                int token = 0;
                TOKEN_PRIVILEGES tp = new()
                {
                    PrivilegeCount = 1,
                    Luid = 0,
                    Attributes = SE_PRIVILEGE_ENABLED
                };

                // We just assume this works
                if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref token) == 0)
                    return;

                if (LookupPrivilegeValue(null, "SeDebugPrivilege", ref tp.Luid) == 0)
                    return;

                if (AdjustTokenPrivileges(token, 0, ref tp, Marshal.SizeOf(tp), 0, 0) == 0)
                    return;
            }
            catch
            {
            }
        }

        private async void DumpToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count == 0)
                return;

            int selectedIndex = lvprocesslist.SelectedIndices[0];
            uint processId = Convert.ToUInt32(lvprocesslist.Items[selectedIndex].SubItems[1].Text);
            string dirname = lvprocesslist.Items[selectedIndex].SubItems[4].Text;
            bool dumpNative = dumpNativeToolStripMenuItem.Checked;
            bool restoreFilename = !dontRestoreFilenameToolStripMenuItem.Checked;

            if (string.IsNullOrWhiteSpace(dirname) || !Directory.Exists(Path.GetPathRoot(dirname)))
                dirname = "C:\\";

            DUMP_DIRECTORIES ddirs = new() { root = dirname };
            if (!CreateDirectories(ref ddirs))
            {
                MessageBox.Show("Could not create or select a valid dump directory. Aborting.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            // =================== FIX START: MODULE MAPPING ===================
            // Pre-fetch module names to solve "UnknownName" issues for native files.
            // If the header dump is slightly off, we can still know the name by address.
            Dictionary<ulong, string> moduleMap = new Dictionary<ulong, string>();
            try
            {
                Process p = Process.GetProcessById((int)processId);
                foreach (ProcessModule m in p.Modules)
                {
                    // key: BaseAddress, value: ModuleName
                    if (!moduleMap.ContainsKey((ulong)m.BaseAddress))
                        moduleMap.Add((ulong)m.BaseAddress, m.ModuleName);
                }
            }
            catch { }
            // =================== FIX END =====================

            string originalTitle = Text;
            Text = "Dumping process... please wait.";
            Cursor = Cursors.WaitCursor;

            try
            {
                string result = await Task.Run(() => DumpProcessLogic(processId, ddirs, dumpNative, restoreFilename, moduleMap));
                MessageBox.Show(result, "Success!", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("An error occurred during the dump process:\n" + ex.Message, "Error!", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                Text = originalTitle;
                Cursor = Cursors.Default;
            }
        }

        public int RVA2Offset(byte[] input, int rva)
        {
            // Minimum size check for DOS header (0x3C) and PE header offset (4 bytes)
            if (input == null || input.Length < 0x3C + 4) return -1;

            int PEOffset = BitConverter.ToInt32(input, 0x3C);
            // Basic sanity check for PEOffset
            if (PEOffset < 0 || PEOffset >= input.Length) return -1;

            // Minimum size check for COFF header (0x06) and NumberOfSections (2 bytes)
            if (input.Length < PEOffset + 0x06 + 2) return -1;
            int nrofsection = BitConverter.ToInt16(input, PEOffset + 0x06);
            // Sanity check for number of sections
            if (nrofsection <= 0 || nrofsection > 96) return -1;

            // Get SizeOfOptionalHeader to correctly calculate section table offset
            // This works for both PE32 (32-bit) and PE32+ (64-bit)
            if (input.Length < PEOffset + 0x14 + 2) return -1;
            short sizeOfOptionalHeader = BitConverter.ToInt16(input, PEOffset + 0x14);

            int sectionTableStartOffset = PEOffset + 4 + 20 + sizeOfOptionalHeader;

            for (int i = 0; i < nrofsection; i++)
            {
                // Each IMAGE_SECTION_HEADER is 0x28 bytes long
                int sectionHeaderOffset = sectionTableStartOffset + (0x28 * i);

                // Ensure there's enough room for the current section header (40 bytes)
                if (input.Length < sectionHeaderOffset + 0x28) return -1;

                // VirtualAddress is at offset 0x0C from section header start (4 bytes)
                int virtualAddress = BitConverter.ToInt32(input, sectionHeaderOffset + 0x0C);
                // VirtualSize is at offset 0x08 from section header start (4 bytes)
                int fvirtualsize = BitConverter.ToInt32(input, sectionHeaderOffset + 0x08);
                // SizeOfRawData is at offset 0x10 from section header start (4 bytes)
                int frawsize = BitConverter.ToInt32(input, sectionHeaderOffset + 0x10);
                // PointerToRawData is at offset 0x14 from section header start (4 bytes)
                int frawAddress = BitConverter.ToInt32(input, sectionHeaderOffset + 0x14);

                // Use the larger of VirtualSize or SizeOfRawData for bounds checking
                // This handles sections where VirtualSize is 0 (common in Scylla-created sections)
                int effectiveSize = Math.Max(fvirtualsize, frawsize);
                if (effectiveSize <= 0) effectiveSize = frawsize > 0 ? frawsize : fvirtualsize;

                if ((virtualAddress <= rva) && (virtualAddress + effectiveSize >= rva))
                    return frawAddress + (rva - virtualAddress);
            }

            return -1;
        }

        public int Offset2RVA(byte[] input, int offset)
        {
            if (input == null || input.Length < 0x3C + 4) return -1;

            int PEOffset = BitConverter.ToInt32(input, 0x3C);
            if (PEOffset < 0 || PEOffset >= input.Length) return -1;

            if (input.Length < PEOffset + 0x06 + 2) return -1;
            int nrofsection = BitConverter.ToInt16(input, PEOffset + 0x06);
            if (nrofsection <= 0 || nrofsection > 96) return -1;

            // Assuming a standard 32-bit PE header structure, 0xF8 is a common offset
            // to the start of the section table after the PE signature, COFF header, and optional header.
            int sectionTableStartOffset = PEOffset + 0xF8;

            for (int i = 0; i < nrofsection; i++)
            {
                int sectionHeaderOffset = sectionTableStartOffset + (0x28 * i);

                if (input.Length < sectionHeaderOffset + 0x28) return -1;

                // SizeOfRawData is at offset 0x10 from section header start (4 bytes)
                int virtualAddress = BitConverter.ToInt32(input, sectionHeaderOffset + 0x0C);
                int frawsize = BitConverter.ToInt32(input, sectionHeaderOffset + 0x10);
                // PointerToRawData is at offset 0x14 from section header start (4 bytes)
                int frawAddress = BitConverter.ToInt32(input, sectionHeaderOffset + 0x14);

                if ((frawAddress <= offset) && (frawAddress + frawsize >= offset))
                    return virtualAddress + (offset - frawAddress);
            }

            return -1;
        }

        /// <summary>
        /// Sanitizes a Scylla-fixed PE file by removing invalid import descriptors.
        /// This is necessary because Scylla's advanced search can generate garbage imports
        /// with DLL names like "?.DLL" or containing unprintable characters.
        /// This function COMPACTS valid imports together (doesn't just zero invalid ones).
        /// </summary>
        /// <param name="filePath">Path to the scyfix file to sanitize</param>
        /// <returns>True if sanitization was successful or no changes were needed</returns>
        private bool SanitizeScyfixFile(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return false;

                byte[] fileData = File.ReadAllBytes(filePath);
                if (fileData.Length < 0x40) return false;

                int peOffset = BitConverter.ToInt32(fileData, 0x3C);
                if (peOffset < 0 || peOffset + 0x80 + 8 > fileData.Length) return false;

                if (fileData[peOffset] != 'P' || fileData[peOffset + 1] != 'E') return false;

                // Determine if PE32 or PE32+ (64-bit)
                ushort magic = BitConverter.ToUInt16(fileData, peOffset + 0x18);
                bool isPE32Plus = magic == 0x20b;

                // Import directory offset differs between PE32 and PE32+
                int importDirRvaOffset = isPE32Plus ? (peOffset + 0x90) : (peOffset + 0x80);

                if (importDirRvaOffset + 8 > fileData.Length) return false;

                int importDirRva = BitConverter.ToInt32(fileData, importDirRvaOffset);
                int importDirSize = BitConverter.ToInt32(fileData, importDirRvaOffset + 4);

                if (importDirRva == 0 || importDirSize == 0) return true;

                int importDirOffset = RVA2Offset(fileData, importDirRva);
                if (importDirOffset < 0 || importDirOffset >= fileData.Length) return false;

                const int IMPORT_DESCRIPTOR_SIZE = 20;

                var allDescriptors = new System.Collections.Generic.List<byte[]>();
                var validDescriptors = new System.Collections.Generic.List<byte[]>();
                var invalidNames = new System.Collections.Generic.List<string>();
                int current = 0;

                // Parse all import descriptors
                while (importDirOffset + current + IMPORT_DESCRIPTOR_SIZE <= fileData.Length)
                {
                    // Read the descriptor
                    byte[] descriptor = new byte[IMPORT_DESCRIPTOR_SIZE];
                    Array.Copy(fileData, importDirOffset + current, descriptor, 0, IMPORT_DESCRIPTOR_SIZE);

                    // Check if this is a null terminator (all zeros)
                    int nameRva = BitConverter.ToInt32(descriptor, 12);
                    if (nameRva == 0) break;

                    allDescriptors.Add(descriptor);

                    // Get the DLL name
                    int nameOffset = RVA2Offset(fileData, nameRva);
                    bool isValid = true;
                    string dllName = "<unknown>";

                    if (nameOffset < 0 || nameOffset >= fileData.Length)
                    {
                        isValid = false;
                    }
                    else
                    {
                        // Read the DLL name (null-terminated ASCII string)
                        var sb = new System.Text.StringBuilder();
                        int maxLen = Math.Min(260, fileData.Length - nameOffset);
                        for (int i = 0; i < maxLen; i++)
                        {
                            byte b = fileData[nameOffset + i];
                            if (b == 0) break;
                            sb.Append((char)b);
                        }
                        dllName = sb.ToString();

                        // Check if DLL name is valid
                        // Invalid if: empty, contains '?', has unprintable chars, or doesn't end with .dll
                        if (string.IsNullOrEmpty(dllName) ||
                            dllName.Contains("?") ||
                            dllName.Any(c => c < 32 || c > 126) ||
                            !dllName.ToLower().EndsWith(".dll"))
                        {
                            isValid = false;
                        }
                    }

                    if (isValid)
                        validDescriptors.Add(descriptor);
                    else
                        invalidNames.Add(dllName);

                    current += IMPORT_DESCRIPTOR_SIZE;
                }

                // Check if we need to modify the file
                if (invalidNames.Count == 0) return true;

                // Second pass: Write valid descriptors contiguously, then null terminator
                int writeOffset = importDirOffset;

                // Write all valid descriptors
                foreach (var descriptor in validDescriptors)
                {
                    if (writeOffset + IMPORT_DESCRIPTOR_SIZE <= fileData.Length)
                    {
                        Array.Copy(descriptor, 0, fileData, writeOffset, IMPORT_DESCRIPTOR_SIZE);
                        writeOffset += IMPORT_DESCRIPTOR_SIZE;
                    }
                }

                // Write null terminator (20 zero bytes)
                for (int i = 0; i < IMPORT_DESCRIPTOR_SIZE; i++)
                {
                    if (writeOffset + i < fileData.Length)
                    {
                        fileData[writeOffset + i] = 0;
                    }
                }
                writeOffset += IMPORT_DESCRIPTOR_SIZE;

                // Zero out any remaining space that was used by old descriptors
                int oldEndOffset = importDirOffset + (allDescriptors.Count + 1) * IMPORT_DESCRIPTOR_SIZE;
                for (int i = writeOffset; i < oldEndOffset && i < fileData.Length; i++)
                {
                    fileData[i] = 0;
                }

                // Write the sanitized file
                File.WriteAllBytes(filePath, fileData);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public unsafe struct image_section_header
        {
            public fixed byte name[8];
            public int virtual_size;
            public int virtual_address;
            public int size_of_raw_data;
            public int pointer_to_raw_data;
            public int pointer_to_relocations;
            public int pointer_to_linenumbers;
            public short number_of_relocations;
            public short number_of_linenumbers;
            public int characteristics;
        };

        public struct IMAGE_FILE_HEADER
        {
            public short Machine;
            public short NumberOfSections;
            public int TimeDateStamp;
            public int PointerToSymbolTable;
            public int NumberOfSymbols;
            public short SizeOfOptionalHeader;
            public short Characteristics;
        }

        private int ReadInt32Safe(byte[] buffer, int offset, int defaultValue = -1)
        {
            if (buffer == null || offset < 0 || offset + 4 > buffer.Length)
            {
                return defaultValue;
            }
            return BitConverter.ToInt32(buffer, offset);
        }

        private short ReadInt16Safe(byte[] buffer, int offset, short defaultValue = -1)
        {
            if (buffer == null || offset < 0 || offset + 2 > buffer.Length)
            {
                return defaultValue;
            }
            return BitConverter.ToInt16(buffer, offset);
        }

        /// <summary>
        /// Checks if a file is a valid .NET assembly by inspecting headers.
        /// </summary>
        private bool IsDotNetAssembly(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return false;
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
                {
                    if (fs.Length < 64) return false;
                    BinaryReader br = new BinaryReader(fs);

                    // PE offset
                    fs.Seek(0x3C, SeekOrigin.Begin);
                    int peOffset = br.ReadInt32();
                    if (peOffset < 0 || peOffset + 24 > fs.Length) return false;

                    // Magic
                    fs.Seek(peOffset + 24, SeekOrigin.Begin);
                    ushort magic = br.ReadUInt16();

                    // Offset to Data Directories (Magic 0x10B = 96, 0x20B = 112)
                    int dataDirOffset = (magic == 0x10B) ? 96 : 112;
                    int clrHeaderDirIndex = 14;

                    // Go to COM Descriptor Directory (index 14)
                    // OptionalHeader + DataDirectory Start
                    fs.Seek(peOffset + 24 + dataDirOffset + (clrHeaderDirIndex * 8), SeekOrigin.Begin);

                    uint rva = br.ReadUInt32();
                    uint size = br.ReadUInt32();

                    return (rva != 0 && size != 0);
                }
            }
            catch { return false; }
        }

        public bool FixImportandEntryPoint(long dumpVA, byte[] Dump)
        {
            // CRITICAL: Robust bounds checking to prevent native corruption
            if (Dump == null || Dump.Length < 0x200) return false;

            int PEOffset = ReadInt32Safe(Dump, 0x3C);
            if (PEOffset < 0 || PEOffset >= Dump.Length - 0x100) return false;

            // Detect architecture
            ushort magic = (ushort)ReadInt16Safe(Dump, PEOffset + 24);
            bool isPE64 = (magic == 0x20B);

            // === STRICT VALIDATION: Ensure this looks like .NET before patching ===
            // This is "Improved Extraction" for non-.NET files by NOT breaking them.
            // Check Data Directory 14 (CLR Runtime Header)
            int dataDirOffset = (magic == 0x10B) ? 96 : 112;
            int clrDirOffset = PEOffset + 24 + dataDirOffset + (14 * 8);

            if (clrDirOffset + 8 > Dump.Length) return false;

            int clrRva = ReadInt32Safe(Dump, clrDirOffset);
            int clrSize = ReadInt32Safe(Dump, clrDirOffset + 4);

            // If CLR Header is empty, it is definitely NOT .NET. Stop here.
            if (clrRva == 0 || clrSize == 0) return false;
            // ======================================================================

            int ImportDirectoryRva = ReadInt32Safe(Dump, PEOffset + (isPE64 ? 0x090 : 0x080));
            int impdiroffset = RVA2Offset(Dump, ImportDirectoryRva);
            if (impdiroffset == -1) return false;

            byte[] mscoreeAscii = { 0x6D, 0x73, 0x63, 0x6F, 0x72, 0x65, 0x65, 0x2E, 0x64, 0x6C, 0x6C, 0x00 }; // mscoree.dll
            byte[] CorExeMain = { 0x5F, 0x43, 0x6F, 0x72, 0x45, 0x78, 0x65, 0x4D, 0x61, 0x69, 0x6E, 0x00 }; // _CorExeMain
            byte[] CorDllMain = { 0x5F, 0x43, 0x6F, 0x72, 0x44, 0x6C, 0x6C, 0x4D, 0x61, 0x69, 0x6E, 0x00 }; // _CorDllMain
            int ThunkToFix = 0;
            long ThunkData = 0;
            int current = 0;

            while (impdiroffset + current + 20 <= Dump.Length)
            {
                int NameRVA = ReadInt32Safe(Dump, impdiroffset + current + 12);
                if (NameRVA <= 0) break;

                int NameOffset = RVA2Offset(Dump, NameRVA);
                if (NameOffset == -1) { current += 20; continue; }

                bool ismscoree = true;
                for (int i = 0; i < mscoreeAscii.Length; i++)
                {
                    if (NameOffset + i >= Dump.Length || Dump[NameOffset + i] != mscoreeAscii[i])
                    {
                        ismscoree = false;
                        break;
                    }
                }

                if (ismscoree)
                {
                    int OriginalFirstThunk = ReadInt32Safe(Dump, impdiroffset + current);
                    int OriginalFirstThunkfo = RVA2Offset(Dump, OriginalFirstThunk);
                    if (OriginalFirstThunkfo == -1) { current += 20; continue; }

                    if (isPE64)
                        ThunkData = BitConverter.ToInt64(Dump, OriginalFirstThunkfo);
                    else
                        ThunkData = BitConverter.ToInt32(Dump, OriginalFirstThunkfo);

                    int ThunkDatafo = RVA2Offset(Dump, (int)(ThunkData & 0xFFFFFFFF));
                    if (ThunkDatafo == -1) { current += 20; continue; }

                    ismscoree = true;
                    for (int i = 0; i < CorExeMain.Length; i++)
                    {
                        if (ThunkDatafo + 2 + i >= Dump.Length || (Dump[ThunkDatafo + 2 + i] != CorExeMain[i] && Dump[ThunkDatafo + 2 + i] != CorDllMain[i]))
                        {
                            ismscoree = false;
                            break;
                        }
                    }

                    if (ismscoree)
                    {
                        ThunkToFix = ReadInt32Safe(Dump, impdiroffset + current + 16);
                        break;
                    }
                }
                current += 20;
            }

            if (ThunkToFix <= 0 || ThunkData == 0) return false;

            int ThunkToFixfo = RVA2Offset(Dump, ThunkToFix);
            if (ThunkToFixfo == -1) return false;

            using var ms = new MemoryStream(Dump);
            BinaryWriter writer = new(ms);

            long currentThunkValue = isPE64 ? BitConverter.ToInt64(Dump, ThunkToFixfo) : BitConverter.ToInt32(Dump, ThunkToFixfo);
            if (currentThunkValue <= 0 || RVA2Offset(Dump, (int)(currentThunkValue & 0xFFFFFFFF)) == -1)
            {
                ms.Position = ThunkToFixfo;
                if (isPE64)
                    writer.Write((long)ThunkData);
                else
                    writer.Write((int)ThunkData);
            }

            int EntryPointOffset = PEOffset + 0x028;
            int EntryPoint = ReadInt32Safe(Dump, EntryPointOffset);

            if (EntryPoint <= 0 || RVA2Offset(Dump, EntryPoint) == -1)
            {
                long realThunkAddress = dumpVA + ThunkToFix;

                if (isPE64)
                {
                    // For x64, we search for FF 25 [Rel32] pointing to the thunk
                    for (int i = 0; i < Dump.Length - 6; i++)
                    {
                        if (Dump[i] == 0xFF && Dump[i + 1] == 0x25)
                        {
                            int rel32 = BitConverter.ToInt32(Dump, i + 2);
                            long targetVA = (long)dumpVA + i + 6 + rel32;
                            if (targetVA == realThunkAddress)
                            {
                                int EntrPointRVA = Offset2RVA(Dump, i);
                                if (EntrPointRVA != -1)
                                {
                                    ms.Position = EntryPointOffset;
                                    writer.Write(EntrPointRVA);
                                    break;
                                }
                            }
                        }
                    }
                }
                else
                {
                    byte[] pattern = BitConverter.GetBytes((uint)realThunkAddress);
                    for (int i = 0; i < Dump.Length - 6; i++)
                    {
                        if (Dump[i] == 0xFF && Dump[i + 1] == 0x25 &&
                            Dump[i + 2] == pattern[0] && Dump[i + 3] == pattern[1] &&
                            Dump[i + 4] == pattern[2] && Dump[i + 5] == pattern[3])
                        {
                            int EntrPointRVA = Offset2RVA(Dump, i);
                            if (EntrPointRVA != -1)
                            {
                                ms.Position = EntryPointOffset;
                                writer.Write(EntrPointRVA);
                                break;
                            }
                        }
                    }
                }
            }

            return true;
        }

        public struct DUMP_DIRECTORIES
        {
            public string root;
            public string dumps;
            public string nativedirname;
            public string sysdirname;
            public string unknowndirname;
        }

        public void SetDirectoriesPath(ref DUMP_DIRECTORIES dpmdirs)
        {
            dpmdirs.dumps = Path.Combine("C:\\", "Dumps");
            dpmdirs.nativedirname = Path.Combine(dpmdirs.dumps, ".NET Native");
            dpmdirs.sysdirname = Path.Combine(dpmdirs.dumps, "System");
            dpmdirs.unknowndirname = Path.Combine(dpmdirs.dumps, "UnknownName");
        }

        public bool CreateDirectories(ref DUMP_DIRECTORIES dpmdirs)
        {
            SetDirectoriesPath(ref dpmdirs);

            if (!Directory.Exists(dpmdirs.dumps))
            {
                try
                {
                    Directory.CreateDirectory(dpmdirs.dumps);
                }
                catch
                {
                    FolderBrowserDialog browse =
                    new()
                    {
                        ShowNewFolderButton = false,
                        Description = "Failed to create the directory - select a new location:",
                        SelectedPath = dpmdirs.root
                    };

                    if (browse.ShowDialog() == DialogResult.OK)
                    {
                        dpmdirs.root = browse.SelectedPath;
                        CreateDirectories(ref dpmdirs);
                    }
                    else
                    {
                        return false;
                    }
                }
            }

            string[] subDirs = { dpmdirs.nativedirname, dpmdirs.sysdirname, dpmdirs.unknowndirname };
            foreach (var d in subDirs)
            {
                if (!Directory.Exists(d))
                {
                    try { Directory.CreateDirectory(d); }
                    catch
                    {
                        return false;
                    }
                }
            }

            return true;
        }

        // helper: IntPtr -> ulong, bit-pattern
        static ulong PtrToULong(IntPtr ip)
        {
            if (IntPtr.Size == 8)
            {
                long v = ip.ToInt64();
                return BitConverter.ToUInt64(BitConverter.GetBytes(v), 0);
            }
            else
            {
                int v = ip.ToInt32();
                return BitConverter.ToUInt32(BitConverter.GetBytes(v), 0);
            }
        }

        private unsafe string DumpProcessLogic(uint processId, DUMP_DIRECTORIES ddirs, bool dumpNative, bool restoreFilename, Dictionary<ulong, string> moduleMap = null)
        {
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, processId);
            List<string> sessionDumpedFiles = new List<string>();

            if (hProcess == IntPtr.Zero)
            {
                GetSecurityInfo((int)Process.GetCurrentProcess().Handle, /*SE_KERNEL_OBJECT*/ 6, /*DACL_SECURITY_INFORMATION*/ 4, 0, 0, out IntPtr pDACL, IntPtr.Zero, out IntPtr pSecDesc);
                hProcess = OpenProcess(0x40000, 0, processId);
                SetSecurityInfo((int)hProcess, /*SE_KERNEL_OBJECT*/ 6, /*DACL_SECURITY_INFORMATION*/ 4 | /*UNPROTECTED_DACL_SECURITY_INFORMATION*/ 0x20000000, 0, 0, pDACL, IntPtr.Zero);
                CloseHandle(hProcess);
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, processId);
            }

            if (hProcess == IntPtr.Zero)
            {
                return "Failed to open selected process!";
            }

            try
            {
                ulong minaddress = 0;
                ulong maxaddress = 0;
                ulong pagesize = 0x1000UL;
                try
                {
                    SYSTEM_INFO pSI = new();
                    GetSystemInfo(ref pSI);

                    minaddress = PtrToULong(pSI.lpMinimumApplicationAddress);
                    maxaddress = PtrToULong(pSI.lpMaximumApplicationAddress);
                    pagesize = pSI.dwPageSize;
                }
                catch
                {
                }

                int CurrentCount = 1;

                bool isok;
                int pagesizeInt = (pagesize > int.MaxValue) ? 0x1000 : (int)pagesize;
                byte[] onepage = new byte[pagesizeInt];
                uint BytesRead = 0;
                byte[] infokeep = new byte[8];

                // --- 64-bit compatible iteration ---
                ulong currentAddress = minaddress;
                MEMORY_BASIC_INFORMATION mbi;
                uint mbiSize = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));

                while (currentAddress < maxaddress && VirtualQueryEx(hProcess, AddrToIntPtr(currentAddress), out mbi, mbiSize) != 0)
                {
                    // =================== FIX START ===================
                    // We are interested in committed memory that is not guarded and is accessible.
                    // The original check was flawed because it didn't use bitwise operations,
                    // which could lead to reading invalid memory and causing the access violation.
                    bool isMemoryReadable = (mbi.State == MEM_COMMIT) &&
                                            ((mbi.Protect & PAGE_GUARD) == 0) &&
                                            ((mbi.Protect & PAGE_NOACCESS) == 0);
                    // =================== FIX END =====================

                    if (isMemoryReadable)
                    {
                        ulong regionBase = PtrToULong(mbi.BaseAddress);
                        ulong regionSize = PtrToULong(mbi.RegionSize);
                        ulong regionEnd = regionBase + regionSize;

                        // Now scan this valid memory region page by page
                        for (ulong j = regionBase; j < regionEnd; j += pagesize)
                        {
                            isok = ReadProcessMemoryW(hProcess, j, onepage, out BytesRead);
                            if (!isok || BytesRead == 0)
                                continue;

                            if (isok)
                            {
                                // FIXED: Multiple safety checks to prevent index out of range
                                // Ensure we have at least 2 bytes and don't exceed array bounds
                                if (BytesRead < 2) continue;

                                // Ensure BytesRead doesn't exceed the actual array size
                                int safeByteCount = Math.Min((int)BytesRead, onepage.Length);
                                if (safeByteCount < 2) continue;

                                for (int k = 0; k < safeByteCount - 1; k++)
                                {
                                    // Additional safety check before array access
                                    if (k >= onepage.Length - 1) break;

                                    // check MZ signature in buffer - now safe with multiple bounds checks
                                    if (onepage[k] == 0x4D && onepage[k + 1] == 0x5A)
                                    {
                                        // Read PE header offset (4 bytes) at j + k + 0x03C
                                        ulong peOffsetAddr = j + (ulong)k + 0x03CUL;
                                        if (!ReadProcessMemoryW(hProcess, peOffsetAddr, infokeep, (UIntPtr)4, out BytesRead))
                                            continue;

                                        int PEOffset = BitConverter.ToInt32(infokeep, 0);
                                        if (PEOffset <= 0)
                                            continue;

                                        // ensure PEOffset falls within our local buffer first, else read from remote
                                        if ((PEOffset + 0x0120) < pagesizeInt)
                                        {
                                            int checkIndex = k + PEOffset;
                                            if (checkIndex + 1 >= onepage.Length)
                                                continue;

                                            // check 'PE' signature
                                            if (onepage[checkIndex] == 0x50 && onepage[checkIndex + 1] == 0x45) // 'P' 'E'
                                            {
                                                bool isNetAssembly = false;

                                                // --- SAFELY obtain e_lfanew (PE header offset) ---
                                                int e_lfanew = -1;
                                                // try read from local buffer if available
                                                if (k + 0x3C + 4 <= safeByteCount)
                                                {
                                                    e_lfanew = BitConverter.ToInt32(onepage, k + 0x3C);
                                                }
                                                else
                                                {
                                                    // fallback: read 4 bytes from remote process at (j + k + 0x3C)
                                                    if (!ReadProcessMemoryW(hProcess, j + (ulong)k + 0x03CUL, infokeep, (UIntPtr)4, out BytesRead))
                                                        continue;
                                                    e_lfanew = BitConverter.ToInt32(infokeep, 0);
                                                }

                                                if (e_lfanew <= 0)
                                                    continue;

                                                // compute local index of PE signature relative to onepage
                                                long peSigLocalIndex = (long)k + e_lfanew;

                                                // verify 'PE\0\0' either in local buffer or by remote read
                                                bool peSigOk = false;
                                                if (peSigLocalIndex >= 0 && (peSigLocalIndex + 4) <= safeByteCount)
                                                {
                                                    // signature is inside current local buffer
                                                    if (onepage[peSigLocalIndex] == 0x50 && onepage[peSigLocalIndex + 1] == 0x45
                                                        && onepage[peSigLocalIndex + 2] == 0x00 && onepage[peSigLocalIndex + 3] == 0x00)
                                                        peSigOk = true;
                                                }
                                                else
                                                {
                                                    // signature not fully in local page: read 4 bytes from remote to confirm
                                                    if (ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)e_lfanew, infokeep, (UIntPtr)4, out BytesRead))
                                                    {
                                                        if (BytesRead == 4 && infokeep[0] == 0x50 && infokeep[1] == 0x45 && infokeep[2] == 0x00 && infokeep[3] == 0x00)
                                                            peSigOk = true;
                                                    }
                                                }

                                                if (!peSigOk)
                                                    continue;

                                                // --- SAFELY read NumberOfSections and SizeOfOptionalHeader ---
                                                int numberOfSections = 0;
                                                short sizeOfOptionalHeader = 0;

                                                // NumberOfSections is at offset +6 from PE signature (i.e. e_lfanew + 6)
                                                if (peSigLocalIndex >= 0 && (peSigLocalIndex + 8) <= safeByteCount)
                                                {
                                                    numberOfSections = BitConverter.ToInt16(onepage, (int)peSigLocalIndex + 6);
                                                }
                                                else
                                                {
                                                    if (!ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)e_lfanew + 6UL, infokeep, (UIntPtr)2, out BytesRead))
                                                        continue;
                                                    numberOfSections = BitConverter.ToInt16(infokeep, 0);
                                                }

                                                // SizeOfOptionalHeader is at offset 20 from PE signature (e_lfanew + 20)
                                                if (peSigLocalIndex >= 0 && (peSigLocalIndex + 22) <= safeByteCount)
                                                {
                                                    sizeOfOptionalHeader = BitConverter.ToInt16(onepage, (int)peSigLocalIndex + 20);
                                                }
                                                else
                                                {
                                                    if (!ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)e_lfanew + 20UL, infokeep, (UIntPtr)2, out BytesRead))
                                                        continue;
                                                    sizeOfOptionalHeader = BitConverter.ToInt16(infokeep, 0);
                                                }

                                                // sanity checks
                                                if (numberOfSections <= 0 || numberOfSections >= 100)
                                                    continue;

                                                // Restore CheckAdvancedPEStructure call to get isNetAssembly status
                                                isNetAssembly = false;
                                                try
                                                {
                                                    isNetAssembly = CheckAdvancedPEStructure(hProcess, (j + (ulong)k), e_lfanew);
                                                }
                                                catch { isNetAssembly = false; }

                                                // Determine architecture and correct Metadata offset
                                                ushort magic = 0;
                                                // Read Magic bytes (PE Signature + 24 bytes = offset 24 in NT header)
                                                if (ReadProcessMemoryW(hProcess, (j + (ulong)k + (ulong)PEOffset + 24UL), infokeep, (UIntPtr)2, out BytesRead))
                                                    magic = BitConverter.ToUInt16(infokeep, 0);

                                                bool isPE64 = (magic == 0x20B);
                                                int metadataOffset = isPE64 ? 0x0F8 : 0x0E8;

                                                long NetMetadata = 0;
                                                // read 8 bytes at CLR metadata pointer
                                                ulong netMetaAddr = j + (ulong)k + (ulong)PEOffset + (ulong)metadataOffset;
                                                if (ReadProcessMemoryW(hProcess, netMetaAddr, infokeep, (UIntPtr)8, out BytesRead))
                                                    NetMetadata = BitConverter.ToInt64(infokeep, 0);

                                                if (NetMetadata == 0 && isNetAssembly)
                                                {
                                                    NetMetadata = 1;
                                                }

                                                // Improved Extraction: Always attempt dump if it looks valid, regardless of isNetAssembly, 
                                                // but ensure minimal validation via CheckAdvancedPEStructure passed.
                                                if (dumpNative || NetMetadata != 0)
                                                {
                                                    int peHeaderSize = Math.Max(pagesizeInt, PEOffset + 0x400);
                                                    byte[] PeHeader = new byte[peHeaderSize];
                                                    if (!ReadProcessMemoryW(hProcess, j + (ulong)k, PeHeader, (UIntPtr)peHeaderSize, out BytesRead))
                                                        continue;

                                                    // Verify we have enough data
                                                    if (BytesRead < PEOffset + 0x100) continue;

                                                    int nrofsection = BitConverter.ToInt16(PeHeader, PEOffset + 0x06);

                                                    if (nrofsection > 0 && nrofsection < 100)
                                                    {
                                                        string dumpdir = "";

                                                        // Read section alignment values directly from memory to ensure accuracy
                                                        byte[] alignmentBytes = new byte[8];
                                                        if (!ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)PEOffset + 0x038, alignmentBytes, (UIntPtr)8, out BytesRead))
                                                            continue;

                                                        int sectionalignment = BitConverter.ToInt32(alignmentBytes, 0);
                                                        // Read SizeOfOptionalHeader directly from memory
                                                        byte[] optHeaderSizeBytes = new byte[2];
                                                        if (!ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)PEOffset + 0x014, optHeaderSizeBytes, (UIntPtr)2, out BytesRead))
                                                            continue;

                                                        short sizeofoptionalheader = BitConverter.ToInt16(optHeaderSizeBytes, 0);

                                                        bool IsDll = false;
                                                        if ((PeHeader[PEOffset + 0x017] & 32) != 0) IsDll = true;

                                                        image_section_header[] sections = new image_section_header[nrofsection];

                                                        // compute ptr as 64-bit address (base of section table)
                                                        ulong ptr = (ulong)j + (ulong)k + (ulong)PEOffset + (ulong)sizeofoptionalheader + 4UL + (ulong)Marshal.SizeOf(typeof(IMAGE_FILE_HEADER));

                                                        for (int i = 0; i < nrofsection; i++)
                                                        {
                                                            byte[] datakeeper = new byte[Marshal.SizeOf(typeof(image_section_header))];
                                                            if (!ReadProcessMemoryW(hProcess, ptr, datakeeper, (UIntPtr)datakeeper.Length, out BytesRead))
                                                                break;

                                                            fixed (byte* p = datakeeper)
                                                            {
                                                                sections[i] = (image_section_header)Marshal.PtrToStructure((IntPtr)p, typeof(image_section_header));
                                                            }

                                                            ptr += (ulong)Marshal.SizeOf(typeof(image_section_header));
                                                        }

                                                        string filename = "";
                                                        int sizeofimage = BitConverter.ToInt32(PeHeader, PEOffset + 0x050);
                                                        int sizeOfHeaders = BitConverter.ToInt32(PeHeader, PEOffset + 0x54);
                                                        int calculatedimagesize = sizeOfHeaders;

                                                        int rawsize, rawAddress, virtualsize, virtualAddress = 0;

                                                        for (int i = 0; i < nrofsection; i++)
                                                        {
                                                            virtualsize = sections[i].virtual_size;
                                                            virtualAddress = sections[i].virtual_address;

                                                            int toadd = virtualsize % sectionalignment;
                                                            if (toadd != 0) toadd = sectionalignment - toadd;

                                                            int sectionEnd = virtualAddress + virtualsize + toadd;
                                                            if (sectionEnd > calculatedimagesize)
                                                                calculatedimagesize = sectionEnd;
                                                        }

                                                        if (calculatedimagesize > sizeofimage) sizeofimage = calculatedimagesize;

                                                        byte[] virtualdump = new byte[sizeofimage];
                                                        Array.Copy(PeHeader, virtualdump, pagesizeInt);

                                                        // =================== FIX START: HEADER PATCHING ===================
                                                        // Patch FileAlignment to match SectionAlignment.
                                                        // In memory dumps (virtual layout), FileAlignment is effectively equal to SectionAlignment.
                                                        // This helps tools like FileVersionInfo read the resources correctly from the dump.
                                                        try
                                                        {
                                                            int sectionAlignOffset = PEOffset + 24 + 32;
                                                            int fileAlignOffset = PEOffset + 24 + 36;
                                                            if (fileAlignOffset + 4 < virtualdump.Length)
                                                            {
                                                                Array.Copy(virtualdump, sectionAlignOffset, virtualdump, fileAlignOffset, 4);
                                                            }
                                                        }
                                                        catch { }
                                                        // =================== FIX END =====================

                                                        int rightrawsize = 0;
                                                        for (int l = 0; l < nrofsection; l++)
                                                        {
                                                            virtualsize = sections[l].virtual_size;
                                                            virtualAddress = sections[l].virtual_address;

                                                            // Memory dumper always produces a "fixed" dump (Raw layout = Virtual layout)
                                                            // to prevent corruption and fragmentation.
                                                            rawsize = virtualsize;
                                                            rawAddress = virtualAddress;

                                                            using (BinaryWriter sectionWriter = new(new MemoryStream(virtualdump)))
                                                            {
                                                                sectionWriter.BaseStream.Position = PEOffset + 24 + sizeofoptionalheader + (0x28 * l) + 16;
                                                                sectionWriter.Write(virtualsize);
                                                                sectionWriter.BaseStream.Position = PEOffset + 24 + sizeofoptionalheader + (0x28 * l) + 20;
                                                                sectionWriter.Write(virtualAddress);
                                                            }

                                                            byte[] csection = new byte[0];
                                                            try
                                                            {
                                                                csection = new byte[rawsize];
                                                            }
                                                            catch
                                                            {
                                                                csection = new byte[virtualsize];
                                                            }
                                                            int rightsize = csection.Length;

                                                            // try reading whole section at once
                                                            isok = ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)virtualAddress, csection, (UIntPtr)rawsize, out BytesRead);
                                                            if (!isok || BytesRead != rawsize)
                                                            {
                                                                rightsize = 0;
                                                                byte[] currentpage = new byte[pagesizeInt];
                                                                for (int c = 0; c < rawsize; c += pagesizeInt)
                                                                {
                                                                    try
                                                                    {
                                                                        // read page-by-page
                                                                        isok = ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)virtualAddress + (ulong)c, currentpage, (UIntPtr)pagesizeInt, out BytesRead);
                                                                    }
                                                                    catch
                                                                    {
                                                                        break;
                                                                    }

                                                                    if (isok)
                                                                    {
                                                                        rightsize += (int)pagesizeInt;
                                                                        for (int i = 0; i < pagesizeInt; i++)
                                                                        {
                                                                            if ((c + i) < csection.Length)
                                                                                csection[c + i] = currentpage[i];
                                                                        }
                                                                    }
                                                                }
                                                            }

                                                            try
                                                            {
                                                                // Force copy to virtualAddress to avoid corrupting header
                                                                Array.Copy(csection, 0, virtualdump, virtualAddress, rightsize);
                                                            }
                                                            catch
                                                            {
                                                            }

                                                            rightrawsize = sizeofimage;
                                                        }

                                                        // Safe Fix: This now strictly checks for .NET internals before applying changes
                                                        FixImportandEntryPoint((long)(j + (ulong)k), virtualdump);

                                                        dumpdir = ddirs.dumps;

                                                        // =================== FIX START: NAMING LOGIC ===================
                                                        string friendlyName = "";
                                                        ulong moduleBaseAddr = j + (ulong)k;
                                                        if (moduleMap != null && moduleMap.ContainsKey(moduleBaseAddr))
                                                        {
                                                            friendlyName = moduleMap[moduleBaseAddr];
                                                        }

                                                        if (!string.IsNullOrEmpty(friendlyName))
                                                        {
                                                            // Use the actual module name if available (avoids UnknownName)
                                                            // We strip .exe/.dll extension first to avoid duplication logic later
                                                            string ext = Path.GetExtension(friendlyName);
                                                            string nameNoExt = Path.GetFileNameWithoutExtension(friendlyName);
                                                            filename = dumpdir + "\\" + nameNoExt + "_" + moduleBaseAddr.ToString("X");
                                                        }
                                                        else
                                                        {
                                                            // Fallback to vdump
                                                            filename = dumpdir + "\\vdump_" + moduleBaseAddr.ToString("X");
                                                            if (File.Exists(filename))
                                                                filename = dumpdir + "\\vdump" + CurrentCount.ToString() + "_" + moduleBaseAddr.ToString("X");
                                                        }
                                                        // =================== FIX END =====================

                                                        if (IsDll)
                                                            filename += ".dll";
                                                        else
                                                            filename += ".exe";

                                                        FileStream fout = null;

                                                        try
                                                        {
                                                            fout = new FileStream(filename, FileMode.Create);
                                                        }
                                                        catch
                                                        {
                                                            // Cannot show UI from background thread
                                                        }

                                                        if (fout != null)
                                                        {
                                                            if (rightrawsize > virtualdump.Length) rightrawsize = virtualdump.Length;

                                                            fout.Write(virtualdump, 0, rightrawsize);
                                                            fout.Close();
                                                            sessionDumpedFiles.Add(filename);

                                                            // Scylla Integration moved to post-processing
                                                        }
                                                        CurrentCount++;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    try
                    {
                        // CHANGE: Wrap the address calculation in an 'unchecked' block.
                        // This prevents an OverflowException when scanning at the top of the 64-bit address space,
                        // which is a necessary change for 64-bit compatibility.
                        unchecked
                        {
                            currentAddress = PtrToULong(mbi.BaseAddress) + PtrToULong(mbi.RegionSize);
                        }
                    }
                    catch (OverflowException)
                    {
                        // Reached the end of the 64-bit address space
                        // This catch is now less likely to be hit, but kept as a safeguard.
                        break;
                    }
                }

                if (restoreFilename)
                {
                    Action<string, string> renameFiles = (string sourceDir, string targetDir) =>
                    {
                        if (Directory.Exists(sourceDir))
                        {
                            DirectoryInfo di = new DirectoryInfo(sourceDir);
                            foreach (FileInfo fi in di.GetFiles())
                            {
                                try
                                {
                                    FileVersionInfo info = FileVersionInfo.GetVersionInfo(fi.FullName);
                                    string finalDir = targetDir;

                                    bool isMicrosoft = info.CompanyName?.IndexOf("microsoft corporation", StringComparison.OrdinalIgnoreCase) >= 0;
                                    bool isDotNet = IsDotNetAssembly(fi.FullName);

                                    // NEW LOGIC: Strict sorting rules
                                    // 1. Unknown files (no original filename) -> UnknownName OR check module map name
                                    if (string.IsNullOrEmpty(info.OriginalFilename))
                                    {
                                        // =================== FIX START: SORTING LOGIC ===================
                                        // If we don't have version info (common for native/packed apps),
                                        // check if we gave it a friendly name from the Module List.
                                        // If the file starts with "vdump_", it means we failed to identify it.
                                        // If it has a real name (e.g. "kernel32_7FF..."), keep it in dumps/root.
                                        if (fi.Name.StartsWith("vdump_", StringComparison.OrdinalIgnoreCase))
                                        {
                                            finalDir = ddirs.unknowndirname;
                                        }
                                        else
                                        {
                                            // It has a recognized name, so we treat it as valid.
                                            // Default to root dumps folder to avoid confusing users.
                                            finalDir = ddirs.dumps;
                                        }
                                        // =================== FIX END =====================
                                    }
                                    else if (isMicrosoft)
                                    {
                                        // 2. System files (Microsoft)
                                        if (isDotNet)
                                        {
                                            // 2a. System .NET -> .NET Native
                                            finalDir = ddirs.nativedirname;
                                        }
                                        else
                                        {
                                            // 2b. System Native -> System
                                            finalDir = ddirs.sysdirname;
                                        }
                                    }
                                    else
                                    {
                                        // 3. User files / Third Party -> Root (C:\Dumps)
                                        // If sourceDir is already root, stay there.
                                        finalDir = ddirs.dumps;
                                    }

                                    if (!string.IsNullOrEmpty(info.OriginalFilename))
                                    {
                                        string safeName = string.Concat(info.OriginalFilename.Where(c => !Path.GetInvalidFileNameChars().Contains(c)));

                                        if (fi.Name.Contains("_scyfix"))
                                        {
                                            string ext = Path.GetExtension(safeName);
                                            string nameNoExt = Path.GetFileNameWithoutExtension(safeName);
                                            safeName = nameNoExt + "_scyfix" + ext;
                                        }

                                        string newFilename = Path.Combine(finalDir, safeName);

                                        int count = 2;
                                        while (File.Exists(newFilename))
                                        {
                                            string extension = Path.GetExtension(newFilename) ?? ".dll";
                                            newFilename = Path.Combine(finalDir, $"{Path.GetFileNameWithoutExtension(safeName)}({count++}){extension}");
                                        }
                                        File.Move(fi.FullName, newFilename);
                                    }
                                    else
                                    {
                                        // Move unknown to unknown folder
                                        try
                                        {
                                            // Only move if finalDir is different from current dir
                                            if (Path.GetFullPath(finalDir) != Path.GetFullPath(fi.DirectoryName))
                                                File.Move(fi.FullName, Path.Combine(finalDir, fi.Name));
                                        }
                                        catch { }
                                    }
                                }
                                catch
                                {
                                    try { File.Move(fi.FullName, Path.Combine(ddirs.unknowndirname, fi.Name)); } catch { }
                                }
                            }
                        }
                    };

                    try
                    {
                        if (MegaDumper.ScyllaBindings.IsAvailable)
                        {
                            bool shouldScyfix = false;
                            string normalizedDumpPath = "";
                            try
                            {
                                normalizedDumpPath = Path.GetFullPath(ddirs.dumps).TrimEnd(Path.DirectorySeparatorChar);
                            }
                            catch { }
                            string cDumpsPath = @"C:\Dumps";

                            if (string.Equals(normalizedDumpPath, cDumpsPath, StringComparison.OrdinalIgnoreCase))
                            {
                                shouldScyfix = true;
                            }

                            if (shouldScyfix)
                            {
                                HashSet<string> filesToScylla = new HashSet<string>(sessionDumpedFiles);
                                try
                                {
                                    if (Directory.Exists(ddirs.dumps))
                                    {
                                        foreach (var f in Directory.GetFiles(ddirs.dumps, "rawdump_*.*", SearchOption.AllDirectories))
                                        {
                                            filesToScylla.Add(f);
                                        }
                                    }
                                }
                                catch { }

                                foreach (string dumpedFile in filesToScylla)
                                {
                                    if (!File.Exists(dumpedFile)) continue;

                                    // NEW LOGIC: SKIP SCYLLA FOR .NET FILES
                                    // "Scylla fixes only for non-.NET"
                                    if (IsDotNetAssembly(dumpedFile))
                                    {
                                        continue;
                                    }

                                    try
                                    {
                                        string fileNameNoExt = Path.GetFileNameWithoutExtension(dumpedFile);

                                        if (!fileNameNoExt.StartsWith("rawdump", StringComparison.OrdinalIgnoreCase))
                                        {
                                            continue;
                                        }

                                        this.Invoke((MethodInvoker)delegate
                                        {
                                            this.Text = $"Scylla fixing: {fileNameNoExt}...";
                                        });

                                        string hexAddress = fileNameNoExt.Split('_').Last();
                                        ulong imageBase = Convert.ToUInt64(hexAddress, 16);

                                        if (imageBase > 0)
                                        {
                                            string scyFixFilename = Path.ChangeExtension(dumpedFile, null) + "_scyfix" + Path.GetExtension(dumpedFile);

                                            try
                                            {
                                                System.Diagnostics.Process.EnterDebugMode();
                                                using (var p = System.Diagnostics.Process.GetProcessById((int)processId))
                                                {
                                                    if (p.HasExited) throw new Exception("Process has exited");
                                                }
                                            }
                                            catch { }

                                            ulong entryPoint = imageBase;
                                            bool is64 = IntPtr.Size == 8;
                                            byte[] header = new byte[0x400];
                                            using (FileStream fs = new FileStream(dumpedFile, FileMode.Open, FileAccess.Read))
                                            {
                                                fs.Read(header, 0, 0x400);
                                            }
                                            int peOffset = BitConverter.ToInt32(header, 0x3C);
                                            if (peOffset > 0 && peOffset < 0x300)
                                            {
                                                int optHeaderOffset = peOffset + 4 + 20;
                                                is64 = BitConverter.ToUInt16(header, optHeaderOffset) == 0x20B;
                                                uint epRva = BitConverter.ToUInt32(header, optHeaderOffset + 16);
                                                entryPoint = imageBase + epRva;

                                                uint sectionAlignment = BitConverter.ToUInt32(header, optHeaderOffset + 32);
                                                uint fileAlignment = BitConverter.ToUInt32(header, optHeaderOffset + 36);

                                                if (fileAlignment != sectionAlignment)
                                                {
                                                    byte[] alignBytes = BitConverter.GetBytes(sectionAlignment);
                                                    Array.Copy(alignBytes, 0, header, optHeaderOffset + 36, 4);

                                                    using (FileStream fsWrite = new FileStream(dumpedFile, FileMode.Open, FileAccess.Write))
                                                    {
                                                        fsWrite.Write(header, 0, 0x400);
                                                    }
                                                }
                                            }

                                            File.AppendAllText(Path.Combine(ddirs.dumps, "scylla_log.txt"),
                                                $"[{DateTime.Now}] Starting Scylla for {Path.GetFileName(dumpedFile)} (Base=0x{imageBase:X}, PE={(!is64 ? "32-bit" : "64-bit")})...\n");

                                            ulong realOEP = 0;
                                            try
                                            {
                                                using (var proc = System.Diagnostics.Process.GetProcessById((int)processId))
                                                {
                                                    if (proc.Threads.Count > 0)
                                                    {
                                                        var outputThread = proc.Threads[0];
                                                        int threadId = outputThread.Id;

                                                        IntPtr hThread = OpenThread(0x0010 | 0x0008 | 0x0002, false, (uint)threadId);
                                                        if (hThread != IntPtr.Zero)
                                                        {
                                                            try
                                                            {
                                                                SuspendThread(hThread);

                                                                if (is64)
                                                                {
                                                                    CONTEXT64 ctx = new CONTEXT64();
                                                                    ctx.ContextFlags = 0x100002;
                                                                    if (GetThreadContext64(hThread, ref ctx))
                                                                    {
                                                                        realOEP = ctx.Rip;
                                                                    }
                                                                }
                                                                else
                                                                {
                                                                    CONTEXT32 ctx = new CONTEXT32();
                                                                    ctx.ContextFlags = 0x10002;
                                                                    if (GetThreadContext32(hThread, ref ctx))
                                                                    {
                                                                        realOEP = (ulong)ctx.Eip;
                                                                    }
                                                                }
                                                            }
                                                            finally
                                                            {
                                                                ResumeThread(hThread);
                                                                CloseHandle(hThread);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            catch (Exception)
                                            {
                                                // Log silent
                                            }

                                            ulong finalEntryPoint = (realOEP > 0) ? realOEP : entryPoint;

                                            MegaDumper.ScyllaError scyResult = MegaDumper.ScyllaError.IatSearchError;

                                            try
                                            {
                                                try
                                                {
                                                    using (var checkProc = System.Diagnostics.Process.GetProcessById((int)processId))
                                                    {
                                                        if (checkProc.HasExited)
                                                        {
                                                            scyResult = MegaDumper.ScyllaError.PidNotFound;
                                                        }
                                                    }
                                                }
                                                catch
                                                {
                                                    scyResult = MegaDumper.ScyllaError.PidNotFound;
                                                }

                                                if (scyResult != MegaDumper.ScyllaError.PidNotFound)
                                                {
                                                    scyResult = MegaDumper.ScyllaBindings.FixImportsAutoDetect(
                                                        processId,
                                                        imageBase,
                                                        finalEntryPoint,
                                                        dumpedFile,
                                                        scyFixFilename,
                                                        advancedSearch: true,
                                                        createNewIat: true);

                                                    if (scyResult != MegaDumper.ScyllaError.Success && finalEntryPoint != entryPoint)
                                                    {
                                                        scyResult = MegaDumper.ScyllaBindings.FixImportsAutoDetect(
                                                           processId,
                                                           imageBase,
                                                           entryPoint,
                                                           dumpedFile,
                                                           scyFixFilename,
                                                           advancedSearch: true,
                                                           createNewIat: true);
                                                    }

                                                    if (scyResult == MegaDumper.ScyllaError.Success)
                                                    {
                                                        File.AppendAllText(Path.Combine(ddirs.dumps, "scylla_log.txt"),
                                                            $"  Result: Success\n");
                                                    }
                                                    else
                                                    {
                                                        File.AppendAllText(Path.Combine(ddirs.dumps, "scylla_log.txt"),
                                                            $"  Result: {scyResult}\n");
                                                    }
                                                }
                                            }
                                            catch (Exception)
                                            {
                                                scyResult = MegaDumper.ScyllaError.IatSearchError;
                                            }

                                            bool skipFallbacks = (scyResult == MegaDumper.ScyllaError.PidNotFound) ||
                                                                (scyResult == MegaDumper.ScyllaError.ModuleNotFound);

                                            if (scyResult != MegaDumper.ScyllaError.Success && !skipFallbacks)
                                            {
                                                string scyNativeDump = Path.Combine(Path.GetDirectoryName(dumpedFile), "scy_native_" + Path.GetFileName(dumpedFile));

                                                bool dumpSuccess = MegaDumper.ScyllaBindings.DumpProcessX64(processId, imageBase, finalEntryPoint, scyNativeDump, dumpedFile);

                                                if (dumpSuccess && File.Exists(scyNativeDump))
                                                {
                                                    scyResult = MegaDumper.ScyllaBindings.FixImportsAutoDetect(
                                                        processId,
                                                        imageBase,
                                                        finalEntryPoint,
                                                        scyNativeDump,
                                                        scyFixFilename,
                                                        advancedSearch: true,
                                                        createNewIat: true);
                                                }
                                            }

                                            if (scyResult != MegaDumper.ScyllaError.Success && !skipFallbacks)
                                            {
                                                try
                                                {
                                                    byte[] peData = File.ReadAllBytes(dumpedFile);
                                                    int peHead = BitConverter.ToInt32(peData, 0x3C);
                                                    int optHead = peHead + 4 + 20;
                                                    bool pe64 = BitConverter.ToUInt16(peData, optHead) == 0x20B;
                                                    int dataDirOffset = optHead + (pe64 ? 112 : 96);

                                                    uint importRva = BitConverter.ToUInt32(peData, dataDirOffset + 8);
                                                    uint importSize = BitConverter.ToUInt32(peData, dataDirOffset + 12);

                                                    uint iatRva = BitConverter.ToUInt32(peData, dataDirOffset + (12 * 8));
                                                    uint iatSize = BitConverter.ToUInt32(peData, dataDirOffset + (12 * 8) + 4);

                                                    if (iatRva > 0 && iatSize > 0)
                                                    {
                                                        scyResult = MegaDumper.ScyllaBindings.IatFix(
                                                            processId,
                                                            imageBase,
                                                            (UIntPtr)(imageBase + iatRva),
                                                            iatSize,
                                                            true,
                                                            dumpedFile,
                                                            scyFixFilename);
                                                    }
                                                }
                                                catch
                                                {
                                                }
                                            }

                                            if (scyResult == MegaDumper.ScyllaError.Success)
                                            {
                                                try
                                                {
                                                    SanitizeScyfixFile(scyFixFilename);
                                                }
                                                catch
                                                {
                                                }
                                            }
                                        }
                                    }
                                    catch
                                    {
                                    }
                                }
                            }
                        }
                    }
                    catch { }

                    renameFiles(ddirs.dumps, ddirs.dumps);
                    // No need to rename subfolders recursively as the logic puts them in place first time, 
                    // but we can ensure they are clean.

                    try
                    {
                        if (MegaDumper.ScyllaBindings.IsAvailable)
                        {
                            var dirsToScan = new List<string>();
                            if (Directory.Exists(ddirs.unknowndirname)) dirsToScan.Add(ddirs.unknowndirname);
                            // "if there no files in non subfolder the main folder C:\Dumps try everything"
                            // We always scan dumps for cleanup, regardless.
                            if (Directory.Exists(ddirs.dumps)) dirsToScan.Add(ddirs.dumps);

                            foreach (var dir in dirsToScan)
                            {
                                foreach (string dumpedFile in Directory.GetFiles(dir, "rawdump_*.*"))
                                {
                                    try
                                    {
                                        // NEW LOGIC: Scylla Strict Check .NET ONLY
                                        if (!IsDotNetAssembly(dumpedFile)) continue;

                                        string checkScyfix = Path.ChangeExtension(dumpedFile, null) + "_scyfix" + Path.GetExtension(dumpedFile);
                                        if (File.Exists(checkScyfix)) continue;

                                        string fileNameNoExt = Path.GetFileNameWithoutExtension(dumpedFile);
                                        string hexAddress = fileNameNoExt.Split('_').Last();
                                        ulong imageBase = Convert.ToUInt64(hexAddress, 16);

                                        if (imageBase > 0)
                                        {
                                            MegaDumper.ScyllaError scyResult = MegaDumper.ScyllaBindings.FixImportsAutoDetect(
                                                  processId,
                                                  imageBase,
                                                  imageBase,
                                                  dumpedFile,
                                                  checkScyfix,
                                                  advancedSearch: false,
                                                  createNewIat: true);
                                        }
                                    }
                                    catch { }
                                }
                            }
                        }
                    }
                    catch { }


                }

                return (CurrentCount - 1) + " files dumped in directory " + ddirs.dumps;
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }

        private void CopyToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                string strtoset = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[4].Text;
                if (strtoset != "") Clipboard.SetText(strtoset);
            }
        }

        private void DumpModuleToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count == 0)
                return;

            string strprname = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[0].Text;
            string dirname = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[4].Text;
            if (strprname != "")
            {
                int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                FrmModules pmodfrm = new(strprname, procid, dirname);
                pmodfrm.Show();
            }
        }

        private void Button3Click(object sender, EventArgs e)
        {
            ProcessManager prman = new();
            prman.Show();
        }

        private void GotoLocationToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count == 0)
                return;

            string dirname = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[4].Text;
            string filename = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[0].Text;
            string fullfilename = Path.Combine(dirname, filename);
            if (Directory.Exists(dirname))
            {
                try
                {
                    string argument = "/select, " + fullfilename;
                    Process.Start("explorer.exe", argument);
                }
                catch
                {
                }
            }
        }

        private void ToolStripMenuItem2Click(object sender, EventArgs e)
        {
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        private void KillProcessToolStripMenuItemClick(object sender, EventArgs e)
        {
            int intselectedindex = lvprocesslist.SelectedIndices[0];
            if (intselectedindex != -1)
            {
                uint processId = Convert.ToUInt32(lvprocesslist.Items[intselectedindex].SubItems[1].Text);
                IntPtr hProcess = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, processId);

                if (hProcess == IntPtr.Zero)
                {
                    GetSecurityInfo((int)Process.GetCurrentProcess().Handle, /*SE_KERNEL_OBJECT*/ 6, /*DACL_SECURITY_INFORMATION*/ 4, 0, 0, out IntPtr pDACL, IntPtr.Zero, out _);
                    hProcess = OpenProcess(0x40000, 0, processId);
                    SetSecurityInfo((int)hProcess, /*SE_KERNEL_OBJECT*/ 6, /*DACL_SECURITY_INFORMATION*/ 4 | /*UNPROTECTED_DACL_SECURITY_INFORMATION*/ 0x20000000, 0, 0, pDACL, IntPtr.Zero);
                    CloseHandle(hProcess);
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, processId);
                }

                try
                {
                    TerminateProcess(hProcess, 0);
                }
                catch
                {
                }
                CloseHandle(hProcess);
            }
        }

        [DllImport("ntdll.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ZwSuspendProcess(IntPtr hProcess);

        [DllImport("ntdll.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ZwResumeProcess(IntPtr hProcess);

        private void SuspendProcessToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count == 0)
                return;

            int intselectedindex = lvprocesslist.SelectedIndices[0];
            if (intselectedindex != -1)
            {
                uint processId = Convert.ToUInt32(lvprocesslist.Items[intselectedindex].SubItems[1].Text);
                IntPtr hProcess = OpenProcess(0x800, 0, processId);

                if (hProcess == IntPtr.Zero)
                {
                    GetSecurityInfo((int)Process.GetCurrentProcess().Handle, /*SE_KERNEL_OBJECT*/ 6, /*DACL_SECURITY_INFORMATION*/ 4, 0, 0, out IntPtr pDACL, IntPtr.Zero, out _);
                    hProcess = OpenProcess(0x40000, 0, processId);
                    SetSecurityInfo((int)hProcess, /*SE_KERNEL_OBJECT*/ 6, /*DACL_SECURITY_INFORMATION*/ 4 | /*UNPROTECTED_DACL_SECURITY_INFORMATION*/ 0x20000000, 0, 0, pDACL, IntPtr.Zero);
                    CloseHandle(hProcess);
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, processId);
                }

                try
                {
                    ZwSuspendProcess(hProcess);
                }
                catch
                {
                }
                CloseHandle(hProcess);
            }
        }

        private void ResumeProcessToolStripMenuItemClick(object sender, EventArgs e)
        {
            int intselectedindex = lvprocesslist.SelectedIndices[0];
            if (intselectedindex != -1)
            {
                uint processId = Convert.ToUInt32(lvprocesslist.Items[intselectedindex].SubItems[1].Text);
                IntPtr hProcess = OpenProcess(0x800, 0, processId);

                if (hProcess == IntPtr.Zero)
                {
                    GetSecurityInfo((int)Process.GetCurrentProcess().Handle, /*SE_KERNEL_OBJECT*/ 6, /*DACL_SECURITY_INFORMATION*/ 4, 0, 0, out IntPtr pDACL, IntPtr.Zero, out _);
                    hProcess = OpenProcess(0x40000, 0, processId);
                    SetSecurityInfo((int)hProcess, /*SE_KERNEL_OBJECT*/ 6, /*DACL_SECURITY_INFORMATION*/ 4 | /*UNPROTECTED_DACL_SECURITY_INFORMATION*/ 0x20000000, 0, 0, pDACL, IntPtr.Zero);
                    CloseHandle(hProcess);
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, processId);
                }

                try
                {
                    ZwResumeProcess(hProcess);
                }
                catch
                {
                }
                CloseHandle(hProcess);
            }
        }
        private void CheckBox3CheckedChanged(object sender, EventArgs e)
        {
            timer1.Stop();
            timer1.Dispose();
            timer1 = null;

            if (timer1 == null)
            {
                timer1 = new Timer
                {
                    Interval = 100,
                    Enabled = true
                };
                timer1.Tick += OnTimerEvent;
            }
        }

        [DllImport("user32.dll")]
        public static extern int SetForegroundWindow(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

        [DllImport("user32.dll")]
        private static extern bool CloseWindow(IntPtr hWnd);

        public enum ShowWindowCommand
        {
            /// <summary>
            /// Hides the window and activates another window.
            /// </summary>
            Hide = 0,
            /// <summary>
            /// Activates and displays a window. If the window is minimized or
            /// maximized, the system restores it to its original size and position.
            /// An application should specify this flag when displaying the window
            /// for the first time.
            /// </summary>
            Normal = 1,
            /// <summary>
            /// Activates the window and displays it as a minimized window.
            /// </summary>
            ShowMinimized = 2,
            /// <summary>
            /// Maximizes the specified window.
            /// </summary>
            Maximize = 3, // is this the right value?
            /// <summary>
            /// Activates the window and displays it as a maximized window.
            /// </summary>
            ShowMaximized = Maximize,
            /// <summary>
            /// Displays a window in its most recent size and position. This value
            /// is similar to <see cref="Win32.ShowWindowCommand.Normal"/>, except
            /// the window is not actived.
            /// </summary>
            ShowNoActivate = 4,
            /// <summary>
            /// Activates the window and displays it in its current size and position.
            /// </summary>
            Show = 5,
            /// <summary>
            /// Minimizes the specified window and activates the next top-level
            /// window in the Z order.
            /// </summary>
            Minimize = 6,
            /// <summary>
            /// Displays the window as a minimized window. This value is similar to
            /// <see cref="Win32.ShowWindowCommand.ShowMinimized"/>, except the
            /// window is not activated.
            /// </summary>
            ShowMinNoActive = 7,
            /// <summary>
            /// Displays the window in its current size and position. This value is
            /// similar to <see cref="Win32.ShowWindowCommand.Show"/>, except the
            // window is not activated.
            /// </summary>
            ShowNA = 8,
            /// <summary>
            /// Activates and displays the window. If the window is minimized or
            /// maximized, the system restores it to its original size and position.
            /// An application should specify this flag when restoring a minimized window.
            /// </summary>
            Restore = 9,
            /// <summary>
            /// Sets the show state based on the SW_* value specified in the
            /// STARTUPINFO structure passed to the CreateProcess function by the
            /// program that started the application.
            /// </summary>
            ShowDefault = 10,
            /// <summary>
            ///  <b>Windows 2000/XP:</b> Minimizes a window, even if the thread
            /// that owns the window is not responding. This flag should only be
            /// used when minimizing windows from a different thread.
            /// </summary>
            ForceMinimize = 11
        }

        [DllImport("user32.dll")]
        private static extern bool ShowWindow(IntPtr hWnd, ShowWindowCommand nCmdShow);

        [DllImport("user32.dll")]
        private static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll", EntryPoint = "SystemParametersInfo")]
        public static extern bool SystemParametersInfo(uint uiAction, uint uiParam, uint pvParam, uint fWinIni);

        private void BringToFrontToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                string strwhitpid = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text;
                int processpid = Convert.ToInt32(strwhitpid, 10);

                EnumWindows eW = new();
                eW.GetWindows();
                foreach (EnumWindowsItem item in eW.Items)
                {
                    if (item.Visible)
                    {
                        _ = GetWindowThreadProcessId(item.Handle, out int currentpid);
                        if (currentpid == processpid)
                        {
                            // SPI_SETFOREGROUNDLOCKTIMEOUT = 0x2001
                            SystemParametersInfo(0x2001, 0, 0, 0x0002 | 0x0001);
                            ShowWindowAsync(item.Handle, 3);
                            SetForegroundWindow(item.Handle);
                            SystemParametersInfo(0x2001, 200000, 200000, 0x0002 | 0x0001);
                        }
                    }
                }
            }
        }

        private void RestoreToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count == 0)
                return;

            string strwhitpid = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text;
            int processpid = Convert.ToInt32(strwhitpid, 10);

            EnumWindows eW = new();
            eW.GetWindows();
            foreach (EnumWindowsItem item in eW.Items)
            {
                if (item.Visible)
                {
                    _ = GetWindowThreadProcessId(item.Handle, out int currentpid);
                    if (currentpid == processpid)
                    {
                        ShowWindow(item.Handle, ShowWindowCommand.Restore);
                    }
                }
            }
        }

        private void MinimizeToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count == 0)
                return;

            string strwhitpid = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text;
            int processpid = Convert.ToInt32(strwhitpid, 10);

            EnumWindows eW = new();
            eW.GetWindows();
            foreach (EnumWindowsItem item in eW.Items)
            {
                if (item.Visible)
                {
                    _ = GetWindowThreadProcessId(item.Handle, out int currentpid);
                    if (currentpid == processpid)
                    {
                        ShowWindow(item.Handle, ShowWindowCommand.Minimize);
                    }
                }
            }
        }

        private void MaximizeToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count == 0)
                return;

            string strwhitpid = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text;
            int processpid = Convert.ToInt32(strwhitpid, 10);

            EnumWindows eW = new();
            eW.GetWindows();
            foreach (EnumWindowsItem item in eW.Items)
            {
                if (item.Visible)
                {
                    _ = GetWindowThreadProcessId(item.Handle, out int currentpid);
                    if (currentpid == processpid)
                    {
                        ShowWindow(item.Handle, ShowWindowCommand.Maximize);
                    }
                }
            }
        }

        private void CloseToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count == 0)
                return;

            string strwhitpid = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text;
            int processpid = Convert.ToInt32(strwhitpid, 10);

            EnumWindows eW = new();
            eW.GetWindows();
            foreach (EnumWindowsItem item in eW.Items)
            {
                if (item.Visible)
                {
                    _ = GetWindowThreadProcessId(item.Handle, out int currentpid);
                    if (currentpid == processpid)
                    {
                        CloseWindow(item.Handle);
                    }
                }
            }
        }

        public enum ProcessPriorities : uint
        {
            Normal = 0x00000020,
            Idle = 0x00000040,
            High = 0x00000080,
            Real_Time = 0x00000100      //Process that has the highest possible priority. The threads of a real-time priority class process preempt the threads of all other processes, including operating system processes performing important tasks. For example, a real-time process that executes for more than a very brief interval can cause disk caches not to flush or cause the mouse to be unresponsive.
,
            Below_Normal = 0x00004000,
            Above_Normal = 0x00008000
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern ProcessPriorities GetPriorityClass(IntPtr handle);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool SetPriorityClass(IntPtr handle, ProcessPriorities priority);

        private void PriorityToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                if (procid != 0)
                {
                    IntPtr hProcess =
                    OpenProcess(PROCESS_QUERY_INFORMATION, 0, (uint)procid);
                    if (hProcess != IntPtr.Zero)
                    {
                        switch (GetPriorityClass(hProcess))
                        {
                            case ProcessPriorities.Real_Time:
                                rttoolStripMenuItem.Checked = true;

                                hToolStripMenuItem.Checked = false;
                                anToolStripMenuItem.Checked = false;
                                nToolStripMenuItem.Checked = false;
                                bnToolStripMenuItem.Checked = false;
                                iToolStripMenuItem.Checked = false;
                                break;
                            case ProcessPriorities.High:
                                hToolStripMenuItem.Checked = true;

                                rttoolStripMenuItem.Checked = false;
                                anToolStripMenuItem.Checked = false;
                                nToolStripMenuItem.Checked = false;
                                bnToolStripMenuItem.Checked = false;
                                iToolStripMenuItem.Checked = false;
                                break;
                            case ProcessPriorities.Above_Normal:
                                anToolStripMenuItem.Checked = true;

                                rttoolStripMenuItem.Checked = false;
                                hToolStripMenuItem.Checked = false;
                                nToolStripMenuItem.Checked = false;
                                bnToolStripMenuItem.Checked = false;
                                iToolStripMenuItem.Checked = false;
                                break;
                            case ProcessPriorities.Normal:
                                nToolStripMenuItem.Checked = true;

                                rttoolStripMenuItem.Checked = false;
                                hToolStripMenuItem.Checked = false;
                                anToolStripMenuItem.Checked = false;
                                bnToolStripMenuItem.Checked = false;
                                iToolStripMenuItem.Checked = false;
                                break;
                            case ProcessPriorities.Below_Normal:
                                bnToolStripMenuItem.Checked = true;

                                rttoolStripMenuItem.Checked = false;
                                hToolStripMenuItem.Checked = false;
                                anToolStripMenuItem.Checked = false;
                                nToolStripMenuItem.Checked = false;
                                iToolStripMenuItem.Checked = false;
                                break;
                            case ProcessPriorities.Idle:
                                iToolStripMenuItem.Checked = true;

                                rttoolStripMenuItem.Checked = false;
                                hToolStripMenuItem.Checked = false;
                                anToolStripMenuItem.Checked = false;
                                nToolStripMenuItem.Checked = false;
                                bnToolStripMenuItem.Checked = false;
                                break;
                            default:
                                break;
                        }

                        CloseHandle(hProcess);
                    }
                }
            }
            //ProcessPriorities retuened = 
        }

        private void ToolStripMenuItem3Click(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                if (procid != 0)
                {
                    IntPtr hProcess =
                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, 0, (uint)procid);
                    if (hProcess != IntPtr.Zero && SetPriorityClass(hProcess, ProcessPriorities.Real_Time))
                    {
                        rttoolStripMenuItem.Checked = true;
                    }
                }
            }
        }

        private void HToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                if (procid != 0)
                {
                    IntPtr hProcess =
                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, 0, (uint)procid);
                    if (hProcess != IntPtr.Zero && SetPriorityClass(hProcess, ProcessPriorities.High))
                    {
                        hToolStripMenuItem.Checked = true;
                    }
                }
            }
        }

        private void AnToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                if (procid != 0)
                {
                    IntPtr hProcess =
                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, 0, (uint)procid);
                    if (hProcess != IntPtr.Zero && SetPriorityClass(hProcess, ProcessPriorities.Above_Normal))
                    {
                        anToolStripMenuItem.Checked = true;
                    }
                }
            }
        }
        private void NToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                if (procid != 0)
                {
                    IntPtr hProcess =
                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, 0, (uint)procid);
                    if (hProcess != IntPtr.Zero && SetPriorityClass(hProcess, ProcessPriorities.Normal))
                    {
                        nToolStripMenuItem.Checked = true;
                    }
                }
            }
        }

        private void BnToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                if (procid != 0)
                {
                    IntPtr hProcess =
                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, 0, (uint)procid);
                    if (hProcess != IntPtr.Zero && SetPriorityClass(hProcess, ProcessPriorities.Below_Normal))
                    {
                        bnToolStripMenuItem.Checked = true;
                    }
                }
            }
        }

        private void IToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                if (procid != 0)
                {
                    IntPtr hProcess =
                    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, 0, (uint)procid);
                    if (hProcess != IntPtr.Zero && SetPriorityClass(hProcess, ProcessPriorities.Idle))
                    {
                        iToolStripMenuItem.Checked = true;
                    }
                }
            }
        }

        private void TestToolStripMenuItemClick(object sender, EventArgs e)
        {
            EnumProcesses();
        }

        private void ExitToolStripMenuItemClick(object sender, EventArgs e)
        {
            Application.Exit();
        }

        private void AboutToolStripMenuItemClick(object sender, EventArgs e)
        {
            AboutForm abf = new();
            abf.Show();
        }

        private void ProcessManagerToolStripMenuItemClick(object sender, EventArgs e)
        {
            ProcessManager prman = new();
            prman.Show();
        }

        private void WindowsHoocksToolStripMenuItemClick(object sender, EventArgs e)
        {
            ViewWindowsHoocks wwh = new();
            wwh.Show();
        }

        private void InstalledFrameworkToolStripMenuItemClick(object sender, EventArgs e)
        {
            InstalledFramework insfr = new();
            insfr.Show();
        }

        private void VirtualMemoryToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                string strprname = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[0].Text;
                int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                VirtualMemoryView vmv = new(procid, strprname);
                vmv.Show();
            }
        }

        private void EnumAppdomainsToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                if (procid != 0)
                {
                    EnumAppDomains enumasm = new(procid);
                    enumasm.Show();
                }
            }
        }

        private void HookDetectionToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                string strprname = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[0].Text;
                if (strprname != "")
                {
                    int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                    EmptyForm hdet = new(strprname, procid, 1);
                    hdet.Show();
                }
            }
        }

        private void EnvironmentVariablesToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                string strprname = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[0].Text;
                int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                EmptyForm envenum = new(strprname, procid, 2);
                envenum.Show();
            }
        }

        private void ViewHeapToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                string strprname = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[0].Text;
                if (strprname != "")
                {
                    int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                    if ((uint)procid == HeapHealper.GetCurrentProcessId())
                    {
                        MessageBox.Show("Can't enumerate heap for MegaDumper itself!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                    else
                    {
                        HeapView hw = new(strprname, procid);
                        hw.Show();
                    }
                }
            }
        }

        private void NETPerformanceToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                string strprname = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[0].Text;
                if (strprname != "")
                {
                    int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                    NetPerformance np = new(strprname, procid);
                    np.Show();
                }
            }
        }

        private void GenerateDmpToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                string strprname = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[0].Text;
                string dirname = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[4].Text;
                if (strprname != "")
                {
                    int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                    GenerateDmp pmodfrm = new(strprname, procid, dirname);
                    pmodfrm.Show();
                }
            }
        }

        private void FileDirectoriesListToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                string strprname = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[0].Text;
                int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                EmptyForm envenum = new(strprname, procid, 3);
                envenum.Show();
            }
        }

        private void InjectManagedDllToolStripMenuItemClick(object sender, EventArgs e)
        {
            if (lvprocesslist.SelectedIndices.Count > 0)
            {
                string strprname = lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[0].Text;
                int procid = int.Parse(lvprocesslist.Items[lvprocesslist.SelectedIndices[0]].SubItems[1].Text);
                MegaDumper.ManagedInjector maninject = new(strprname, procid);
                maninject.Show();
            }
        }
    }
}
