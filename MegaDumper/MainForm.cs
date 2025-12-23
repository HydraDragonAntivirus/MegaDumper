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
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
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

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FreeLibrary(IntPtr hModule);

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
            string result = await Task.Run(() => DumpProcessLogic(processId, ddirs, true /* dumpNative */, true /* restoreFilename */));
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

        /// <summary>
        /// Create a deterministic 64-bit-ish hex string from pid + address.
        /// Uses FNV-1a 64-bit over the ASCII of "PID:ADDRESS" and returns uppercase hex.
        /// This is fast, deterministic, and small compared to SHA256.
        /// </summary>
        private string ComputeAddressHash(uint pid, ulong address)
        {
            try
            {
                string input = pid.ToString() + ":" + address.ToString("X16"); // stable textual input
                                                                               // FNV-1a 64-bit
                const ulong FNV_offset_basis = 14695981039346656037UL;
                const ulong FNV_prime = 1099511628211UL;
                ulong hash = FNV_offset_basis;
                foreach (byte b in Encoding.ASCII.GetBytes(input))
                {
                    hash ^= b;
                    hash *= FNV_prime;
                }
                return hash.ToString("X16"); // 16 hex chars (64-bit) uppercase
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Recursively scans a directory for PE files and writes their hashes to the writer.
        /// </summary>
        private void ScanDirectoryForPeFiles(string directoryPath, StreamWriter writer)
        {
            try
            {
                foreach (string file in Directory.EnumerateFiles(directoryPath, "*.exe"))
                {
                    try
                    {
                        if (IsPeFile(file))
                        {
                            string hash = ComputeSha256Hash(file);
                            if (!string.IsNullOrEmpty(hash))
                            {
                                writer.WriteLine(hash);
                            }
                        }
                    }
                    catch
                    {
                        // Ignore errors for individual files (e.g., access denied)
                    }
                }

                foreach (string directory in Directory.EnumerateDirectories(directoryPath))
                {
                    ScanDirectoryForPeFiles(directory, writer);
                }
            }
            catch (UnauthorizedAccessException)
            {
                // Ignore directories we cannot access
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Warning] Could not scan directory {directoryPath}: {ex.Message}");
            }
        }

        /// <summary>
        /// Checks if a file is a valid PE file by reading its headers.
        /// </summary>
        private bool IsPeFile(string filePath)
        {
            try
            {
                using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    if (fs.Length < 0x40) return false;
                    using (BinaryReader reader = new BinaryReader(fs))
                    {
                        // Check for 'MZ' signature at the beginning
                        if (reader.ReadUInt16() != 0x5A4D) return false;

                        // Seek to the PE Header offset field
                        fs.Seek(0x3C, SeekOrigin.Begin);
                        uint peHeaderOffset = reader.ReadUInt32();

                        if (fs.Length < peHeaderOffset + 4) return false;

                        // Seek to the PE Header and check for 'PE\0\0' signature
                        fs.Seek(peHeaderOffset, SeekOrigin.Begin);
                        if (reader.ReadUInt32() != 0x00004550) return false;

                        return true;
                    }
                }
            }
            catch
            {
                // File could be locked, unreadable, or cause other errors
                return false;
            }
        }

        /// <summary>
        /// Computes the SHA256 hash of a file.
        /// </summary>
        private string ComputeSha256Hash(string filePath)
        {
            try
            {
                using (SHA256 sha256 = SHA256.Create())
                {
                    using (FileStream fileStream = File.OpenRead(filePath))
                    {
                        byte[] hash = sha256.ComputeHash(fileStream);
                        var sb = new StringBuilder(hash.Length * 2);
                        foreach (byte b in hash)
                        {
                            sb.Append(b.ToString("x2"));
                        }
                        return sb.ToString();
                    }
                }
            }
            catch
            {
                // Handle file access errors
                return null;
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
                            string isnet = "-";

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
        // Add this simple fallback method to your MainForm class
        private bool SimpleDotNetCheck(int processId)
        {
            try
            {
                Process process = Process.GetProcessById(processId);

                // Check process name patterns
                string processName = process.ProcessName.ToLower();
                if (processName.Contains("dotnet") || processName.Contains("mono") ||
                    processName.EndsWith(".vshost"))
                {
                    process.Close();
                    return true;
                }

                // Check main module file name
                try
                {
                    string fileName = process.MainModule.FileName.ToLower();
                    if (fileName.Contains("framework") || fileName.Contains("dotnet") ||
                        fileName.Contains("system32\\mscoree.dll"))
                    {
                        process.Close();
                        return true;
                    }
                }
                catch
                {
                    // MainModule access denied, ignore
                }

                process.Close();
                return false;
            }
            catch
            {
                return false;
            }
        }

        // Safe memory checking method with minimal API calls
        private bool SafeMemoryCheck(int processId)
        {
            IntPtr hProcess = IntPtr.Zero;
            try
            {
                // Try only the most basic access level
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, (uint)processId);
                if (hProcess == IntPtr.Zero) return false;

                // Just check if we can access the process, don't scan memory extensively
                // This avoids most Win32Exception scenarios
                return true; // If we got this far, assume it might be .NET for now
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
                        int timeDateStamp = BitConverter.ToInt32(peHeaders, 8);
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
                    // Memory access denied for this region
                }

                // Try alternative validation - check for standard PE sections
                try
                {
                    return ValidateCommonPESections(hProcess, baseAddress, peOffset);
                }
                catch (System.ComponentModel.Win32Exception)
                {
                    // Memory access denied
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

        private bool ValidateCommonPESections(IntPtr hProcess, ulong baseAddress, int peOffset)
        {
            try
            {
                // Read section headers to validate PE structure
                byte[] sectionHeaders = new byte[512];
                uint bytesRead = 0;

                // Calculate sections table offset
                uint sectionsOffset = (uint)(peOffset + 24); // Skip PE signature + COFF header

                // Skip optional header
                byte[] optHeaderSize = new byte[2];
                if (ReadProcessMemory(hProcess, baseAddress + (uint)peOffset + 20, optHeaderSize, 2, ref bytesRead))
                {
                    short optSize = BitConverter.ToInt16(optHeaderSize, 0);
                    sectionsOffset += (uint)optSize;
                }
                else
                {
                    sectionsOffset += 240; // Assume standard optional header size
                }

                if (ReadProcessMemory(hProcess, baseAddress + sectionsOffset, sectionHeaders, 512, ref bytesRead))
                {
                    // Look for common section names
                    string sectionData = System.Text.Encoding.ASCII.GetString(sectionHeaders);

                    // Check for typical PE sections
                    return sectionData.Contains(".text") ||   // Code section
                           sectionData.Contains(".data") ||   // Data section
                           sectionData.Contains(".rdata") ||  // Read-only data
                           sectionData.Contains(".rsrc") ||   // Resources
                           sectionData.Contains(".reloc") ||  // Relocations
                           sectionData.Contains(".idata");   // Import data
                }
            }
            catch
            {
            }

            return false;
        }

        // Optional: Enhanced PE type detection
        private PEFileInfo GetPEFileInfo(IntPtr hProcess, uint baseAddress, int peOffset)
        {
            var fileInfo = new PEFileInfo();

            try
            {
                byte[] peHeaders = new byte[256];
                uint bytesRead = 0;

                if (ReadProcessMemory(hProcess, baseAddress + (uint)peOffset, peHeaders, 256, ref bytesRead))
                {
                    // Get machine type
                    short machine = BitConverter.ToInt16(peHeaders, 4);
                    fileInfo.Architecture = GetArchitectureName((ushort)machine);

                    // Get characteristics
                    short characteristics = BitConverter.ToInt16(peHeaders, 22);
                    fileInfo.IsDLL = (characteristics & 0x2000) != 0;
                    fileInfo.IsExecutable = (characteristics & 0x0002) != 0;
                    fileInfo.IsSystem = (characteristics & 0x1000) != 0; // IMAGE_FILE_SYSTEM

                    // Get timestamp
                    int timestamp = BitConverter.ToInt32(peHeaders, 8);
                    fileInfo.CompileTime = DateTimeOffset.FromUnixTimeSeconds(timestamp).DateTime;
                }
            }
            catch
            {
            }

            return fileInfo;
        }

        private string GetArchitectureName(ushort machine)
        {
            return machine switch
            {
                0x014c => "x86",
                0x8664 => "x64",
                0x01c0 => "ARM",
                0xaa64 => "ARM64",
                0x0200 => "IA64",
                0x01c4 => "ARMNT",
                _ => "Unknown"
            };
        }

        // Structure to hold PE file information
        public struct PEFileInfo
        {
            public string Architecture;
            public bool IsDLL;
            public bool IsExecutable;
            public bool IsSystem;
            public DateTime CompileTime;
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
                catch (System.ComponentModel.Win32Exception)
                {
                    // Module enumeration failed, skip to next method
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
                catch (System.ComponentModel.Win32Exception)
                {
                    return false;
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

        /// <summary>
        /// Checks if a process is a .NET assembly by looking for CLR metadata.
        /// </summary>
        /// <param name="processId">Process ID to check</param>
        /// <returns>True if .NET, false if native</returns>
        public bool IsNetProcess(int processId)
        {
            try
            {
                Process process = Process.GetProcessById(processId);
                if (process == null) return false;

                // Method 1: Check for mscoree.dll or clr.dll (CLR runtime)
                try
                {
                    ProcModule.ModuleInfo[] modules = ProcModule.GetModuleInfos(processId);
                    if (modules != null)
                    {
                        foreach (var module in modules)
                        {
                            if (!string.IsNullOrEmpty(module.baseName))
                            {
                                string lowerName = module.baseName.ToLower();
                                // Core CLR indicators
                                if (lowerName.Contains("mscoree.dll") || 
                                    lowerName.Contains("clr.dll") ||
                                    lowerName.Contains("clrjit.dll") ||
                                    lowerName.Contains("coreclr.dll") ||
                                    lowerName.Contains("mscorlib"))
                                {
                                    return true;
                                }
                            }
                        }
                    }
                }
                catch { }

                // Method 2: Check the PE header for CLR Data Directory
                try
                {
                    string mainModulePath = null;
                    try { mainModulePath = process.MainModule?.FileName; } catch { }
                    
                    if (!string.IsNullOrEmpty(mainModulePath) && File.Exists(mainModulePath))
                    {
                        byte[] header = new byte[0x200];
                        using (FileStream fs = new FileStream(mainModulePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                        {
                            fs.Read(header, 0, 0x200);
                        }

                        // Check MZ signature
                        if (header[0] != 0x4D || header[1] != 0x5A) return false;

                        int peOffset = BitConverter.ToInt32(header, 0x3C);
                        if (peOffset <= 0 || peOffset >= 0x180) return false;

                        // Check PE signature
                        if (header[peOffset] != 0x50 || header[peOffset + 1] != 0x45) return false;

                        // Check Optional Header magic to determine architecture
                        int optHeaderOffset = peOffset + 0x18;
                        ushort magic = BitConverter.ToUInt16(header, optHeaderOffset);
                        bool isPE64 = (magic == 0x20B);

                        // CLR Data Directory is at index 14
                        int dataDirOffset = optHeaderOffset + (isPE64 ? 112 : 96);
                        int clrDirOffset = dataDirOffset + (14 * 8);

                        if (clrDirOffset + 8 <= header.Length)
                        {
                            uint clrRva = BitConverter.ToUInt32(header, clrDirOffset);
                            uint clrSize = BitConverter.ToUInt32(header, clrDirOffset + 4);

                            if (clrRva > 0 && clrSize > 0)
                            {
                                return true;
                            }
                        }
                    }
                }
                catch { }

                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Gets the process type as a display string (NET, Native, or Unknown)
        /// </summary>
        public string GetProcessType(int processId)
        {
            try
            {
                // Simply check for .NET. If process is invalid/access denied, 
                // IsNetProcess returns false, so we default to "Native".
                bool isNet = IsNetProcess(processId);
                return isNet ? "NET" : "Native";
            }
            catch
            {
                return "Native";
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
                catch (InvalidOperationException)
                {
                    // Process exited between calls
                    return false;
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
            string isnet = "-";

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
                        isnet = "-";
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

            string originalTitle = Text;
            Text = "Dumping process... please wait.";
            Cursor = Cursors.WaitCursor;

            try
            {
                string result = await Task.Run(() => DumpProcessLogic(processId, ddirs, dumpNative, restoreFilename));
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
            if (nrofsection <= 0 || nrofsection > 96) return -1; // Max 96 sections is a common heuristic

            // Get SizeOfOptionalHeader to correctly calculate section table offset
            // This works for both PE32 (32-bit) and PE32+ (64-bit)
            if (input.Length < PEOffset + 0x14 + 2) return -1;
            short sizeOfOptionalHeader = BitConverter.ToInt16(input, PEOffset + 0x14);
            
            // Section table starts after: PE signature (4) + COFF header (20) + Optional header
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

            short sizeOfOptionalHeader = BitConverter.ToInt16(input, PEOffset + 0x14);
            int sectionTableStartOffset = PEOffset + 4 + 20 + sizeOfOptionalHeader;

            for (int i = 0; i < nrofsection; i++)
            {
                int sectionHeaderOffset = sectionTableStartOffset + (0x28 * i);

                if (input.Length < sectionHeaderOffset + 0x28) return -1;

                int virtualAddress = BitConverter.ToInt32(input, sectionHeaderOffset + 0x0C); // VirtualAddress
                // SizeOfRawData is at offset 0x10 from section header start (4 bytes)
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
                if (!File.Exists(filePath))
                {
                    Console.WriteLine($"[Scylla Sanitize] File not found: {filePath}");
                    return false;
                }

                byte[] fileData = File.ReadAllBytes(filePath);
                if (fileData.Length < 0x40)
                {
                    Console.WriteLine("[Scylla Sanitize] File too small to be a valid PE");
                    return false;
                }

                // Get PE offset
                int peOffset = BitConverter.ToInt32(fileData, 0x3C);
                if (peOffset < 0 || peOffset + 0x80 + 8 > fileData.Length)
                {
                    Console.WriteLine("[Scylla Sanitize] Invalid PE header offset");
                    return false;
                }

                // Check PE signature
                if (fileData[peOffset] != 'P' || fileData[peOffset + 1] != 'E')
                {
                    Console.WriteLine("[Scylla Sanitize] Invalid PE signature");
                    return false;
                }

                // Determine if PE32 or PE32+ (64-bit)
                ushort magic = BitConverter.ToUInt16(fileData, peOffset + 0x18);
                bool isPE32Plus = magic == 0x20b;

                // Import directory offset differs between PE32 and PE32+
                int importDirRvaOffset = isPE32Plus ? (peOffset + 0x90) : (peOffset + 0x80);

                if (importDirRvaOffset + 8 > fileData.Length)
                {
                    Console.WriteLine("[Scylla Sanitize] Cannot read import directory info");
                    return false;
                }

                int importDirRva = BitConverter.ToInt32(fileData, importDirRvaOffset);
                int importDirSize = BitConverter.ToInt32(fileData, importDirRvaOffset + 4);

                if (importDirRva == 0 || importDirSize == 0)
                {
                    Console.WriteLine("[Scylla Sanitize] No import directory found, nothing to sanitize");
                    return true;
                }

                // Convert RVA to file offset
                int importDirOffset = RVA2Offset(fileData, importDirRva);
                if (importDirOffset < 0 || importDirOffset >= fileData.Length)
                {
                    Console.WriteLine($"[Scylla Sanitize] Could not map import directory RVA 0x{importDirRva:X} to file offset");
                    return false;
                }

                Console.WriteLine($"[Scylla Sanitize] Scanning import directory at offset 0x{importDirOffset:X}");

                const int IMPORT_DESCRIPTOR_SIZE = 20; // sizeof(IMAGE_IMPORT_DESCRIPTOR)
                
                // First pass: collect all descriptors and determine which are valid
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
                    if (nameRva == 0)
                    {
                        // End of import directory
                        break;
                    }
                    
                    allDescriptors.Add(descriptor);

                    // Get the DLL name
                    int nameOffset = RVA2Offset(fileData, nameRva);
                    bool isValid = true;
                    string dllName = "<unknown>";

                    if (nameOffset < 0 || nameOffset >= fileData.Length)
                    {
                        isValid = false;
                        dllName = $"<invalid RVA 0x{nameRva:X}>";
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
                    {
                        validDescriptors.Add(descriptor);
                        Console.WriteLine($"[Scylla Sanitize] Valid import: {dllName}");
                    }
                    else
                    {
                        invalidNames.Add(dllName);
                        Console.WriteLine($"[Scylla Sanitize] REMOVING invalid import: \"{dllName}\"");
                    }

                    current += IMPORT_DESCRIPTOR_SIZE;
                }

                // Check if we need to modify the file
                if (invalidNames.Count == 0)
                {
                    Console.WriteLine("[Scylla Sanitize] No invalid imports found");
                    return true;
                }

                Console.WriteLine($"[Scylla Sanitize] Compacting import table: {validDescriptors.Count} valid, {invalidNames.Count} removed");

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
                Console.WriteLine($"[Scylla Sanitize] Writing sanitized file with {validDescriptors.Count} imports");
                File.WriteAllBytes(filePath, fileData);

                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Scylla Sanitize] Exception: {ex.Message}");
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

        private long GetRemoteCorExeMainAddress(int processId)
        {
            try
            {
                // 1. Get Local Address of _CorExeMain
                IntPtr hMscoree = LoadLibrary("mscoree.dll");
                if (hMscoree == IntPtr.Zero) return 0;
                
                IntPtr pLocalCorExeMain = GetProcAddress(hMscoree, "_CorExeMain");
                if (pLocalCorExeMain == IntPtr.Zero) return 0;

                long localOffset = (long)pLocalCorExeMain - (long)hMscoree;
                FreeLibrary(hMscoree);

                // 2. Get Remote Base Address of mscoree.dll
                using (var proc = Process.GetProcessById(processId))
                {
                    foreach (ProcessModule mod in proc.Modules)
                    {
                        if (mod.ModuleName.Equals("mscoree.dll", StringComparison.OrdinalIgnoreCase))
                        {
                            return (long)mod.BaseAddress + localOffset;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
               try { File.AppendAllText(Path.Combine("C:\\Dumps", "scylla_log.txt"), $"[GetRemoteCorExeMainAddress] Error: {ex.Message}\n"); } catch {}
            }
            return 0;
        }

        public bool FixImportandEntryPoint(long dumpVA, byte[] Dump, int processId = -1)
        {
            string logPath = Path.Combine("C:\\Dumps", "scylla_log.txt");
            try { File.AppendAllText(logPath, $"[FixImport] Starting for VA 0x{dumpVA:X}...\n"); } catch {}

            if (Dump == null || Dump.Length < 0x40) return false;

            int PEOffset = ReadInt32Safe(Dump, 0x3C);
            if (PEOffset < 0 || PEOffset >= Dump.Length - 0x100) return false;

            // Detect architecture
            ushort magic = BitConverter.ToUInt16(Dump, PEOffset + 24);
            bool isPE64 = (magic == 0x20B);

            int ImportDirectoryRva = ReadInt32Safe(Dump, PEOffset + (isPE64 ? 0x090 : 0x080));
            int impdiroffset = RVA2Offset(Dump, ImportDirectoryRva);
            if (impdiroffset == -1) 
            {
                try { File.AppendAllText(logPath, $"[FixImport] Error: Could not find Import Directory Offset for RVA 0x{ImportDirectoryRva:X}\n"); } catch {}
                return false;
            }

            // Check for CLR Runtime Header (DataDirectory[14])
            // If missing, this is not a .NET assembly, so skip mscoree fix without error.
            int clrDirOffset = PEOffset + 24 + (isPE64 ? 224 : 208);
            int clrRva = ReadInt32Safe(Dump, clrDirOffset);
            int clrSize = ReadInt32Safe(Dump, clrDirOffset + 4);

            if (clrRva == 0 || clrSize == 0)
            {
                // Not a .NET assembly (or effectively native)
                return false;
            }

            byte[] mscoreeAscii = { 0x6D, 0x73, 0x63, 0x6F, 0x72, 0x65, 0x65, 0x2E, 0x64, 0x6C, 0x6C, 0x00 };
            byte[] CorExeMain = { 0x5F, 0x43, 0x6F, 0x72, 0x45, 0x78, 0x65, 0x4D, 0x61, 0x69, 0x6E, 0x00 };
            byte[] CorDllMain = { 0x5F, 0x43, 0x6F, 0x72, 0x44, 0x6C, 0x6C, 0x4D, 0x61, 0x69, 0x6E, 0x00 };
            int ThunkToFix = 0;
            long ThunkData = 0;
            int ThunkToFixfo = 0; // Fixed: Variable scope issue
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

            if ((ThunkToFix <= 0 || ThunkData == 0) && processId != -1)
            {
                // Fallback: Try to find _CorExeMain by runtime address if we couldn't find it via Import Directory
                try 
                {
                    long remoteCorExeMain = GetRemoteCorExeMainAddress(processId);
                    if (remoteCorExeMain > 0)
                    {
                        try { File.AppendAllText(logPath, $"[FixImport] Searching for remote _CorExeMain address: 0x{remoteCorExeMain:X}\n"); } catch {}
                        
                         // Scan Dump for this address (It should be in the IAT)
                        for (int i = 0; i < Dump.Length - 8; i++)
                        {
                            // Check for 64-bit or 32-bit value
                            bool found = false;
                            if (isPE64)
                            {
                                if (BitConverter.ToInt64(Dump, i) == remoteCorExeMain) found = true;
                            }
                            else
                            {
                                if (BitConverter.ToInt32(Dump, i) == (int)remoteCorExeMain) found = true;
                            }

                            if (found)
                            {
                                // Verify this looks like valid IAT area (e.g. part of .rdata or .data)
                                // For now, just assume found.
                                int foundRVA = Offset2RVA(Dump, i);
                                if (foundRVA != -1)
                                {
                                     ThunkToFix = foundRVA;
                                     ThunkData = remoteCorExeMain;
                                     ThunkToFixfo = i;
                                     try { File.AppendAllText(logPath, $"[FixImport] Found _CorExeMain IAT Thunk via signature scan at FileOffset 0x{i:X} (RVA 0x{foundRVA:X})\n"); } catch {}
                                     break;
                                }
                            }
                        }
                    }
                }
                catch (Exception ex) 
                {
                     try { File.AppendAllText(logPath, $"[FixImport] Signature Scan Error: {ex.Message}\n"); } catch {}
                }
            }

            if (ThunkToFix <= 0 || ThunkData == 0) 
            {
                try { File.AppendAllText(logPath, $"[FixImport] Error: Could not find mscoree thunk to fix.\n"); } catch {}
                return false;
            }

            int ThunkToFixfo_Final = (ThunkToFixfo > 0) ? ThunkToFixfo : RVA2Offset(Dump, ThunkToFix);
            if (ThunkToFixfo_Final == -1) return false;

            using var ms = new MemoryStream(Dump);
            BinaryWriter writer = new(ms);

            // We already have ThunkData from scan or walk, so we can skip reading currentThunkValue if we found it via scan
            // But if we found it via scan, ThunkToFixfo is set.
            
            // Just ensure header matches.
            ms.Position = ThunkToFixfo_Final;
            if (isPE64)
                 writer.Write((long)ThunkData);
            else
                 writer.Write((int)ThunkData);

            int EntryPointOffset = PEOffset + 0x028;
            int EntryPoint = ReadInt32Safe(Dump, EntryPointOffset);

            if (EntryPoint <= 0 || RVA2Offset(Dump, EntryPoint) == -1)
            {
                long realThunkAddress = dumpVA + ThunkToFix;
                try { File.AppendAllText(logPath, $"[FixImport] Patched IAT Thunk at RVA 0x{ThunkToFix:X}, Address 0x{realThunkAddress:X}.\n"); } catch {}
                try { File.AppendAllText(logPath, $"[FixImport] Searching for jump stub to 0x{realThunkAddress:X}...\n"); } catch {}

                if (isPE64)
                {
                    // For x64, we search for FF 25 [Rel32] pointing to the thunk
                    // The rel32 is RIP-relative, so we need to calculate using RVA, not file offset
                    for (int i = 0; i < Dump.Length - 6; i++)
                    {
                        if (Dump[i] == 0xFF && Dump[i + 1] == 0x25)
                        {
                            int currentRVA = Offset2RVA(Dump, i);
                            if (currentRVA == -1) continue;
                            
                            int rel32 = BitConverter.ToInt32(Dump, i + 2);
                            // RIP-relative: target = RIP + rel32, where RIP = instruction address + 6
                            long targetVA = (long)dumpVA + currentRVA + 6 + rel32;
                            
                            if (targetVA == realThunkAddress)
                            {
                                try { File.AppendAllText(logPath, $"[FixImport] Detected Entry Point at RVA 0x{currentRVA:X} (File Offset 0x{i:X}). Patching...\n"); } catch {}
                                ms.Position = EntryPointOffset;
                                writer.Write(currentRVA);
                                break;
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
                                try { File.AppendAllText(logPath, $"[FixImport] Detected Entry Point at RVA 0x{EntrPointRVA:X} (File Offset 0x{i:X}). Patching...\n"); } catch {}
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

        #region Native Executable Dumper Support

        /// <summary>
        /// Detects the entry point for native (non-.NET) executables using generic heuristics.
        /// Works with any packer by analyzing code patterns and section characteristics.
        /// </summary>
        /// <param name="hProcess">Handle to the target process</param>
        /// <param name="imageBase">Base address of the module in memory</param>
        /// <param name="peData">PE header and section data from memory</param>
        /// <param name="is64Bit">Whether the target is 64-bit</param>
        /// <param name="logPath">Path to log file for debugging</param>
        /// <returns>Detected entry point VA, or 0 if not found</returns>
        private ulong DetectNativeEntryPoint(IntPtr hProcess, ulong imageBase, byte[] peData, bool is64Bit, string logPath = null)
        {
            if (peData == null || peData.Length < 0x200)
                return 0;

            try
            {
                int peOffset = BitConverter.ToInt32(peData, 0x3C);
                if (peOffset <= 0 || peOffset >= peData.Length - 0x100)
                    return 0;

                // 1. First try: PE Header Entry Point (most reliable for unpacked/simple packed)
                int optHeaderOffset = peOffset + 0x18;
                int epRvaOffset = optHeaderOffset + 16; // AddressOfEntryPoint
                uint headerEpRva = BitConverter.ToUInt32(peData, epRvaOffset);
                
                if (headerEpRva > 0)
                {
                    // Validate EP points to an executable section
                    int epFileOffset = RVA2Offset(peData, (int)headerEpRva);
                    if (epFileOffset != -1 && epFileOffset < peData.Length)
                    {
                        // Check if there's actual code at EP (not zeroed or garbage)
                        bool hasCode = false;
                        for (int i = 0; i < Math.Min(16, peData.Length - epFileOffset); i++)
                        {
                            if (peData[epFileOffset + i] != 0x00 && peData[epFileOffset + i] != 0xCC)
                            {
                                hasCode = true;
                                break;
                            }
                        }
                        
                        if (hasCode)
                        {
                            LogNative(logPath, $"[NativeEP] Using PE Header Entry Point: RVA 0x{headerEpRva:X}");
                            return imageBase + headerEpRva;
                        }
                    }
                }

                // 2. Second try: TLS Callback detection (some packers use TLS for anti-debug)
                ulong tlsEp = DetectTLSCallback(peData, is64Bit, imageBase, logPath);
                if (tlsEp > 0)
                {
                    LogNative(logPath, $"[NativeEP] Found TLS Callback at: 0x{tlsEp:X}");
                }

                // 3. Third try: Generic code pattern detection
                ulong codeEp = DetectCodeEntryPattern(peData, is64Bit, imageBase, logPath);
                if (codeEp > 0)
                {
                    return codeEp;
                }

                // 4. Fourth try: Search for jump stubs to known runtime functions
                ulong jumpEp = DetectJumpStubEntry(hProcess, imageBase, peData, is64Bit, logPath);
                if (jumpEp > 0)
                {
                    return jumpEp;
                }

                // Fallback: Return header EP even if validation failed
                if (headerEpRva > 0)
                {
                    LogNative(logPath, $"[NativeEP] Fallback to Header EP (unvalidated): RVA 0x{headerEpRva:X}");
                    return imageBase + headerEpRva;
                }
            }
            catch (Exception ex)
            {
                LogNative(logPath, $"[NativeEP] Error: {ex.Message}");
            }

            return 0;
        }

        /// <summary>
        /// Detects TLS callbacks that may execute before the entry point.
        /// </summary>
        private ulong DetectTLSCallback(byte[] peData, bool is64Bit, ulong imageBase, string logPath)
        {
            try
            {
                int peOffset = BitConverter.ToInt32(peData, 0x3C);
                int optHeaderOffset = peOffset + 0x18;
                int dataDirOffset = optHeaderOffset + (is64Bit ? 112 : 96);
                
                int tlsDirOffset = dataDirOffset + (9 * 8);
                if (tlsDirOffset + 8 > peData.Length) return 0;
                
                uint tlsRva = BitConverter.ToUInt32(peData, tlsDirOffset);
                uint tlsSize = BitConverter.ToUInt32(peData, tlsDirOffset + 4);
                
                if (tlsRva == 0 || tlsSize == 0) return 0;
                
                int tlsOffset = RVA2Offset(peData, (int)tlsRva);
                if (tlsOffset == -1) return 0;
                
                int callbackOffset = tlsOffset + (is64Bit ? 24 : 12);
                if (callbackOffset + (is64Bit ? 8 : 4) > peData.Length) return 0;
                
                ulong callbackTableVA = is64Bit 
                    ? BitConverter.ToUInt64(peData, callbackOffset)
                    : BitConverter.ToUInt32(peData, callbackOffset);
                
                if (callbackTableVA > 0)
                {
                    LogNative(logPath, $"[NativeEP] TLS Callback table found at VA: 0x{callbackTableVA:X}");
                    return callbackTableVA;
                }
            }
            catch { }
            return 0;
        }

        /// <summary>
        /// Detects entry point by looking for common code patterns (generic for all packers).
        /// </summary>
        private ulong DetectCodeEntryPattern(byte[] peData, bool is64Bit, ulong imageBase, string logPath)
        {
            try
            {
                int peOffset = BitConverter.ToInt32(peData, 0x3C);
                int numSections = BitConverter.ToInt16(peData, peOffset + 6);
                int sizeOfOptHeader = BitConverter.ToInt16(peData, peOffset + 20);
                int sectionTableOffset = peOffset + 24 + sizeOfOptHeader;
                
                for (int s = 0; s < numSections && s < 96; s++)
                {
                    int secOffset = sectionTableOffset + (s * 40);
                    if (secOffset + 40 > peData.Length) break;
                    
                    uint characteristics = BitConverter.ToUInt32(peData, secOffset + 36);
                    bool isExecutable = (characteristics & 0x20000000) != 0 || (characteristics & 0x00000020) != 0;
                    
                    if (!isExecutable) continue;
                    
                    uint secRva = BitConverter.ToUInt32(peData, secOffset + 12);
                    uint secVSize = BitConverter.ToUInt32(peData, secOffset + 8);
                    int secFileOffset = RVA2Offset(peData, (int)secRva);
                    
                    if (secFileOffset == -1) continue;
                    
                    int scanLimit = Math.Min((int)secVSize, peData.Length - secFileOffset);
                    scanLimit = Math.Min(scanLimit, 0x100000);
                    
                    for (int i = 0; i < scanLimit - 16; i++)
                    {
                        int offset = secFileOffset + i;
                        if (offset + 16 >= peData.Length) break;
                        
                        bool patternFound = false;
                        
                        if (is64Bit)
                        {
                            if ((peData[offset] == 0x48 && peData[offset + 1] == 0x83 && peData[offset + 2] == 0xEC) ||
                                (peData[offset] == 0x48 && peData[offset + 1] == 0x81 && peData[offset + 2] == 0xEC) ||
                                (peData[offset] == 0x53 && peData[offset + 1] == 0x48 && peData[offset + 2] == 0x83 && peData[offset + 3] == 0xEC) ||
                                (peData[offset] == 0x40 && peData[offset + 1] == 0x53 && peData[offset + 2] == 0x48))
                            {
                                patternFound = true;
                            }
                        }
                        else
                        {
                            if ((peData[offset] == 0x55 && peData[offset + 1] == 0x8B && peData[offset + 2] == 0xEC) ||
                                (peData[offset] == 0x55 && peData[offset + 1] == 0x89 && peData[offset + 2] == 0xE5) ||
                                (peData[offset] == 0x83 && peData[offset + 1] == 0xEC) ||
                                (peData[offset] == 0x81 && peData[offset + 1] == 0xEC))
                            {
                                patternFound = true;
                            }
                        }
                        
                        if (patternFound)
                        {
                            int foundRva = Offset2RVA(peData, offset);
                            if (foundRva != -1)
                            {
                                LogNative(logPath, $"[NativeEP] Found code entry pattern at RVA 0x{foundRva:X} (section {s})");
                                return imageBase + (ulong)foundRva;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogNative(logPath, $"[NativeEP] Pattern detection error: {ex.Message}");
            }
            return 0;
        }

        /// <summary>
        /// Detects entry point by finding jump stubs (JMP instructions).
        /// Generic approach that works with many packers.
        /// </summary>
        private ulong DetectJumpStubEntry(IntPtr hProcess, ulong imageBase, byte[] peData, bool is64Bit, string logPath)
        {
            try
            {
                int peOffset = BitConverter.ToInt32(peData, 0x3C);
                uint headerEpRva = BitConverter.ToUInt32(peData, peOffset + 0x28);
                
                if (headerEpRva == 0) return 0;
                
                int epOffset = RVA2Offset(peData, (int)headerEpRva);
                if (epOffset == -1 || epOffset + 16 >= peData.Length) return 0;
                
                byte firstByte = peData[epOffset];
                
                if (firstByte == 0xE9 && epOffset + 5 <= peData.Length)
                {
                    int rel32 = BitConverter.ToInt32(peData, epOffset + 1);
                    int targetRva = (int)headerEpRva + 5 + rel32;
                    
                    if (targetRva > 0)
                    {
                        LogNative(logPath, $"[NativeEP] EP is JMP stub, real entry at RVA 0x{targetRva:X}");
                        return imageBase + (ulong)targetRva;
                    }
                }
                
                if (firstByte == 0xEB && epOffset + 2 <= peData.Length)
                {
                    sbyte rel8 = (sbyte)peData[epOffset + 1];
                    int targetRva = (int)headerEpRva + 2 + rel8;
                    
                    if (targetRva > 0)
                    {
                        LogNative(logPath, $"[NativeEP] EP is short JMP stub, real entry at RVA 0x{targetRva:X}");
                        return imageBase + (ulong)targetRva;
                    }
                }
                
                if (firstByte == 0xFF && peData[epOffset + 1] == 0x25)
                {
                    if (is64Bit)
                    {
                        int rel32 = BitConverter.ToInt32(peData, epOffset + 2);
                        int targetPtrRva = (int)headerEpRva + 6 + rel32;
                        int targetPtrOffset = RVA2Offset(peData, targetPtrRva);
                        
                        if (targetPtrOffset != -1 && targetPtrOffset + 8 <= peData.Length)
                        {
                            ulong realTarget = BitConverter.ToUInt64(peData, targetPtrOffset);
                            if (realTarget > imageBase && realTarget < imageBase + 0x10000000)
                            {
                                LogNative(logPath, $"[NativeEP] EP is indirect JMP, target VA: 0x{realTarget:X}");
                                return realTarget;
                            }
                        }
                    }
                    else
                    {
                        uint targetPtr = BitConverter.ToUInt32(peData, epOffset + 2);
                        uint targetPtrRva = targetPtr - (uint)imageBase;
                        int targetPtrOffset = RVA2Offset(peData, (int)targetPtrRva);
                        
                        if (targetPtrOffset != -1 && targetPtrOffset + 4 <= peData.Length)
                        {
                            uint realTarget = BitConverter.ToUInt32(peData, targetPtrOffset);
                            if (realTarget > imageBase && realTarget < imageBase + 0x10000000)
                            {
                                LogNative(logPath, $"[NativeEP] EP is indirect JMP, target VA: 0x{realTarget:X}");
                                return realTarget;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogNative(logPath, $"[NativeEP] Jump stub detection error: {ex.Message}");
            }
            return 0;
        }

        /// <summary>
        /// Validates and repairs corrupted PE headers in dumped files.
        /// </summary>
        private bool ValidateAndRepairPEHeader(byte[] peData, ulong imageBase, string logPath = null)
        {
            if (peData == null || peData.Length < 0x200) return false;
            
            try
            {
                if (peData[0] != 0x4D || peData[1] != 0x5A)
                {
                    LogNative(logPath, "[PE Repair] Invalid DOS header, fixing...");
                    peData[0] = 0x4D;
                    peData[1] = 0x5A;
                }
                
                int peOffset = BitConverter.ToInt32(peData, 0x3C);
                if (peOffset <= 0 || peOffset >= peData.Length - 0x100)
                {
                    LogNative(logPath, "[PE Repair] Invalid PE offset, cannot repair");
                    return false;
                }
                
                if (peData[peOffset] != 0x50 || peData[peOffset + 1] != 0x45 ||
                    peData[peOffset + 2] != 0x00 || peData[peOffset + 3] != 0x00)
                {
                    LogNative(logPath, "[PE Repair] Invalid PE signature, fixing...");
                    peData[peOffset] = 0x50;
                    peData[peOffset + 1] = 0x45;
                    peData[peOffset + 2] = 0x00;
                    peData[peOffset + 3] = 0x00;
                }
                
                int optHeaderOffset = peOffset + 0x18;
                ushort magic = BitConverter.ToUInt16(peData, optHeaderOffset);
                bool is64 = magic == 0x20B;
                
                if (magic != 0x10B && magic != 0x20B)
                {
                    LogNative(logPath, $"[PE Repair] Invalid Optional Header magic 0x{magic:X}");
                    return false;
                }
                
                uint sizeOfImage = BitConverter.ToUInt32(peData, optHeaderOffset + 56);
                int numSections = BitConverter.ToInt16(peData, peOffset + 6);
                int sizeOfOptHeader = BitConverter.ToInt16(peData, peOffset + 20);
                int sectionTableOffset = peOffset + 24 + sizeOfOptHeader;
                
                uint calculatedSize = 0;
                uint sectionAlignment = BitConverter.ToUInt32(peData, optHeaderOffset + 32);
                
                for (int s = 0; s < numSections && s < 96; s++)
                {
                    int secOffset = sectionTableOffset + (s * 40);
                    if (secOffset + 40 > peData.Length) break;
                    
                    uint secRva = BitConverter.ToUInt32(peData, secOffset + 12);
                    uint secVSize = BitConverter.ToUInt32(peData, secOffset + 8);
                    
                    uint alignedEnd = secRva + secVSize;
                    if (sectionAlignment > 0)
                    {
                        uint remainder = alignedEnd % sectionAlignment;
                        if (remainder != 0) alignedEnd += sectionAlignment - remainder;
                    }
                    
                    if (alignedEnd > calculatedSize) calculatedSize = alignedEnd;
                }
                
                if (calculatedSize > sizeOfImage && calculatedSize > 0)
                {
                    LogNative(logPath, $"[PE Repair] Fixing SizeOfImage from 0x{sizeOfImage:X} to 0x{calculatedSize:X}");
                    Array.Copy(BitConverter.GetBytes(calculatedSize), 0, peData, optHeaderOffset + 56, 4);
                }
                
                uint fileAlignment = BitConverter.ToUInt32(peData, optHeaderOffset + 36);
                if (fileAlignment != sectionAlignment && sectionAlignment > 0)
                {
                    LogNative(logPath, $"[PE Repair] Setting FileAlignment to SectionAlignment (0x{sectionAlignment:X})");
                    Array.Copy(BitConverter.GetBytes(sectionAlignment), 0, peData, optHeaderOffset + 36, 4);
                }
                
                ulong headerImageBase = is64 
                    ? BitConverter.ToUInt64(peData, optHeaderOffset + 24)
                    : BitConverter.ToUInt32(peData, optHeaderOffset + 28);
                
                if (headerImageBase != imageBase && imageBase > 0)
                {
                    LogNative(logPath, $"[PE Repair] Fixing ImageBase from 0x{headerImageBase:X} to 0x{imageBase:X}");
                    if (is64)
                        Array.Copy(BitConverter.GetBytes(imageBase), 0, peData, optHeaderOffset + 24, 8);
                    else
                        Array.Copy(BitConverter.GetBytes((uint)imageBase), 0, peData, optHeaderOffset + 28, 4);
                }
                
                return true;
            }
            catch (Exception ex)
            {
                LogNative(logPath, $"[PE Repair] Error: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Finds the Import Address Table for native executables using generic methods.
        /// </summary>
        private bool FindNativeImports(IntPtr hProcess, ulong imageBase, byte[] peData, out uint iatRva, out uint iatSize, string logPath = null)
        {
            iatRva = 0;
            iatSize = 0;
            
            try
            {
                int peOffset = BitConverter.ToInt32(peData, 0x3C);
                if (peOffset <= 0 || peOffset >= peData.Length - 0x100) return false;
                
                int optHeaderOffset = peOffset + 0x18;
                ushort magic = BitConverter.ToUInt16(peData, optHeaderOffset);
                bool is64 = magic == 0x20B;
                int dataDirOffset = optHeaderOffset + (is64 ? 112 : 96);
                
                if (dataDirOffset + (12 * 8) + 8 <= peData.Length)
                {
                    iatRva = BitConverter.ToUInt32(peData, dataDirOffset + (12 * 8));
                    iatSize = BitConverter.ToUInt32(peData, dataDirOffset + (12 * 8) + 4);
                    
                    if (iatRva > 0 && iatSize > 0)
                    {
                        LogNative(logPath, $"[FindImports] Found IAT in Data Directory: RVA=0x{iatRva:X}, Size=0x{iatSize:X}");
                        return true;
                    }
                }
                
                if (dataDirOffset + 8 <= peData.Length)
                {
                    uint importRva = BitConverter.ToUInt32(peData, dataDirOffset + 8);
                    uint importSize = BitConverter.ToUInt32(peData, dataDirOffset + 12);
                    
                    if (importRva > 0 && importSize > 0)
                    {
                        int importOffset = RVA2Offset(peData, (int)importRva);
                        if (importOffset != -1)
                        {
                            uint minIatRva = uint.MaxValue;
                            uint maxIatEnd = 0;
                            
                            int current = importOffset;
                            while (current + 20 <= peData.Length)
                            {
                                uint name = BitConverter.ToUInt32(peData, current + 12);
                                uint firstThunk = BitConverter.ToUInt32(peData, current + 16);
                                
                                if (name == 0 && firstThunk == 0) break;
                                
                                if (firstThunk > 0)
                                {
                                    if (firstThunk < minIatRva) minIatRva = firstThunk;
                                    
                                    int thunkOffset = RVA2Offset(peData, (int)firstThunk);
                                    if (thunkOffset != -1)
                                    {
                                        int entrySize = is64 ? 8 : 4;
                                        int count = 0;
                                        while (thunkOffset + (count + 1) * entrySize <= peData.Length)
                                        {
                                            ulong entry = is64 
                                                ? BitConverter.ToUInt64(peData, thunkOffset + count * entrySize)
                                                : BitConverter.ToUInt32(peData, thunkOffset + count * entrySize);
                                            if (entry == 0) break;
                                            count++;
                                        }
                                        uint thunkEnd = firstThunk + (uint)(count * entrySize);
                                        if (thunkEnd > maxIatEnd) maxIatEnd = thunkEnd;
                                    }
                                }
                                
                                current += 20;
                            }
                            
                            if (minIatRva < uint.MaxValue && maxIatEnd > minIatRva)
                            {
                                iatRva = minIatRva;
                                iatSize = maxIatEnd - minIatRva;
                                LogNative(logPath, $"[FindImports] Calculated IAT from Import Directory: RVA=0x{iatRva:X}, Size=0x{iatSize:X}");
                                return true;
                            }
                        }
                    }
                }
                
                LogNative(logPath, "[FindImports] Trying pointer cluster detection...");
                return FindIATByPointerCluster(hProcess, imageBase, peData, out iatRva, out iatSize, is64, logPath);
            }
            catch (Exception ex)
            {
                LogNative(logPath, $"[FindImports] Error: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Finds IAT by scanning for clusters of pointers to system DLLs.
        /// </summary>
        private bool FindIATByPointerCluster(IntPtr hProcess, ulong imageBase, byte[] peData, out uint iatRva, out uint iatSize, bool is64, string logPath)
        {
            iatRva = 0;
            iatSize = 0;
            
            try
            {
                int peOffset = BitConverter.ToInt32(peData, 0x3C);
                int numSections = BitConverter.ToInt16(peData, peOffset + 6);
                int sizeOfOptHeader = BitConverter.ToInt16(peData, peOffset + 20);
                int sectionTableOffset = peOffset + 24 + sizeOfOptHeader;
                
                int entrySize = is64 ? 8 : 4;
                int minClusterSize = 8;
                
                for (int s = 0; s < numSections && s < 96; s++)
                {
                    int secOffset = sectionTableOffset + (s * 40);
                    if (secOffset + 40 > peData.Length) break;
                    
                    string secName = "";
                    for (int n = 0; n < 8 && peData[secOffset + n] != 0; n++)
                        secName += (char)peData[secOffset + n];
                    
                    if (!secName.StartsWith(".rdata") && !secName.StartsWith(".idata") && 
                        !secName.StartsWith(".data") && !secName.StartsWith(".text"))
                        continue;
                    
                    uint secRva = BitConverter.ToUInt32(peData, secOffset + 12);
                    uint secVSize = BitConverter.ToUInt32(peData, secOffset + 8);
                    int secFileOffset = RVA2Offset(peData, (int)secRva);
                    
                    if (secFileOffset == -1) continue;
                    
                    int scanLimit = Math.Min((int)secVSize, peData.Length - secFileOffset);
                    
                    int clusterStart = -1;
                    int clusterCount = 0;
                    
                    for (int i = 0; i < scanLimit - entrySize; i += entrySize)
                    {
                        int offset = secFileOffset + i;
                        if (offset + entrySize > peData.Length) break;
                        
                        ulong ptr = is64 
                            ? BitConverter.ToUInt64(peData, offset)
                            : BitConverter.ToUInt32(peData, offset);
                        
                        bool isSystemPtr = is64 
                            ? (ptr >= 0x00007F0000000000 && ptr <= 0x00007FFFFFFFFFFF)
                            : (ptr >= 0x70000000 && ptr <= 0x7FFFFFFF);
                        
                        if (isSystemPtr)
                        {
                            if (clusterStart == -1) clusterStart = i;
                            clusterCount++;
                        }
                        else if (ptr == 0 && clusterCount >= minClusterSize)
                        {
                            iatRva = secRva + (uint)clusterStart;
                            iatSize = (uint)((clusterCount + 1) * entrySize);
                            LogNative(logPath, $"[FindImports] Found pointer cluster in {secName}: RVA=0x{iatRva:X}, Size=0x{iatSize:X}");
                            return true;
                        }
                        else
                        {
                            clusterStart = -1;
                            clusterCount = 0;
                        }
                    }
                    
                    if (clusterCount >= minClusterSize)
                    {
                        iatRva = secRva + (uint)clusterStart;
                        iatSize = (uint)(clusterCount * entrySize);
                        LogNative(logPath, $"[FindImports] Found pointer cluster in {secName}: RVA=0x{iatRva:X}, Size=0x{iatSize:X}");
                        return true;
                    }
                }
            }
            catch (Exception ex)
            {
                LogNative(logPath, $"[FindImports] Cluster detection error: {ex.Message}");
            }
            
            return false;
        }

        /// <summary>
        /// Performs comprehensive post-dump fixes for native executables.
        /// </summary>
        private bool FixNativeDump(string dumpPath, uint processId, ulong imageBase, string logPath = null)
        {
            try
            {
                if (!File.Exists(dumpPath)) return false;
                
                byte[] peData = File.ReadAllBytes(dumpPath);
                if (peData.Length < 0x200) return false;
                
                LogNative(logPath, $"[FixNative] Starting native dump fix for: {Path.GetFileName(dumpPath)}");
                
                if (!ValidateAndRepairPEHeader(peData, imageBase, logPath))
                {
                    LogNative(logPath, "[FixNative] PE header repair failed");
                    return false;
                }
                
                int peOffset = BitConverter.ToInt32(peData, 0x3C);
                int optHeaderOffset = peOffset + 0x18;
                ushort magic = BitConverter.ToUInt16(peData, optHeaderOffset);
                bool is64 = magic == 0x20B;
                
                IntPtr hProcess = OpenProcess(0x0010, 0, processId);
                if (hProcess != IntPtr.Zero)
                {
                    try
                    {
                        ulong detectedEp = DetectNativeEntryPoint(hProcess, imageBase, peData, is64, logPath);
                        if (detectedEp > imageBase)
                        {
                            uint epRva = (uint)(detectedEp - imageBase);
                            uint currentEpRva = BitConverter.ToUInt32(peData, optHeaderOffset + 16);
                            
                            if (epRva != currentEpRva && epRva < 0x10000000)
                            {
                                LogNative(logPath, $"[FixNative] Updating EP from RVA 0x{currentEpRva:X} to 0x{epRva:X}");
                                Array.Copy(BitConverter.GetBytes(epRva), 0, peData, optHeaderOffset + 16, 4);
                            }
                        }
                        
                        if (FindNativeImports(hProcess, imageBase, peData, out uint iatRva, out uint iatSize, logPath))
                        {
                            LogNative(logPath, $"[FixNative] Native imports located: IAT RVA=0x{iatRva:X}, Size=0x{iatSize:X}");
                            
                            int iatOffset = RVA2Offset(peData, (int)iatRva);
                            if (iatOffset != -1 && iatOffset + iatSize <= peData.Length)
                            {
                                byte[] iatBuffer = new byte[iatSize];
                                uint bytesRead = 0;
                                if (ReadProcessMemoryW(hProcess, imageBase + iatRva, iatBuffer, (UIntPtr)iatSize, out bytesRead))
                                {
                                    if (bytesRead == iatSize)
                                    {
                                        Array.Copy(iatBuffer, 0, peData, iatOffset, iatSize);
                                        LogNative(logPath, "[FixNative] Re-patched IAT from live process memory");
                                    }
                                }
                            }
                        }
                    }
                    finally
                    {
                        CloseHandle(hProcess);
                    }
                }
                
                File.WriteAllBytes(dumpPath, peData);
                LogNative(logPath, "[FixNative] Native dump fix completed successfully");
                return true;
            }
            catch (Exception ex)
            {
                LogNative(logPath, $"[FixNative] Error: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Helper method for native dumper logging.
        /// </summary>
        private void LogNative(string logPath, string message)
        {
            if (string.IsNullOrEmpty(logPath)) return;
            try { File.AppendAllText(logPath, $"[{DateTime.Now:HH:mm:ss}] {message}\n"); } catch { }
        }

        #endregion

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
            dpmdirs.nativedirname = Path.Combine(dpmdirs.dumps, "Native");
            dpmdirs.sysdirname = Path.Combine(dpmdirs.dumps, "System");
            dpmdirs.unknowndirname = Path.Combine(dpmdirs.dumps, "UnknownName");
        }

        public bool CreateDirectories(ref DUMP_DIRECTORIES dpmdirs)
        {
            SetDirectoriesPath(ref dpmdirs);

            if (!TryCreateDirectoryWithFallback(dpmdirs.dumps, ref dpmdirs)) return false;
            if (!TryCreateDirectoryWithFallback(dpmdirs.nativedirname, ref dpmdirs)) return false;
            if (!TryCreateDirectoryWithFallback(dpmdirs.sysdirname, ref dpmdirs)) return false;
            if (!TryCreateDirectoryWithFallback(dpmdirs.unknowndirname, ref dpmdirs)) return false;

            return true;
        }

        private bool TryCreateDirectoryWithFallback(string dirPath, ref DUMP_DIRECTORIES dpmdirs)
        {
            if (Directory.Exists(dirPath)) return true;

            try
            {
                Directory.CreateDirectory(dirPath);
                return true;
            }
            catch
            {
                FolderBrowserDialog browse = new()
                {
                    ShowNewFolderButton = false,
                    Description = "Failed to create the directory - select a new location:",
                    SelectedPath = dpmdirs.root
                };

                if (browse.ShowDialog() == DialogResult.OK)
                {
                    dpmdirs.root = browse.SelectedPath;
                    return CreateDirectories(ref dpmdirs);
                }
                return false;
            }
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

        private MegaDumper.ScyllaError TryManualIATRecovery(string dumpedFile, uint processId, ulong imageBase, string scyFixFilename, string logPath)
        {
            try
            {
                File.AppendAllText(logPath, $"[{DateTime.Now:HH:mm:ss}] Attempting Manual IAT Recovery...\n");
                
                byte[] pData = File.ReadAllBytes(dumpedFile);
                IntPtr hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, processId);
                
                try
                {
                    if (FindNativeImports(hProcess, imageBase, pData, out uint iatRva, out uint iatSize, logPath)) 
                    {
                         File.AppendAllText(logPath, $"  Calling Scylla IatFix (RVA=0x{iatRva:X}, Size=0x{iatSize:X})...\n");
                         return MegaDumper.ScyllaBindings.IatFix(
                            processId,
                            imageBase,
                            (UIntPtr)(imageBase + iatRva),
                            iatSize,
                            true,
                            dumpedFile,
                            scyFixFilename);
                    }
                }
                finally
                {
                    if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
                }
                
                return MegaDumper.ScyllaError.IatSearchError;
            }
            catch (Exception ex)
            {
                File.AppendAllText(logPath, $"  Manual recovery exception: {ex.Message}\n");
                return MegaDumper.ScyllaError.IatSearchError;
            }
        }

        private MegaDumper.ScyllaError ProcessDumpWithScylla(string dumpedFile, uint processId, ulong imageBase, string scyFixFilename, string logPath, bool isPass2 = false)
        {
            string passPrefix = isPass2 ? "[Pass 2] " : "";
            
            // Just read header EP for simple fallback
            ulong entryPoint = imageBase; 
            try {
                byte[] header = new byte[0x400];
                using (FileStream fs = new FileStream(dumpedFile, FileMode.Open, FileAccess.Read)) { fs.Read(header, 0, 0x400); }
                int pe = BitConverter.ToInt32(header, 0x3C);
                uint epRva = BitConverter.ToUInt32(header, pe + 0x18 + 16);
                entryPoint = imageBase + epRva;
            } catch {}

            ulong finalEntryPoint = entryPoint;

            // Strategy 1: Advanced Search
            MegaDumper.ScyllaError scyResult = MegaDumper.ScyllaBindings.FixImportsAutoDetect(
                processId, imageBase, finalEntryPoint, dumpedFile, scyFixFilename,
                advancedSearch: true, createNewIat: true);
            
            // Strategy 2: Basic Search fallback
            if (scyResult == MegaDumper.ScyllaError.IatSearchError)
            {
                File.AppendAllText(logPath, $"{passPrefix}Advanced Search failed. Retrying with Basic Search...\n");
                scyResult = MegaDumper.ScyllaBindings.FixImportsAutoDetect(
                    processId, imageBase, finalEntryPoint, dumpedFile, scyFixFilename,
                    advancedSearch: false, createNewIat: true);
            }

            // Strategy 3: Manual IAT Recovery
            if (scyResult != MegaDumper.ScyllaError.Success && scyResult != MegaDumper.ScyllaError.PidNotFound)
            {
                scyResult = TryManualIATRecovery(dumpedFile, processId, imageBase, scyFixFilename, logPath);
            }
        
            // Cleanup and Sanitize
            if (scyResult == MegaDumper.ScyllaError.Success)
            {
                SanitizeScyfixFile(scyFixFilename);
            }
            else
            {
                File.AppendAllText(logPath, $"{passPrefix}Critical: All Scylla strategies failed for {Path.GetFileName(dumpedFile)}.\n");
                 if (File.Exists(scyFixFilename)) try { File.Delete(scyFixFilename); } catch { }
            }
        
            return scyResult;
        }

        private unsafe string DumpProcessLogic(uint processId, DUMP_DIRECTORIES ddirs, bool dumpNative, bool restoreFilename)
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
                                                int sectionTableOffset = isPE64 ? 0x108 : 0x0F8;

                                                long NetMetadata = 0;
                                                // read 8 bytes at CLR metadata pointer (COM Descriptor / CLR Header)
                                                ulong netMetaAddr = j + (ulong)k + (ulong)PEOffset + (ulong)metadataOffset;
                                                if (ReadProcessMemoryW(hProcess, netMetaAddr, infokeep, (UIntPtr)8, out BytesRead))
                                                    NetMetadata = BitConverter.ToInt64(infokeep, 0);

                                                // NOTE: Removed faulty fallback that forced NetMetadata=1 based on isNetAssembly.
                                                // isNetAssembly (from CheckAdvancedPEStructure) only validates PE structure,
                                                // not .NET metadata presence. NetMetadata==0 means native executable.

                                                if (dumpNative || NetMetadata != 0 || isNetAssembly)
                                                {
                                                    // Read entire PE header from memory in one operation to ensure consistency
                                                    int peHeaderSize = Math.Max(pagesizeInt, PEOffset + 0x400); // Ensure we read enough data
                                                    byte[] PeHeader = new byte[peHeaderSize];
                                                    if (!ReadProcessMemoryW(hProcess, j + (ulong)k, PeHeader, (UIntPtr)peHeaderSize, out BytesRead))
                                                        continue;

                                                    // Verify we have enough data
                                                    if (BytesRead < PEOffset + 0x100) continue;

                                                    int nrofsection = BitConverter.ToInt16(PeHeader, PEOffset + 0x06);

                                                    // Debug: Log the section count for troubleshooting
                                                    System.Diagnostics.Debug.WriteLine($"Found PE at {(j + (ulong)k):X8}, Sections: {nrofsection}");
                                                    if (nrofsection > 0 && nrofsection < 100) // Sanity check for number of sections
                                                    {
                                                        bool isNetFile = true;
                                                        string dumpdir = "";
                                                        if (NetMetadata == 0)
                                                            isNetFile = false;

                                                        // Read section alignment values directly from memory to ensure accuracy
                                                        byte[] alignmentBytes = new byte[8];
                                                        if (!ReadProcessMemoryW(hProcess, j + (ulong)k + (ulong)PEOffset + 0x038, alignmentBytes, (UIntPtr)8, out BytesRead))
                                                            continue;

                                                        int sectionalignment = BitConverter.ToInt32(alignmentBytes, 0);
                                                        int filealignment = BitConverter.ToInt32(alignmentBytes, 4);
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

                                                        // get total raw size (of all sections):
                                                        int totalrawsize = 0;
                                                        if (nrofsection > 0)
                                                        {
                                                            int rawsizeoflast = sections[nrofsection - 1].size_of_raw_data;
                                                            int rawaddressoflast = sections[nrofsection - 1].pointer_to_raw_data;
                                                            if (rawsizeoflast > 0 && rawaddressoflast > 0)
                                                                totalrawsize = rawsizeoflast + rawaddressoflast;
                                                        }
                                                        string filename = "";

                                                        // calculate right size of image
                                                        int sizeofimage = BitConverter.ToInt32(PeHeader, PEOffset + 0x050);

                                                        // CHANGE: Correctly initialize calculatedimagesize from PE Header's SizeOfHeaders field.
                                                        // Offset 60 from OptionalHeader start (24) = 84 (0x54)
                                                        int sizeOfHeaders = BitConverter.ToInt32(PeHeader, PEOffset + 0x54);
                                                        int calculatedimagesize = sizeOfHeaders;

                                                        int rawsize, rawAddress, virtualsize, virtualAddress = 0;

                                                        for (int i = 0; i < nrofsection; i++)
                                                        {
                                                            virtualsize = sections[i].virtual_size;
                                                            virtualAddress = sections[i].virtual_address;
                                                            
                                                            int toadd = virtualsize % sectionalignment;
                                                            if (toadd != 0) toadd = sectionalignment - toadd;
                                                            
                                                            // Correctly calculate total size by finding the end of the last section
                                                            int sectionEnd = virtualAddress + virtualsize + toadd;
                                                            if (sectionEnd > calculatedimagesize)
                                                                calculatedimagesize = sectionEnd;
                                                        }

                                                        if (calculatedimagesize > sizeofimage) sizeofimage = calculatedimagesize;

                                                        // Memory dumper rawdump always produces a "fixed" dump (Raw layout = Virtual layout)
                                                        // to correspond with the memory-read buffer.
                                                        totalrawsize = sizeofimage;

                                                        if (totalrawsize != 0)
                                                        {
                                                            try
                                                            {
                                                                byte[] rawdump = new byte[totalrawsize];
                                                                // read rawdump from remote at base j+k
                                                                isok = ReadProcessMemoryW(hProcess, j + (ulong)k, rawdump, (UIntPtr)rawdump.Length, out BytesRead);
                                                                if (isok)
                                                                {
                                                                    // Patch section headers in the rawdump buffer to match memory layout
                                                                    for (int l = 0; l < nrofsection; l++)
                                                                    {
                                                                        int vSize = sections[l].virtual_size;
                                                                        int vAddr = sections[l].virtual_address;
                                                                        
                                                                        // Set PointerToRawData = VirtualAddress, SizeOfRawData = VirtualSize
                                                                        byte[] vSizeB = BitConverter.GetBytes(vSize);
                                                                        byte[] vAddrB = BitConverter.GetBytes(vAddr);
                                                                        
                                                                        int hdrOff = PEOffset + 24 + sizeofoptionalheader + (0x28 * l);
                                                                        Array.Copy(vSizeB, 0, rawdump, hdrOff + 16, 4);
                                                                        Array.Copy(vAddrB, 0, rawdump, hdrOff + 20, 4);
                                                                    }

                                                                    // CRITICAL FIX: Patch ImageBase in rawdump header to match Runtime Base Address.
                                                                    // This prevents crashes (Access Violation) when running the dump if relocations are missing/invalid,
                                                                    // by ensuring the Loader loads the dump at the address it was dumped from (where code is already related).
                                                                    ulong runtimeBase = j + (ulong)k;
                                                                    ushort magicVal = BitConverter.ToUInt16(PeHeader, PEOffset + 24);
                                                                    bool isPE64Val = (magicVal == 0x20B);
                                                                    
                                                                    if (isPE64Val)
                                                                    {
                                                                        // 64-bit ImageBase at PEOffset + 0x30
                                                                        Array.Copy(BitConverter.GetBytes(runtimeBase), 0, rawdump, PEOffset + 0x30, 8);
                                                                        
                                                                        // Disable ASLR (Dynamic Base) - Offset 70 (0x46) in Optional Header (PEOffset + 24 + 70)
                                                                        int dllCharOffset = PEOffset + 24 + 70;
                                                                        ushort dllChar = BitConverter.ToUInt16(rawdump, dllCharOffset);
                                                                        dllChar &= 0xFFBF; // Clear 0x0040 (IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
                                                                        Array.Copy(BitConverter.GetBytes(dllChar), 0, rawdump, dllCharOffset, 2);
                                                                    }
                                                                    else
                                                                    {
                                                                        // 32-bit ImageBase at PEOffset + 0x34
                                                                        Array.Copy(BitConverter.GetBytes((uint)runtimeBase), 0, rawdump, PEOffset + 0x34, 4);

                                                                        // Disable ASLR (Dynamic Base) - Offset 66 (0x42) in Optional Header (PEOffset + 24 + 66)
                                                                        int dllCharOffset = PEOffset + 24 + 66;
                                                                        ushort dllChar = BitConverter.ToUInt16(rawdump, dllCharOffset);
                                                                        dllChar &= 0xFFBF; // Clear 0x0040
                                                                        Array.Copy(BitConverter.GetBytes(dllChar), 0, rawdump, dllCharOffset, 2);
                                                                    }

                                                                    dumpdir = ddirs.nativedirname;
                                                                    if (isNetFile)
                                                                        dumpdir = ddirs.dumps;

                                                                    filename = dumpdir + "\\rawdump_" + (j + (ulong)k).ToString("X");
                                                                    if (File.Exists(filename))
                                                                        filename = dumpdir + "\\rawdump" + CurrentCount.ToString() + "_" + (j + (ulong)k).ToString("X");


                                                                    
                                                                    bool IsExe = false;
                                                                    try {
                                                                        short characteristics = BitConverter.ToInt16(PeHeader, PEOffset + 0x16);
                                                                        // Exe if ExecutableImage flag is set AND it is NOT a DLL
                                                                        if ((characteristics & 0x0002) != 0 && !IsDll) IsExe = true;
                                                                    } catch {}

                                                                    if (IsDll) filename += ".dll";
                                                                    else if (IsExe) filename += ".exe";
                                                                    else filename += ".exe";

                                                                    try {
                                                                         File.AppendAllText(Path.Combine(ddirs.dumps, "scylla_log.txt"), 
                                                                            $"[{DateTime.Now}] Dump: {Path.GetFileName(filename)} | Base: {runtimeBase:X} | IsDll: {IsDll} | IsExe: {IsExe}\n");
                                                                    } catch {}



                                                                    try
                                                                    {
                                                                        File.WriteAllBytes(filename, rawdump);
                                                                        sessionDumpedFiles.Add(filename);
                                                                        
                                                                        // Apply native dump fixes for non-.NET executables
                                                                        // Check NetMetadata directly since isNetFile can be incorrectly set
                                                                        string nativeLogPath = Path.Combine(ddirs.dumps, "scylla_log.txt");
                                                                        if (NetMetadata == 0)
                                                                        {
                                                                            try
                                                                            {
                                                                                File.AppendAllText(nativeLogPath, $"[{DateTime.Now:HH:mm:ss}] [NativeFix] Applying native dump fix for {Path.GetFileName(filename)}...\n");
                                                                                FixNativeDump(filename, processId, runtimeBase, nativeLogPath);
                                                                            }
                                                                            catch (Exception nativeEx)
                                                                            {
                                                                                File.AppendAllText(nativeLogPath, $"[NativeFix] Exception: {nativeEx.Message}\n");
                                                                            }
                                                                        }
                                                                        else
                                                                        {
                                                                            try { File.AppendAllText(nativeLogPath, $"[{DateTime.Now:HH:mm:ss}] [NativeFix] Skipped for {Path.GetFileName(filename)} (NetMetadata={NetMetadata})\n"); } catch {}
                                                                        }
                                                                    }
                                                                    catch { }

                                                                    CurrentCount++;
                                                                }
                                                            }
                                                            catch { }
                                                        }

                                                        byte[] virtualdump = new byte[sizeofimage];
                                                        Array.Copy(PeHeader, virtualdump, pagesizeInt);

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
                                                                // Fix section header in memory buffer
                                                                sectionWriter.BaseStream.Position = PEOffset + 24 + sizeofoptionalheader + (0x28 * l) + 16;
                                                                sectionWriter.Write(virtualsize);   // SizeOfRawData
                                                                sectionWriter.BaseStream.Position = PEOffset + 24 + sizeofoptionalheader + (0x28 * l) + 20;
                                                                sectionWriter.Write(virtualAddress); // PointerToRawData
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

                                                        FixImportandEntryPoint((long)(j + (ulong)k), virtualdump, (int)processId);

                                                        dumpdir = ddirs.nativedirname;
                                                        if (isNetFile)
                                                            dumpdir = ddirs.dumps;

                                                        filename = dumpdir + "\\vdump_" + (j + (ulong)k).ToString("X");
                                                        if (File.Exists(filename))
                                                            filename = dumpdir + "\\vdump" + CurrentCount.ToString() + "_" + (j + (ulong)k).ToString("X");

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

                                                            // Apply native dump fixes for non-.NET executables
                                                            // Check NetMetadata directly since isNetFile can be incorrectly set
                                                            string vdumpLogPath = Path.Combine(ddirs.dumps, "scylla_log.txt");
                                                            if (NetMetadata == 0)
                                                            {
                                                                try
                                                                {
                                                                    File.AppendAllText(vdumpLogPath, $"[{DateTime.Now:HH:mm:ss}] [NativeFix] Applying native dump fix for {Path.GetFileName(filename)}...\n");
                                                                    FixNativeDump(filename, processId, (j + (ulong)k), vdumpLogPath);
                                                                }
                                                                catch (Exception nativeEx)
                                                                {
                                                                    try { File.AppendAllText(vdumpLogPath, 
                                                                        $"[NativeFix] Exception: {nativeEx.Message}\n"); } catch {}
                                                                }
                                                            }
                                                            else
                                                            {
                                                                try { File.AppendAllText(vdumpLogPath, $"[{DateTime.Now:HH:mm:ss}] [NativeFix] Skipped for {Path.GetFileName(filename)} (NetMetadata={NetMetadata})\n"); } catch {}
                                                            }

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
                    Action<string, string> renameFiles = (string sourceDir, string targetDir) => {
                        if (Directory.Exists(sourceDir))
                        {
                            DirectoryInfo di = new DirectoryInfo(sourceDir);
                            foreach (FileInfo fi in di.GetFiles())
                            {
                                try
                                {
                                    FileVersionInfo info = FileVersionInfo.GetVersionInfo(fi.FullName);
                                    string finalDir = targetDir;

                                    if (targetDir == ddirs.dumps && info.CompanyName?.IndexOf("microsoft corporation", StringComparison.OrdinalIgnoreCase) >= 0)
                                    {
                                        finalDir = ddirs.sysdirname;
                                    }

                                    if (!string.IsNullOrEmpty(info.OriginalFilename))
                                    {
                                        string safeName = string.Concat(info.OriginalFilename.Where(c => !Path.GetInvalidFileNameChars().Contains(c)));
                                        
                                        // Preserve _scyfix suffix if present
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
                                        File.Move(fi.FullName, Path.Combine(ddirs.unknowndirname, fi.Name));
                                    }
                                }
                                catch
                                {
                                    try { File.Move(fi.FullName, Path.Combine(ddirs.unknowndirname, fi.Name)); } catch { }
                                }
                            }
                        }
                    };


                    // Scylla Integration (Pre-Rename)
                    try 
                    {
                        if (MegaDumper.ScyllaBindings.IsAvailable)
                        {
                            // Collect files first to avoid modification during iteration issues
                            HashSet<string> filesToScylla = new HashSet<string>(sessionDumpedFiles);
                            if (Directory.Exists(ddirs.dumps)) 
                            {
                                try {
                                    foreach (var f in Directory.GetFiles(ddirs.dumps, "rawdump_*.*", SearchOption.AllDirectories)) 
                                        filesToScylla.Add(f);
                                } catch {}
                            }

                            string vdumpLogPath = Path.Combine(ddirs.dumps, "scylla_log.txt");

                            foreach (string dumpedFile in filesToScylla)
                            {
                                if (!File.Exists(dumpedFile)) continue;
                                string fileNameNoExt = Path.GetFileNameWithoutExtension(dumpedFile);
                                if (!fileNameNoExt.StartsWith("rawdump", StringComparison.OrdinalIgnoreCase)) continue;

                                try
                                {
                                    string hexAddress = fileNameNoExt.Split('_').Last();
                                    ulong imageBase = Convert.ToUInt64(hexAddress, 16);
                                    
                                    if (imageBase > 0)
                                    {
                                         string scyFixFilename = Path.ChangeExtension(dumpedFile, null) + "_scyfix" + Path.GetExtension(dumpedFile);
                                         
                                         // Update UI
                                         this.Invoke((MethodInvoker)delegate { this.Text = $"Scylla fixing: {fileNameNoExt}..."; });

                                         ProcessDumpWithScylla(dumpedFile, processId, imageBase, scyFixFilename, vdumpLogPath, isPass2: false);
                                    }
                                }
                                catch (Exception ex)
                                {
                                     try { File.AppendAllText(vdumpLogPath, $"Error processing {Path.GetFileName(dumpedFile)}: {ex.Message}\n"); } catch {}
                                }
                            }
                        }
                        else
                        {
                             try { File.AppendAllText(Path.Combine(ddirs.dumps, "scylla_log.txt"), $"[{DateTime.Now}] Scylla is NOT Available! Error: {MegaDumper.ScyllaBindings.LastLoadError}\n"); } catch {}
                        }
                    }
                    catch {}

                    renameFiles(ddirs.dumps, ddirs.dumps);
                    renameFiles(ddirs.nativedirname, ddirs.nativedirname);

                    // PASS 2: Scylla for UnknownName AND Main Dumps files (Post-Rename)
                    try
                    {
                        if (MegaDumper.ScyllaBindings.IsAvailable)
                        {
                             var dirsToScan = new List<string>();
                             if (Directory.Exists(ddirs.unknowndirname)) dirsToScan.Add(ddirs.unknowndirname);
                             if (Directory.Exists(ddirs.dumps)) dirsToScan.Add(ddirs.dumps);

                             string vdumpLogPath = Path.Combine(ddirs.dumps, "scylla_log.txt");

                             foreach (var dir in dirsToScan)
                             {
                                 try {
                                     foreach (string dumpedFile in Directory.GetFiles(dir, "rawdump_*.*"))
                                     {
                                         try
                                         {
                                             string fileNameNoExt = Path.GetFileNameWithoutExtension(dumpedFile);
                                             
                                             // Robust check: if file already has a _scyfix version, skip it
                                             // This prevents duplicate processing
                                             if (fileNameNoExt.Contains("_scyfix")) continue;
                                             
                                             string checkScyfix = Path.ChangeExtension(dumpedFile, null) + "_scyfix" + Path.GetExtension(dumpedFile);
                                             if (File.Exists(checkScyfix)) continue;

                                             string hexAddress = fileNameNoExt.Split('_').Last();
                                             ulong imageBase = Convert.ToUInt64(hexAddress, 16);

                                             if (imageBase > 0)
                                             {
                                                  this.Invoke((MethodInvoker)delegate { this.Text = $"Scylla fixing [Pass 2]: {fileNameNoExt}..."; });
                                                  ProcessDumpWithScylla(dumpedFile, processId, imageBase, checkScyfix, vdumpLogPath, isPass2: true);
                                             }
                                         }
                                         catch {}
                                     }
                                 } catch {}
                             }
                        }
                    }
                    catch {}


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
