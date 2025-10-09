/*
 * Created by SharpDevelop.
 * User: Bogdan
 * Date: 11.10.2010
 * Time: 15:47
 * * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using ProcessUtils;
using System;
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
                            string isnet = "false";

                            try
                            {
                                theProc = Process.GetProcessById((int)procEntry.th32ProcessID);
                                if (theProc != null)  // Add null check here
                                {
                                    isnet = IsPEProcess((int)procEntry.th32ProcessID) ? "true" : "false";
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

                        // Validate optional header size
                        if (sizeOfOptionalHeader < 224) // Minimum size for PE32
                            return false;

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
            string isnet = "false";

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

                            isnet = IsPEProcess((int)procEntry.th32ProcessID) ? "true" : "false";
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
        private static extern int OpenProcessToken(int ProcessHandle, int DesiredAccess, ref int tokenhandle);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        private static extern int GetCurrentProcess();

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
            int PEOffset = BitConverter.ToInt32(input, 0x3C);
            int nrofsection = BitConverter.ToInt16(input, PEOffset + 0x06);

            for (int i = 0; i < nrofsection; i++)
            {
                int virtualAddress = BitConverter.ToInt32(input, PEOffset + 0x0F8 + (0x28 * i) + 012);
                int fvirtualsize = BitConverter.ToInt32(input, PEOffset + 0x0F8 + (0x28 * i) + 08);
                int frawAddress = BitConverter.ToInt32(input, PEOffset + (0x28 * i) + 0x0F8 + 20);
                if ((virtualAddress <= rva) && (virtualAddress + fvirtualsize >= rva))
                    return frawAddress + (rva - virtualAddress);
            }

            return -1;
        }

        public int Offset2RVA(byte[] input, int offset)
        {
            int PEOffset = BitConverter.ToInt32(input, 0x3C);
            int nrofsection = BitConverter.ToInt16(input, PEOffset + 0x06);

            for (int i = 0; i < nrofsection; i++)
            {
                int virtualAddress = BitConverter.ToInt32(input, PEOffset + 0x0F8 + (0x28 * i) + 012);
                _ = BitConverter.ToInt32(input, PEOffset + 0x0F8 + (0x28 * i) + 08);
                int frawAddress = BitConverter.ToInt32(input, PEOffset + (0x28 * i) + 0x0F8 + 20);
                int frawsize = BitConverter.ToInt32(input, PEOffset + (0x28 * i) + 0x0F8 + 16);
                if ((frawAddress <= offset) && (frawAddress + frawsize >= offset))
                    return virtualAddress + (offset - frawAddress);
            }

            return -1;
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

        public bool FixImportandEntryPoint(long dumpVA, byte[] Dump)
        {
            if (Dump == null || Dump.Length == 0) return false;

            int PEOffset = BitConverter.ToInt32(Dump, 0x3C);

            int ImportDirectoryRva = BitConverter.ToInt32(Dump, PEOffset + 0x080);
            int impdiroffset = RVA2Offset(Dump, ImportDirectoryRva);
            if (impdiroffset == -1) return false;

            byte[] mscoreeAscii = { 0x6D, 0x73, 0x63, 0x6F, 0x72, 0x65, 0x65, 0x2E, 0x64, 0x6C, 0x6C, 0x00 };
            byte[] CorExeMain = { 0x5F, 0x43, 0x6F, 0x72, 0x45, 0x78, 0x65, 0x4D, 0x61, 0x69, 0x6E, 0x00 };
            byte[] CorDllMain = { 0x5F, 0x43, 0x6F, 0x72, 0x44, 0x6C, 0x6C, 0x4D, 0x61, 0x69, 0x6E, 0x00 };
            int ThunkToFix = 0;
            int ThunkData = 0;
            _ = new byte[mscoreeAscii.Length];
            int current = 0;
            int NameRVA = BitConverter.ToInt32(Dump, impdiroffset + current + 12);
            while (NameRVA > 0)
            {
                int NameOffset = RVA2Offset(Dump, NameRVA);
                if (NameOffset > 0)
                {
                    try
                    {
                        bool ismscoree = true;
                        for (int i = 0; i < mscoreeAscii.Length; i++)
                        {
                            if (Dump[NameOffset + i] != mscoreeAscii[i])
                            {
                                ismscoree = false;
                                break;
                            }
                        }

                        if (ismscoree)
                        {
                            int OriginalFirstThunk = BitConverter.ToInt32(Dump, impdiroffset + current);
                            int OriginalFirstThunkfo = RVA2Offset(Dump, OriginalFirstThunk);
                            if (OriginalFirstThunkfo > 0)
                            {
                                ThunkData = BitConverter.ToInt32(Dump, OriginalFirstThunkfo);
                                int ThunkDatafo = RVA2Offset(Dump, ThunkData);
                                if (ThunkDatafo > 0)
                                {
                                    ismscoree = true;
                                    for (int i = 0; i < mscoreeAscii.Length; i++)
                                    {
                                        if (Dump[ThunkDatafo + 2 + i] != CorExeMain[i] && Dump[ThunkDatafo + 2 + i] != CorDllMain[i])
                                        {
                                            ismscoree = false;
                                            break;
                                        }
                                    }

                                    if (ismscoree)
                                    {
                                        ThunkToFix = BitConverter.ToInt32(Dump, impdiroffset + current + 16);  // FirstThunk;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    catch
                    {
                    }
                }

                try
                {
                    current += 20; // 20 = size of IMAGE_IMPORT_DESCRIPTOR
                    NameRVA = BitConverter.ToInt32(Dump, ImportDirectoryRva + current + 12);
                }
                catch
                {
                    break;
                }
            }

            if (ThunkToFix <= 0 || ThunkData == 0) return false;

            int ThunkToFixfo = RVA2Offset(Dump, ThunkToFix);
            if (ThunkToFixfo < 0) return false;

            BinaryWriter writer = new(new MemoryStream(Dump));
            int ThunkValue = BitConverter.ToInt32(Dump, ThunkToFixfo);  // old thunk value
            if (ThunkValue <= 0 || RVA2Offset(Dump, ThunkValue) < 0)
            {
                writer.BaseStream.Position = ThunkToFixfo;
                writer.Write(ThunkData);
            }

            int EntryPoint = BitConverter.ToInt32(Dump, PEOffset + 0x028);
            if (EntryPoint <= 0 || RVA2Offset(Dump, EntryPoint) < 0)
            {
                // The address search logic is designed for 32-bit addresses (JMP [imm32]).
                // To prevent an overflow exception with 64-bit VAs while maintaining the existing logic,
                // we perform the addition using 64-bit math and then truncate the result to 32 bits.
                // This will work correctly for modules loaded in the lower 4GB of address space.
                long realThunkAddress = dumpVA + ThunkToFix;
                byte[] ThunkToFixbytes = BitConverter.GetBytes((uint)realThunkAddress);
                for (int i = 0; i < Dump.Length - 6; i++)
                {
                    if (Dump[i + 0] == 0x0FF && Dump[i + 1] == 0x025 && Dump[i + 2] == ThunkToFixbytes[0] && Dump[i + 3] == ThunkToFixbytes[1] && Dump[i + 4] == ThunkToFixbytes[2] && Dump[i + 5] == ThunkToFixbytes[3])
                    {
                        int EntrPointRVA = Offset2RVA(Dump, i);
                        writer.BaseStream.Position = PEOffset + 0x028;
                        writer.Write(EntrPointRVA);
                        break;
                    }
                }
            }

            writer.Close();
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
            dpmdirs.dumps = Path.Combine(dpmdirs.root, "Dumps");
            dpmdirs.nativedirname = Path.Combine(dpmdirs.dumps, "Native");
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

            if (!Directory.Exists(dpmdirs.nativedirname))
            {
                try
                {
                    Directory.CreateDirectory(dpmdirs.nativedirname);
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

            if (!Directory.Exists(dpmdirs.sysdirname))
            {
                try
                {
                    Directory.CreateDirectory(dpmdirs.sysdirname);
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

            if (!Directory.Exists(dpmdirs.unknowndirname))
            {
                try
                {
                    Directory.CreateDirectory(dpmdirs.unknowndirname);
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

        private unsafe string DumpProcessLogic(uint processId, DUMP_DIRECTORIES ddirs, bool dumpNative, bool restoreFilename)
        {
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 0, processId);

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

                                                // Now call CheckAdvancedPEStructure with the correct PE header offset
                                                try
                                                {
                                                    // pass the image base and e_lfanew so the checker knows where the header lives
                                                    isNetAssembly = CheckAdvancedPEStructure(hProcess, (j + (ulong)k), e_lfanew);
                                                }
                                                catch (System.ComponentModel.Win32Exception)
                                                {
                                                    isNetAssembly = false;
                                                }
                                                catch
                                                {
                                                    isNetAssembly = false;
                                                }

                                                long NetMetadata = 0;
                                                // read 8 bytes at CLR metadata pointer (j + k + PEOffset + 0x0E8)
                                                ulong netMetaAddr = j + (ulong)k + (ulong)PEOffset + 0x0E8UL;
                                                if (ReadProcessMemoryW(hProcess, netMetaAddr, infokeep, (UIntPtr)8, out BytesRead))
                                                    NetMetadata = BitConverter.ToInt64(infokeep, 0);

                                                if (NetMetadata == 0 && isNetAssembly)
                                                {
                                                    NetMetadata = 1;
                                                }

                                                if (dumpNative || NetMetadata != 0)
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
                                                        // The original line was reading from an incorrect offset and was a likely source of errors.
                                                        int sizeOfHeaders = BitConverter.ToInt32(PeHeader, PEOffset + 0x5C);
                                                        int calculatedimagesize = sizeOfHeaders;

                                                        int rawsize, rawAddress, virtualsize, virtualAddress = 0;
                                                        int calcrawsize = 0;

                                                        for (int i = 0; i < nrofsection; i++)
                                                        {
                                                            virtualsize = sections[i].virtual_size;
                                                            int toadd = virtualsize % sectionalignment;
                                                            if (toadd != 0) toadd = sectionalignment - toadd;
                                                            calculatedimagesize = calculatedimagesize + virtualsize + toadd;
                                                        }

                                                        if (calculatedimagesize > sizeofimage) sizeofimage = calculatedimagesize;

                                                        try
                                                        {
                                                            byte[] crap = new byte[totalrawsize];
                                                        }
                                                        catch
                                                        {
                                                            totalrawsize = sizeofimage;
                                                        }

                                                        if (totalrawsize != 0)
                                                        {
                                                            try
                                                            {
                                                                byte[] rawdump = new byte[totalrawsize];
                                                                // read rawdump from remote at base j+k
                                                                isok = ReadProcessMemoryW(hProcess, j + (ulong)k, rawdump, (UIntPtr)rawdump.Length, out BytesRead);
                                                                if (isok)
                                                                {
                                                                    dumpdir = ddirs.nativedirname;
                                                                    if (isNetFile)
                                                                        dumpdir = ddirs.dumps;

                                                                    filename = dumpdir + "\\rawdump_" + (j + (ulong)k).ToString("X8");
                                                                    if (File.Exists(filename))
                                                                        filename = dumpdir + "\\rawdump" + CurrentCount.ToString() + "_" + (j + (ulong)k).ToString("X8");

                                                                    if (IsDll)
                                                                        filename += ".dll";
                                                                    else
                                                                        filename += ".exe";

                                                                    try
                                                                    {
                                                                        File.WriteAllBytes(filename, rawdump);
                                                                    }
                                                                    catch
                                                                    {
                                                                        // This part involves UI, cannot be called from a background thread directly
                                                                    }

                                                                    CurrentCount++;
                                                                }
                                                            }
                                                            catch
                                                            {
                                                            }
                                                        }

                                                        byte[] virtualdump = new byte[sizeofimage];
                                                        Array.Copy(PeHeader, virtualdump, pagesizeInt);

                                                        int rightrawsize = 0;
                                                        for (int l = 0; l < nrofsection; l++)
                                                        {
                                                            rawsize = sections[l].size_of_raw_data;
                                                            rawAddress = sections[l].pointer_to_raw_data;
                                                            virtualsize = sections[l].virtual_size;
                                                            virtualAddress = sections[l].virtual_address;

                                                            // RawSize = Virtual Size rounded on FileAlignment
                                                            calcrawsize = 0;
                                                            calcrawsize = virtualsize % filealignment;
                                                            if (calcrawsize != 0) calcrawsize = filealignment - calcrawsize;
                                                            calcrawsize = virtualsize + calcrawsize;

                                                            if ((calcrawsize != 0 && rawsize != calcrawsize && rawsize != virtualsize)
                                                               || rawAddress < 0)
                                                            {
                                                                // if raw size is bad:
                                                                rawsize = virtualsize;
                                                                rawAddress = virtualAddress;
                                                                BinaryWriter writer = new(new MemoryStream(virtualdump));
                                                                writer.BaseStream.Position = PEOffset + 0x0F8 + (0x28 * l) + 16;
                                                                writer.Write(virtualsize);
                                                                writer.BaseStream.Position = PEOffset + 0x0F8 + (0x28 * l) + 20;
                                                                writer.Write(virtualAddress);
                                                                writer.Close();
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
                                                                Array.Copy(csection, 0, virtualdump, rawAddress, rightsize);
                                                            }
                                                            catch
                                                            {
                                                            }

                                                            if (l == nrofsection - 1)
                                                            {
                                                                rightrawsize = rawAddress + rawsize;
                                                            }
                                                        }

                                                        FixImportandEntryPoint((long)(j + (ulong)k), virtualdump);

                                                        dumpdir = ddirs.nativedirname;
                                                        if (isNetFile)
                                                            dumpdir = ddirs.dumps;

                                                        filename = dumpdir + "\\vdump_" + (j + (ulong)k).ToString("X8");
                                                        if (File.Exists(filename))
                                                            filename = dumpdir + "\\vdump" + CurrentCount.ToString() + "_" + (j + (ulong)k).ToString("X8");

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
                                        string newFilename = Path.Combine(finalDir, safeName);

                                        int count = 2;
                                        while (File.Exists(newFilename))
                                        {
                                            string extension = Path.GetExtension(newFilename) ?? ".dll";
                                            newFilename = Path.Combine(finalDir, $"{Path.GetFileNameWithoutExtension(info.OriginalFilename)}({count++}){extension}");
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

                    renameFiles(ddirs.dumps, ddirs.dumps);
                    renameFiles(ddirs.nativedirname, ddirs.nativedirname);
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
