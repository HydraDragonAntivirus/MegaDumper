/*
 * ScyllaBindings.cs
 * C# P/Invoke bindings for Scylla x64/x86 Import Reconstruction DLL
 * 
 * This provides managed wrappers for Scylla's native functions to search for
 * and fix Import Address Tables (IAT) in dumped executables.
 */

using System;
using System.Runtime.InteropServices;

namespace MegaDumper
{
    /// <summary>
    /// Error codes returned by Scylla functions
    /// </summary>
    public enum ScyllaError : int
    {
        Success = 0,
        ProcessOpenFailed = -1,
        IatWriteError = -2,
        IatSearchError = -3,
        IatNotFound = -4,
        PidNotFound = -5,
        ModuleNotFound = -6
    }

    /// <summary>
    /// C# bindings for Scylla import reconstruction DLL.
    /// Provides IAT search and fix functionality for dumped executables.
    /// </summary>
    public static class ScyllaBindings
    {
        // DLL name changes based on architecture
        private const string SCYLLA_DLL_X86 = "Scylla.dll";
        private const string SCYLLA_DLL_X64 = "Scylla.dll";

        /// <summary>
        /// Gets the appropriate Scylla DLL name for the current architecture
        /// </summary>
        public static string ScyllaDllName => IntPtr.Size == 8 ? SCYLLA_DLL_X64 : SCYLLA_DLL_X86;

        /// <summary>
        /// Stores the last error encountered when trying to load Scylla DLL
        /// </summary>
        public static string LastLoadError { get; private set; } = string.Empty;

        /// <summary>
        /// Checks if the Scylla DLL is available
        /// </summary>
        public static bool IsAvailable
        {
            get
            {
                try
                {
                    LastLoadError = string.Empty;
                    var version = VersionInformation();
                    return !string.IsNullOrEmpty(version);
                }
                catch (DllNotFoundException ex)
                {
                    LastLoadError = $"DLL not found: {ex.Message}";
                    Console.WriteLine($"[Scylla] {LastLoadError}");
                    return false;
                }
                catch (BadImageFormatException ex)
                {
                    LastLoadError = $"Architecture mismatch (x86/x64): {ex.Message}";
                    Console.WriteLine($"[Scylla] {LastLoadError}");
                    return false;
                }
                catch (Exception ex)
                {
                    LastLoadError = $"Load error: {ex.GetType().Name} - {ex.Message}";
                    Console.WriteLine($"[Scylla] {LastLoadError}");
                    return false;
                }
            }
        }

        #region Native Imports

        // Import based on architecture - we use the x64 DLL name and let the loader find it
        // For x86 builds, the Scylla.dll will be used
        
        [DllImport("Scylla.dll", EntryPoint = "ScyllaVersionInformationW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr ScyllaVersionInformationW_x64();

        [DllImport("Scylla.dll", EntryPoint = "ScyllaVersionInformationW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr ScyllaVersionInformationW_x86();

        [DllImport("Scylla.dll", EntryPoint = "ScyllaIatSearch", CallingConvention = CallingConvention.StdCall)]
        private static extern int ScyllaIatSearch_x64(
            uint dwProcessId,
            UIntPtr imagebase,
            out UIntPtr iatStart,
            out uint iatSize,
            UIntPtr searchStart,
            [MarshalAs(UnmanagedType.Bool)] bool advancedSearch);

        [DllImport("Scylla.dll", EntryPoint = "ScyllaIatSearch", CallingConvention = CallingConvention.StdCall)]
        private static extern int ScyllaIatSearch_x86(
            uint dwProcessId,
            UIntPtr imagebase,
            out UIntPtr iatStart,
            out uint iatSize,
            UIntPtr searchStart,
            [MarshalAs(UnmanagedType.Bool)] bool advancedSearch);

        [DllImport("Scylla.dll", EntryPoint = "ScyllaIatFixAutoW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        private static extern int ScyllaIatFixAutoW_x64(
            uint dwProcessId,
            UIntPtr imagebase,
            UIntPtr iatAddr,
            uint iatSize,
            [MarshalAs(UnmanagedType.Bool)] bool createNewIat,
            [MarshalAs(UnmanagedType.LPWStr)] string dumpFile,
            [MarshalAs(UnmanagedType.LPWStr)] string iatFixFile);

        [DllImport("Scylla.dll", EntryPoint = "ScyllaIatFixAutoW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        private static extern int ScyllaIatFixAutoW_x86(
            uint dwProcessId,
            UIntPtr imagebase,
            UIntPtr iatAddr,
            uint iatSize,
            [MarshalAs(UnmanagedType.Bool)] bool createNewIat,
            [MarshalAs(UnmanagedType.LPWStr)] string dumpFile,
            [MarshalAs(UnmanagedType.LPWStr)] string iatFixFile);

        [DllImport("Scylla.dll", EntryPoint = "ScyllaRebuildFileW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ScyllaRebuildFileW_x64(
            [MarshalAs(UnmanagedType.LPWStr)] string fileToRebuild,
            [MarshalAs(UnmanagedType.Bool)] bool removeDosStub,
            [MarshalAs(UnmanagedType.Bool)] bool updatePeHeaderChecksum,
            [MarshalAs(UnmanagedType.Bool)] bool createBackup);

        [DllImport("Scylla.dll", EntryPoint = "ScyllaRebuildFileW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ScyllaRebuildFileW_x86(
            [MarshalAs(UnmanagedType.LPWStr)] string fileToRebuild,
            [MarshalAs(UnmanagedType.Bool)] bool removeDosStub,
            [MarshalAs(UnmanagedType.Bool)] bool updatePeHeaderChecksum,
            [MarshalAs(UnmanagedType.Bool)] bool createBackup);

        [DllImport("Scylla.dll", EntryPoint = "ScyllaDumpProcessW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ScyllaDumpProcessW_x64(
            UIntPtr pid,
            [MarshalAs(UnmanagedType.LPWStr)] string fileToDump,
            UIntPtr imagebase,
            UIntPtr entrypoint,
            [MarshalAs(UnmanagedType.LPWStr)] string fileResult);

        [DllImport("Scylla.dll", EntryPoint = "ScyllaDumpProcessW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ScyllaDumpProcessW_x86(
            UIntPtr pid,
            [MarshalAs(UnmanagedType.LPWStr)] string fileToDump,
            UIntPtr imagebase,
            UIntPtr entrypoint,
            [MarshalAs(UnmanagedType.LPWStr)] string fileResult);

        #endregion

        #region Public API

        /// <summary>
        /// Gets Scylla version information string
        /// </summary>
        /// <returns>Version string like "Scylla x64 v0.9.8"</returns>
        public static string VersionInformation()
        {
            try
            {
                IntPtr ptr = IntPtr.Size == 8 
                    ? ScyllaVersionInformationW_x64() 
                    : ScyllaVersionInformationW_x86();
                return ptr != IntPtr.Zero ? Marshal.PtrToStringUni(ptr) : string.Empty;
            }
            catch (DllNotFoundException)
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Searches for the Import Address Table in a process
        /// </summary>
        /// <param name="processId">Target process ID</param>
        /// <param name="imageBase">Base address of the module to search</param>
        /// <param name="searchStart">Address to start searching from (usually entry point)</param>
        /// <param name="advancedSearch">Use advanced IAT search algorithm</param>
        /// <param name="iatStart">Output: Start address of found IAT</param>
        /// <param name="iatSize">Output: Size of found IAT in bytes</param>
        /// <returns>ScyllaError result code</returns>
        public static ScyllaError IatSearch(
            uint processId,
            ulong imageBase,
            ulong searchStart,
            bool advancedSearch,
            out ulong iatStart,
            out uint iatSize)
        {
            iatStart = 0;
            iatSize = 0;
            
            try
            {
                // Validate parameters before calling native code
                if (processId == 0 || imageBase == 0)
                {
                    return ScyllaError.PidNotFound;
                }
                
                UIntPtr outIatStart;
                uint outIatSize;

                int result = IntPtr.Size == 8
                    ? ScyllaIatSearch_x64(processId, (UIntPtr)imageBase, out outIatStart, out outIatSize, (UIntPtr)searchStart, advancedSearch)
                    : ScyllaIatSearch_x86(processId, (UIntPtr)imageBase, out outIatStart, out outIatSize, (UIntPtr)searchStart, advancedSearch);

                iatStart = (ulong)outIatStart;
                iatSize = outIatSize;

                return (ScyllaError)result;
            }
            catch (AccessViolationException)
            {
                Console.WriteLine("[Scylla] AccessViolationException in IatSearch - process may have exited or memory is invalid");
                return ScyllaError.ProcessOpenFailed;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Scylla] Exception in IatSearch: {ex.Message}");
                return ScyllaError.IatSearchError;
            }
        }

        /// <summary>
        /// Automatically fixes the IAT of a dumped PE file
        /// </summary>
        /// <param name="processId">Target process ID (must still be running)</param>
        /// <param name="imageBase">Base address of the dumped module</param>
        /// <param name="iatAddress">Start address of the IAT</param>
        /// <param name="iatSize">Size of the IAT in bytes</param>
        /// <param name="createNewIat">Create a new IAT section instead of patching in-place</param>
        /// <param name="dumpFilePath">Path to the dumped PE file</param>
        /// <param name="outputFilePath">Path for the fixed output file</param>
        /// <returns>ScyllaError result code</returns>
        public static ScyllaError IatFix(
            uint processId,
            ulong imageBase,
            ulong iatAddress,
            uint iatSize,
            bool createNewIat,
            string dumpFilePath,
            string outputFilePath)
        {
            try
            {
                // Validate parameters
                if (processId == 0 || imageBase == 0 || iatAddress == 0 || iatSize == 0)
                {
                    return ScyllaError.IatNotFound;
                }
                
                if (string.IsNullOrEmpty(dumpFilePath) || string.IsNullOrEmpty(outputFilePath))
                {
                    return ScyllaError.IatWriteError;
                }
                
                int result = IntPtr.Size == 8
                    ? ScyllaIatFixAutoW_x64(processId, (UIntPtr)imageBase, (UIntPtr)iatAddress, iatSize, createNewIat, dumpFilePath, outputFilePath)
                    : ScyllaIatFixAutoW_x86(processId, (UIntPtr)imageBase, (UIntPtr)iatAddress, iatSize, createNewIat, dumpFilePath, outputFilePath);

                return (ScyllaError)result;
            }
            catch (AccessViolationException)
            {
                Console.WriteLine("[Scylla] AccessViolationException in IatFix - process may have exited or memory is invalid");
                return ScyllaError.ProcessOpenFailed;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Scylla] Exception in IatFix: {ex.Message}");
                return ScyllaError.IatWriteError;
            }
        }

        /// <summary>
        /// Rebuilds a PE file, optionally removing DOS stub and fixing checksum
        /// </summary>
        /// <param name="filePath">Path to the PE file to rebuild</param>
        /// <param name="removeDosStub">Remove the DOS stub</param>
        /// <param name="updateChecksum">Update the PE header checksum</param>
        /// <param name="createBackup">Create a backup before modifying</param>
        /// <returns>True if successful</returns>
        public static bool RebuildFile(
            string filePath,
            bool removeDosStub = false,
            bool updateChecksum = true,
            bool createBackup = false)
        {
            return IntPtr.Size == 8
                ? ScyllaRebuildFileW_x64(filePath, removeDosStub, updateChecksum, createBackup)
                : ScyllaRebuildFileW_x86(filePath, removeDosStub, updateChecksum, createBackup);
        }

        /// <summary>
        /// Dumps a PE from process memory
        /// </summary>
        /// <param name="processId">Target process ID</param>
        /// <param name="imageBase">Base address of the module</param>
        /// <param name="entryPoint">Entry point address</param>
        /// <param name="outputPath">Output file path</param>
        /// <param name="inputFilePath">Optional input file path (null to dump from memory)</param>
        /// <returns>True if successful</returns>
        public static bool DumpProcess(
            uint processId,
            ulong imageBase,
            ulong entryPoint,
            string outputPath,
            string inputFilePath = null)
        {
            return IntPtr.Size == 8
                ? ScyllaDumpProcessW_x64((UIntPtr)processId, inputFilePath, (UIntPtr)imageBase, (UIntPtr)entryPoint, outputPath)
                : ScyllaDumpProcessW_x86((UIntPtr)processId, inputFilePath, (UIntPtr)imageBase, (UIntPtr)entryPoint, outputPath);
        }

        /// <summary>
        /// Performs full import reconstruction on a dumped file
        /// </summary>
        /// <param name="processId">Target process ID (must still be running)</param>
        /// <param name="imageBase">Base address of the dumped module</param>
        /// <param name="entryPoint">Entry point address for IAT search</param>
        /// <param name="dumpFilePath">Path to the dumped PE file</param>
        /// <param name="outputFilePath">Path for the fixed output file</param>
        /// <param name="advancedSearch">Use advanced IAT search</param>
        /// <param name="createNewIat">Create new IAT section</param>
        /// <returns>ScyllaError result code</returns>
        public static ScyllaError FixImportsAuto(
            uint processId,
            ulong imageBase,
            ulong entryPoint,
            string dumpFilePath,
            string outputFilePath,
            bool advancedSearch = true,
            bool createNewIat = true)
        {
            // Step 1: Search for IAT
            var searchResult = IatSearch(processId, imageBase, entryPoint, advancedSearch, out ulong iatStart, out uint iatSize);
            
            if (searchResult != ScyllaError.Success)
            {
                return searchResult;
            }

            if (iatSize == 0)
            {
                return ScyllaError.IatNotFound;
            }

            // Step 2: Fix the IAT
            return IatFix(processId, imageBase, iatStart, iatSize, createNewIat, dumpFilePath, outputFilePath);
        }

        /// <summary>
        /// Gets a human-readable error message for a Scylla error code
        /// </summary>
        public static string GetErrorMessage(ScyllaError error)
        {
            return error switch
            {
                ScyllaError.Success => "Success",
                ScyllaError.ProcessOpenFailed => "Failed to open process",
                ScyllaError.IatWriteError => "Failed to write IAT",
                ScyllaError.IatSearchError => "Error during IAT search",
                ScyllaError.IatNotFound => "Import Address Table not found",
                ScyllaError.PidNotFound => "Process ID not found",
                ScyllaError.ModuleNotFound => "Module not found at specified address",
                _ => $"Unknown error ({(int)error})"
            };
        }

        #endregion
    }
}
