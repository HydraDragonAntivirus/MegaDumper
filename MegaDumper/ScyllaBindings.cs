/*
 * ScyllaBindings.cs
 * C# P/Invoke bindings for Scylla Import Reconstruction DLL (x64)
 */

using System;
using System.Runtime.InteropServices;
using System.Runtime.ExceptionServices;
using System.IO;

namespace MegaDumper
{
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

    public static class ScyllaBindings
    {
        private const string SCYLLA_DLL_X64 = "Scylla.dll";

        public static bool IsAvailable
        {
            get
            {
                try
                {
                    var version = VersionInformation();
                    return !string.IsNullOrEmpty(version);
                }
                catch (Exception ex)
                {
                    LastLoadError = $"Load error: {ex.GetType().Name} - {ex.Message}";
                    return false;
                }
            }
        }
        
        public static string LastLoadError { get; private set; } = string.Empty;

        #region Native Imports

        [DllImport("Scylla.dll", EntryPoint = "ScyllaVersionInformationW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        private static extern IntPtr ScyllaVersionInformationW_x64();

        [DllImport("Scylla.dll", EntryPoint = "ScyllaIatSearch", CallingConvention = CallingConvention.StdCall)]
        private static extern int ScyllaIatSearch_x64(
            uint dwProcessId,
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

        [DllImport("Scylla.dll", EntryPoint = "ScyllaRebuildFileW", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ScyllaRebuildFileW_x64(
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

        #endregion

        public static string VersionInformation()
        {
            try { return Marshal.PtrToStringUni(ScyllaVersionInformationW_x64()); } catch { return null; }
        }

        public static bool IsProcessAccessible(uint processId)
        {
            try
            {
                using (var proc = System.Diagnostics.Process.GetProcessById((int)processId)) { return !proc.HasExited; }
            }
            catch { return false; }
        }

        public static int IatSearch(uint processId, ulong imageBase, out UIntPtr iatStart, out uint iatSize, ulong searchStart, bool advancedSearch)
        {
             return ScyllaIatSearch_x64(processId, out iatStart, out iatSize, (UIntPtr)searchStart, advancedSearch);
        }

        public static ScyllaError IatFix(uint processId, ulong imageBase, UIntPtr iatStart, uint iatSize, bool createNewIat, string dumpFilePath, string outputFilePath)
        {
             return (ScyllaError)ScyllaIatFixAutoW_x64(processId, (UIntPtr)imageBase, iatStart, iatSize, createNewIat, dumpFilePath, outputFilePath);
        }

        public static bool RebuildFile(string filePath, bool removeDosStub, bool updatePeHeaderChecksum, bool createBackup)
        {
             return ScyllaRebuildFileW_x64(filePath, removeDosStub, updatePeHeaderChecksum, createBackup);
        }

        public static ScyllaError FixImportsAutoDetect(
            uint processId,
            ulong imageBase,
            ulong entryPoint,
            string dumpFilePath,
            string outputFilePath,
            bool advancedSearch = true,
            bool createNewIat = true)
        {
            // Always use x64 Scylla (Handles WoW64 automatically)
            return FixImportsAutoX64(processId, imageBase, entryPoint, dumpFilePath, outputFilePath, advancedSearch, createNewIat);
        }

        public static ScyllaError FixImportsAutoX64(
            uint processId,
            ulong imageBase,
            ulong entryPoint,
            string dumpFilePath,
            string outputFilePath,
            bool advancedSearch = true,
            bool createNewIat = true)
        {
            try
            {
                if (!IsProcessAccessible(processId)) return ScyllaError.ProcessOpenFailed;
                
                UIntPtr outIatStart;
                uint outIatSize;
                
                int searchResult = ScyllaIatSearch_x64(processId, out outIatStart, out outIatSize, (UIntPtr)entryPoint, advancedSearch);
                
                if (searchResult != 0) return (ScyllaError)searchResult;
                if (outIatSize == 0) return ScyllaError.IatNotFound;
                
                return (ScyllaError)ScyllaIatFixAutoW_x64(processId, (UIntPtr)imageBase, outIatStart, outIatSize, createNewIat, dumpFilePath, outputFilePath);
            }
            catch (Exception) { return ScyllaError.ProcessOpenFailed; }
        }

        public static bool DumpProcessX64(uint processId, ulong imageBase, ulong entryPoint, string outputPath, string inputFilePath = null)
        {
            try
            {
                if (!IsProcessAccessible(processId)) return false;
                return ScyllaDumpProcessW_x64((UIntPtr)processId, inputFilePath, (UIntPtr)imageBase, (UIntPtr)entryPoint, outputPath);
            }
            catch { return false; }
        }

        // Methods invoked by MainForm that we determine are necessary to keep for compatibility
        public static bool IsProcess32Bit(uint processId)
        {
            // Simplified check or just return true/false if needed. 
            // MainForm assumes this method exists.
            
            // Re-implement IsProcess32Bit correctly as used by MainForm logic?
            // Actually, now we don't need it for dispatch, but MainForm might call it for display?
            // Yes, MainForm checks it. We should keep it.
            
            IntPtr hProcess = IntPtr.Zero;
            try
            {
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, processId);
                if (hProcess == IntPtr.Zero) return false;
                if (!Environment.Is64BitOperatingSystem) return true;
                if (!IsWow64Process(hProcess, out bool isWow64)) return false;
                return isWow64;
            }
            catch { return false; }
            finally { if (hProcess != IntPtr.Zero) CloseHandle(hProcess); }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        
    }
}
