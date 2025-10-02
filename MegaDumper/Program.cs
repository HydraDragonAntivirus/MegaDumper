/*
 * Created by SharpDevelop.
 * User: Bogdan
 * Date: 11.10.2010
 * Time: 15:47
 * * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.Windows.Forms;
using System.IO;
using System.Threading.Tasks;

namespace Mega_Dumper
{
    /// <summary>
    /// Class with program entry point.
    /// </summary>
    internal sealed class Program
    {
        /// <summary>
        /// Program entry point. Handles GUI or CLI mode based on arguments.
        /// </summary>
        [STAThread]
        private static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                // No arguments, run in standard GUI mode.
                Application.EnableVisualStyles();
                Application.Run(new MainForm());
            }
            else
            {
                // Arguments detected, run in CLI mode.
                RunCli(args).GetAwaiter().GetResult();
            }
        }

        /// <summary>
        /// Parses command-line arguments and executes the requested operation.
        /// </summary>
        private static async Task RunCli(string[] args)
        {
            uint pid = 0;
            string outputPath = null;
            bool whitelistMode = false;
            string whitelistPath = "whitelist_hashes.txt"; // Default filename for the whitelist

            // Simple argument parsing logic
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i].ToLowerInvariant())
                {
                    case "--pid":
                        if (i + 1 < args.Length && uint.TryParse(args[i + 1], out pid))
                        {
                            i++; // Consume the value
                        }
                        else
                        {
                            Console.WriteLine("Error: --pid requires a valid integer process ID.");
                            PrintUsage();
                            return;
                        }
                        break;

                    case "--output":
                        if (i + 1 < args.Length)
                        {
                            outputPath = args[i + 1];
                            i++; // Consume the value
                        }
                        else
                        {
                            Console.WriteLine("Error: --output requires a file path.");
                            PrintUsage();
                            return;
                        }
                        break;

                    case "--whitelist":
                        whitelistMode = true;
                        // Allow optionally specifying the output path for the whitelist
                        if (i + 1 < args.Length && !args[i + 1].StartsWith("--"))
                        {
                            whitelistPath = args[i + 1];
                            i++;
                        }
                        break;

                    default:
                        Console.WriteLine($"Error: Unknown or invalid argument '{args[i]}'");
                        PrintUsage();
                        return;
                }
            }

            // A MainForm instance is needed to access the logic methods.
            // We create it but do not run Application.Run() on it.
            var logic = new MainForm();
            logic.EnableDebuggerPrivileges();

            // auto-load default whitelist if present (so dumps will consult it automatically)
            string defaultWhitelist = Path.Combine(Directory.GetCurrentDirectory(), "whitelist_hashes.txt");
            if (File.Exists(defaultWhitelist))
            {
                logic.LoadWhitelistFile(defaultWhitelist);
            }

            if (whitelistMode)
            {
                logic.GenerateWhitelist(whitelistPath);
            }
            else if (pid > 0 && outputPath != null)
            {
                Console.WriteLine($"Attempting to dump process with PID: {pid} into directory: '{outputPath}'...");
                string result = await logic.DumpProcessByIdCli(pid, outputPath);
                Console.WriteLine($"\nResult: {result}");
            }
            else
            {
                // If arguments are provided but don't match the required combinations
                Console.WriteLine("Error: Invalid argument combination.");
                PrintUsage();
            }
        }

        /// <summary>
        /// Prints the command-line usage instructions to the console.
        /// </summary>
        private static void PrintUsage()
        {
            Console.WriteLine("\n===========================");
            Console.WriteLine("  Mega Dumper CLI Usage");
            Console.WriteLine("===========================");
            Console.WriteLine("\nTo dump a process by its PID:");
            Console.WriteLine("  Mega_Dumper.exe --pid <ProcessID> --output <TargetDirectoryPath>");
            Console.WriteLine("\nTo generate a system-wide whitelist of memory-address hashes:");
            Console.WriteLine("  Mega_Dumper.exe --whitelist [OptionalOutputFilePath.txt]");
        }
    }
}
