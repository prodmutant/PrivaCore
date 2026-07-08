using System;
using System.IO;
using System.Management;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Diagnostics;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Manages Hyper-V virtual machines for honeypot deployment
    /// Now supports both Generation 1 (BIOS) and Generation 2 (UEFI) VMs
    /// </summary>
    public class HyperVManager
    {
        private const string NAMESPACE = @"root\virtualization\v2";
        private ManagementScope _scope;
        private string _vmStoragePath = @"C:\HyperV\VMs";
        private string _vhdStoragePath = @"C:\HyperV\VHDs";

        public HyperVManager()
        {
            InitializeScope();
            EnsureDirectoriesExist();
        }

        private void InitializeScope()
        {
            try
            {
                _scope = new ManagementScope(NAMESPACE, null);
                _scope.Connect();
            }
            catch (Exception ex)
            {
                throw new Exception("Failed to connect to Hyper-V. Ensure Hyper-V is installed and you have administrator privileges.", ex);
            }
        }
        private void ConfigureNetworkAdapter(string vmName, NetworkAdapterType networkType)
        {
            try
            {
                Debug.WriteLine($"Configuring network: {networkType}");

                switch (networkType)
                {
                    case NetworkAdapterType.NAT:
                        // Use Default Switch (NAT) - usually created by Hyper-V automatically
                        try
                        {
                            RunPowerShell($"Connect-VMNetworkAdapter -VMName '{vmName}' -SwitchName 'Default Switch'");
                            Debug.WriteLine("Connected to Default Switch (NAT)");
                        }
                        catch
                        {
                            Debug.WriteLine("Default Switch not found, using first available switch");
                            // Fallback: connect to first available switch
                            RunPowerShell($"$switch = Get-VMSwitch | Select-Object -First 1; if ($switch) {{ Connect-VMNetworkAdapter -VMName '{vmName}' -SwitchName $switch.Name }}");
                        }
                        break;

                    case NetworkAdapterType.Bridged:
                    case NetworkAdapterType.External:
                        // Connect to external switch (bridged to physical network)
                        try
                        {
                            // Try to find an external switch
                            string externalSwitch = RunPowerShell("Get-VMSwitch | Where-Object { $_.SwitchType -eq 'External' } | Select-Object -First 1 -ExpandProperty Name");

                            if (!string.IsNullOrWhiteSpace(externalSwitch))
                            {
                                RunPowerShell($"Connect-VMNetworkAdapter -VMName '{vmName}' -SwitchName '{externalSwitch.Trim()}'");
                                Debug.WriteLine($"Connected to external switch: {externalSwitch.Trim()}");
                            }
                            else
                            {
                                Debug.WriteLine("No external switch found. Creating one...");
                                // Prompt user or create external switch
                                throw new Exception("No external (bridged) network switch found. Please create one in Hyper-V Manager:\n\n" +
                                    "1. Open Hyper-V Manager\n" +
                                    "2. Click 'Virtual Switch Manager'\n" +
                                    "3. Create new 'External' switch\n" +
                                    "4. Select your physical network adapter\n" +
                                    "5. Try creating the VM again");
                            }
                        }
                        catch (Exception ex)
                        {
                            throw new Exception($"Could not configure bridged network: {ex.Message}", ex);
                        }
                        break;

                    case NetworkAdapterType.Internal:
                        // Use internal switch (VM to VM + Host)
                        try
                        {
                            string internalSwitch = RunPowerShell("Get-VMSwitch | Where-Object { $_.SwitchType -eq 'Internal' } | Select-Object -First 1 -ExpandProperty Name");

                            if (!string.IsNullOrWhiteSpace(internalSwitch))
                            {
                                RunPowerShell($"Connect-VMNetworkAdapter -VMName '{vmName}' -SwitchName '{internalSwitch.Trim()}'");
                                Debug.WriteLine($"Connected to internal switch: {internalSwitch.Trim()}");
                            }
                            else
                            {
                                // Create internal switch
                                Debug.WriteLine("Creating internal switch...");
                                RunPowerShell("New-VMSwitch -Name 'Internal Switch' -SwitchType Internal");
                                RunPowerShell($"Connect-VMNetworkAdapter -VMName '{vmName}' -SwitchName 'Internal Switch'");
                                Debug.WriteLine("Created and connected to Internal Switch");
                            }
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"Warning: Could not configure internal network: {ex.Message}");
                        }
                        break;

                    case NetworkAdapterType.Private:
                        // Private switch (VM to VM only, no host)
                        try
                        {
                            string privateSwitch = RunPowerShell("Get-VMSwitch | Where-Object { $_.SwitchType -eq 'Private' } | Select-Object -First 1 -ExpandProperty Name");

                            if (!string.IsNullOrWhiteSpace(privateSwitch))
                            {
                                RunPowerShell($"Connect-VMNetworkAdapter -VMName '{vmName}' -SwitchName '{privateSwitch.Trim()}'");
                                Debug.WriteLine($"Connected to private switch: {privateSwitch.Trim()}");
                            }
                            else
                            {
                                // Create private switch
                                Debug.WriteLine("Creating private switch...");
                                RunPowerShell("New-VMSwitch -Name 'Private Switch' -SwitchType Private");
                                RunPowerShell($"Connect-VMNetworkAdapter -VMName '{vmName}' -SwitchName 'Private Switch'");
                                Debug.WriteLine("Created and connected to Private Switch");
                            }
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"Warning: Could not configure private network: {ex.Message}");
                        }
                        break;
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Network configuration error: {ex.Message}");
                throw;
            }
        }
        private void EnsureDirectoriesExist()
        {
            try
            {
                Directory.CreateDirectory(_vmStoragePath);
                Directory.CreateDirectory(_vhdStoragePath);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to create storage directories: {ex.Message}", ex);
            }
        }

        public bool IsHyperVAvailable()
        {
            try
            {
                var query = new ObjectQuery("SELECT * FROM Msvm_VirtualSystemManagementService");
                using (var searcher = new ManagementObjectSearcher(_scope, query))
                {
                    return searcher.Get().Count > 0;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Creates a new VM from an ISO file with specified generation
        /// </summary>
        /// <param name="config">VM configuration</param>
        /// <param name="isoPath">Path to ISO file (optional)</param>
        /// <param name="generation">VM Generation (1 = BIOS, 2 = UEFI)</param>
        public async Task<string> CreateVirtualMachine(HoneypotVM config, string? isoPath = null, int generation = 1)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (generation != 1 && generation != 2)
                    {
                        throw new Exception("Invalid VM generation. Must be 1 or 2.");
                    }

                    string vmPath = Path.Combine(_vmStoragePath, config.Name);
                    string vhdPath = Path.Combine(_vhdStoragePath, $"{config.Name}.vhdx");
                    Directory.CreateDirectory(vmPath);

                    Debug.WriteLine($"=== Creating VM: {config.Name} ===");
                    Debug.WriteLine($"Generation: {generation}");
                    Debug.WriteLine($"ISO: {isoPath ?? "None"}");
                    Debug.WriteLine($"Memory: {config.MemoryMB} MB");
                    Debug.WriteLine($"CPU: {config.CPUCores} cores");
                    Debug.WriteLine($"Storage: {config.StorageSizeGB} GB");

                    // Step 1: Create VHD
                    Debug.WriteLine("Step 1: Creating VHD...");
                    RunPowerShell($"New-VHD -Path '{vhdPath}' -SizeBytes {config.StorageSizeGB}GB -Dynamic");

                    // Step 2: Create VM with selected generation
                    Debug.WriteLine($"Step 2: Creating VM (Generation {generation})...");
                    string createCmd = $"New-VM -Name '{config.Name}' -MemoryStartupBytes {config.MemoryMB}MB -Path '{vmPath}' -Generation {generation} -VHDPath '{vhdPath}'";
                    string vmIdOutput = RunPowerShell(createCmd + " | Select-Object -ExpandProperty VMId | Select-Object -ExpandProperty Guid");
                    string vmId = vmIdOutput.Trim();
                    Debug.WriteLine($"VM ID: {vmId}");

                    // Step 3: Configure memory
                    Debug.WriteLine("Step 3: Configuring dynamic memory...");
                    RunPowerShell($"Set-VMMemory -VMName '{config.Name}' -DynamicMemoryEnabled $true -MinimumBytes 128MB -StartupBytes {config.MemoryMB}MB -MaximumBytes {config.MemoryMB * 2}MB");

                    // Step 4: Set CPU count
                    Debug.WriteLine("Step 4: Setting CPU count...");
                    RunPowerShell($"Set-VMProcessor -VMName '{config.Name}' -Count {config.CPUCores}");

                    // Step 5: Add and configure network adapter
                    Debug.WriteLine("Step 5: Adding network adapter...");
                    RunPowerShell($"Add-VMNetworkAdapter -VMName '{config.Name}'");

                    Debug.WriteLine($"Configuring network type: {config.NetworkType}");
                    ConfigureNetworkAdapter(config.Name, config.NetworkType);

                    // Step 6: Attach ISO if provided
                    if (!string.IsNullOrEmpty(isoPath) && File.Exists(isoPath))
                    {
                        Debug.WriteLine($"Step 6: Attaching ISO: {isoPath}");

                        if (generation == 1)
                        {
                            // Generation 1: Use Set-VMDvdDrive (VM has DVD drive by default)
                            Debug.WriteLine("Configuring Generation 1 DVD drive...");
                            RunPowerShell($"Set-VMDvdDrive -VMName '{config.Name}' -Path '{isoPath}'");
                            Debug.WriteLine("ISO attached successfully (Gen 1 auto-boots from DVD)");
                        }
                        else
                        {
                            // Generation 2: Add DVD drive and configure UEFI boot order
                            Debug.WriteLine("Configuring Generation 2 DVD drive and boot order...");
                            RunPowerShell($"Add-VMDvdDrive -VMName '{config.Name}' -Path '{isoPath}'");

                            Debug.WriteLine("Disabling Secure Boot...");
                            RunPowerShell($"Set-VMFirmware -VMName '{config.Name}' -EnableSecureBoot Off");

                            Debug.WriteLine("Setting boot order (DVD first)...");
                            RunPowerShell($"$dvd = Get-VMDvdDrive -VMName '{config.Name}'; $hdd = Get-VMHardDiskDrive -VMName '{config.Name}'; Set-VMFirmware -VMName '{config.Name}' -BootOrder $dvd,$hdd");
                            Debug.WriteLine("ISO attached and boot order configured successfully");
                        }
                    }
                    else
                    {
                        Debug.WriteLine("No ISO provided or file not found");

                        // For Generation 2, still disable Secure Boot even without ISO
                        if (generation == 2)
                        {
                            Debug.WriteLine("Disabling Secure Boot for Generation 2 VM...");
                            RunPowerShell($"Set-VMFirmware -VMName '{config.Name}' -EnableSecureBoot Off");
                        }
                    }

                    Debug.WriteLine("=== VM created successfully! ===");
                    return vmId;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"!!! ERROR creating VM: {ex.Message}");
                    throw new Exception($"Error creating VM: {ex.Message}", ex);
                }
            });
        }

        /// <summary>
        /// Creates VM from a pre-built base image using differencing disks
        /// </summary>
        /// <param name="config">VM configuration</param>
        /// <param name="baseImagePath">Path to base VHDX image</param>
        /// <param name="generation">VM Generation (1 = BIOS, 2 = UEFI)</param>
        public async Task<string> CreateVMFromBaseImage(HoneypotVM config, string baseImagePath, int generation = 1)
        {
            return await Task.Run(() =>
            {
                try
                {
                    if (!File.Exists(baseImagePath))
                    {
                        throw new Exception($"Base image not found: {baseImagePath}");
                    }

                    if (generation != 1 && generation != 2)
                    {
                        throw new Exception("Invalid VM generation. Must be 1 or 2.");
                    }

                    string vmPath = Path.Combine(_vmStoragePath, config.Name);
                    string vhdPath = Path.Combine(_vhdStoragePath, $"{config.Name}.vhdx");
                    Directory.CreateDirectory(vmPath);

                    Debug.WriteLine($"=== Creating VM from base image ===");
                    Debug.WriteLine($"VM Name: {config.Name}");
                    Debug.WriteLine($"Base Image: {baseImagePath}");
                    Debug.WriteLine($"Generation: {generation}");

                    // Step 1: Create differencing disk from base image
                    Debug.WriteLine("Creating differencing disk...");
                    RunPowerShell($"New-VHD -Path '{vhdPath}' -ParentPath '{baseImagePath}' -Differencing");

                    // Step 2: Create VM with differencing disk
                    Debug.WriteLine("Creating VM...");
                    string vmIdOutput = RunPowerShell($"New-VM -Name '{config.Name}' -MemoryStartupBytes {config.MemoryMB}MB -Path '{vmPath}' -Generation {generation} -VHDPath '{vhdPath}' | Select-Object -ExpandProperty VMId | Select-Object -ExpandProperty Guid");
                    string vmId = vmIdOutput.Trim();

                    // Step 3: Configure VM
                    Debug.WriteLine("Configuring VM...");
                    RunPowerShell($"Set-VMMemory -VMName '{config.Name}' -DynamicMemoryEnabled $true -MinimumBytes 128MB -StartupBytes {config.MemoryMB}MB -MaximumBytes {config.MemoryMB * 2}MB");
                    RunPowerShell($"Set-VMProcessor -VMName '{config.Name}' -Count {config.CPUCores}");
                    RunPowerShell($"Add-VMNetworkAdapter -VMName '{config.Name}'");
                    ConfigureNetworkAdapter(config.Name, config.NetworkType);  // ADD THIS LINE
                    // Step 4: Configure boot settings based on generation
                    if (generation == 2)
                    {
                        Debug.WriteLine("Disabling Secure Boot for Generation 2...");
                        RunPowerShell($"Set-VMFirmware -VMName '{config.Name}' -EnableSecureBoot Off");
                    }

                    config.UsesDifferencingDisk = true;
                    config.BaseImagePath = baseImagePath;

                    Debug.WriteLine("=== VM created successfully from base image! ===");
                    return vmId;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"!!! ERROR: {ex.Message}");
                    throw new Exception($"Error creating VM from base image: {ex.Message}", ex);
                }
            });
        }

        /// <summary>
        /// Executes a PowerShell command and returns output
        /// </summary>
        private string RunPowerShell(string command)
        {
            try
            {
                var startInfo = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{command}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var process = Process.Start(startInfo))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    string error = process.StandardError.ReadToEnd();
                    process.WaitForExit();

                    if (process.ExitCode != 0 && !string.IsNullOrEmpty(error))
                    {
                        Debug.WriteLine($"PowerShell Error: {error}");
                        throw new Exception(error);
                    }

                    return output;
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"PowerShell execution failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Gets the real current state of a VM from Hyper-V
        /// </summary>
        public HoneypotStatus GetVMRealState(string vmId)
        {
            try
            {
                var query = new ObjectQuery($"SELECT * FROM Msvm_ComputerSystem WHERE Name='{vmId}'");
                using (var searcher = new ManagementObjectSearcher(_scope, query))
                {
                    foreach (ManagementObject vm in searcher.Get())
                    {
                        ushort state = (ushort)vm["EnabledState"];
                        return ConvertToHoneypotStatus(state);
                    }
                }
                return HoneypotStatus.Error;
            }
            catch
            {
                return HoneypotStatus.Error;
            }
        }

        /// <summary>
        /// Starts a VM
        /// </summary>
        public async Task<bool> StartVM(string vmId)
        {
            return await Task.Run(() =>
            {
                try
                {
                    Debug.WriteLine($"Starting VM: {vmId}");

                    var currentState = GetVMRealState(vmId);
                    if (currentState == HoneypotStatus.Running)
                    {
                        Debug.WriteLine("VM is already running");
                        return true;
                    }

                    string vmName = GetVMNameById(vmId);
                    if (string.IsNullOrEmpty(vmName))
                    {
                        throw new Exception("VM not found");
                    }

                    RunPowerShell($"Start-VM -Name '{vmName}'");
                    Debug.WriteLine("VM started successfully");
                    return true;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error starting VM: {ex.Message}");
                    throw new Exception($"Error starting VM: {ex.Message}", ex);
                }
            });
        }

        /// <summary>
        /// Stops a VM
        /// </summary>
        public async Task<bool> StopVM(string vmId)
        {
            return await Task.Run(() =>
            {
                try
                {
                    Debug.WriteLine($"Stopping VM: {vmId}");

                    var currentState = GetVMRealState(vmId);
                    if (currentState == HoneypotStatus.Stopped)
                    {
                        Debug.WriteLine("VM is already stopped");
                        return true;
                    }

                    string vmName = GetVMNameById(vmId);
                    if (string.IsNullOrEmpty(vmName))
                    {
                        throw new Exception("VM not found");
                    }

                    RunPowerShell($"Stop-VM -Name '{vmName}' -Force");
                    Debug.WriteLine("VM stopped successfully");
                    return true;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error stopping VM: {ex.Message}");
                    throw new Exception($"Error stopping VM: {ex.Message}", ex);
                }
            });
        }

        /// <summary>
        /// Deletes a VM and its associated VHD files
        /// </summary>
        public async Task<bool> DeleteVM(string vmId)
        {
            return await Task.Run(() =>
            {
                try
                {
                    Debug.WriteLine($"Deleting VM: {vmId}");

                    string vmName = GetVMNameById(vmId);
                    if (string.IsNullOrEmpty(vmName))
                    {
                        Debug.WriteLine("VM not found, may already be deleted");
                        return true;
                    }

                    // Stop VM first
                    try
                    {
                        Debug.WriteLine("Stopping VM before deletion...");
                        RunPowerShell($"Stop-VM -Name '{vmName}' -Force");
                        System.Threading.Thread.Sleep(2000);
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Warning: Could not stop VM: {ex.Message}");
                    }

                    // Get VHD paths before deleting VM
                    string vhdPaths = "";
                    try
                    {
                        vhdPaths = RunPowerShell($"Get-VMHardDiskDrive -VMName '{vmName}' | Select-Object -ExpandProperty Path");
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Warning: Could not get VHD paths: {ex.Message}");
                    }

                    // Remove VM
                    Debug.WriteLine("Removing VM...");
                    RunPowerShell($"Remove-VM -Name '{vmName}' -Force");
                    System.Threading.Thread.Sleep(2000);

                    // Delete VHD files
                    if (!string.IsNullOrEmpty(vhdPaths))
                    {
                        foreach (var vhdPath in vhdPaths.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
                        {
                            try
                            {
                                string path = vhdPath.Trim();
                                if (File.Exists(path))
                                {
                                    Debug.WriteLine($"Deleting VHD: {path}");
                                    File.Delete(path);
                                }
                            }
                            catch (Exception ex)
                            {
                                Debug.WriteLine($"Warning: Could not delete VHD: {ex.Message}");
                            }
                        }
                    }

                    Debug.WriteLine("VM deleted successfully");
                    return true;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error deleting VM: {ex.Message}");
                    throw new Exception($"Error deleting VM: {ex.Message}", ex);
                }
            });
        }

        /// <summary>
        /// Gets VM name from its ID
        /// </summary>
        private string GetVMNameById(string vmId)
        {
            try
            {
                string output = RunPowerShell($"Get-VM | Where-Object {{ $_.VMId.Guid -eq '{vmId}' }} | Select-Object -ExpandProperty Name");
                return output.Trim();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Gets all VMs from Hyper-V
        /// </summary>
        public List<HoneypotVM> GetAllVMs()
        {
            var vms = new List<HoneypotVM>();

            try
            {
                Debug.WriteLine("Retrieving all VMs from Hyper-V...");

                var query = new ObjectQuery("SELECT * FROM Msvm_ComputerSystem WHERE Caption='Virtual Machine'");
                using (var searcher = new ManagementObjectSearcher(_scope, query))
                {
                    foreach (ManagementObject vm in searcher.Get())
                    {
                        try
                        {
                            var vmId = vm["Name"]?.ToString();
                            var vmName = vm["ElementName"]?.ToString();
                            ushort enabledState = (ushort)vm["EnabledState"];

                            var honeypot = new HoneypotVM
                            {
                                Name = vmName,
                                Hostname = vmName, // ADD THIS
                                HyperVVMId = vmId,
                                Status = ConvertToHoneypotStatus(enabledState),
                                OSType = "Hyper-V VM",
                                MemoryMB = 1024,
                                CPUCores = 1,
                                StorageSizeGB = 10
                            };

                            vms.Add(honeypot);
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"Error processing VM: {ex.Message}");
                        }
                    }
                }

                Debug.WriteLine($"Retrieved {vms.Count} VMs");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error retrieving VMs: {ex.Message}");
                throw new Exception($"Error retrieving VMs: {ex.Message}", ex);
            }

            return vms;
        }

        /// <summary>
        /// Updates VM memory allocation
        /// </summary>
        public async Task<bool> UpdateVMMemory(string vmId, long memoryMB)
        {
            return await Task.Run(() =>
            {
                try
                {
                    string vmName = GetVMNameById(vmId);
                    if (string.IsNullOrEmpty(vmName))
                    {
                        throw new Exception("VM not found");
                    }

                    RunPowerShell($"Set-VMMemory -VMName '{vmName}' -StartupBytes {memoryMB}MB");
                    return true;
                }
                catch (Exception ex)
                {
                    throw new Exception($"Error updating VM memory: {ex.Message}", ex);
                }
            });
        }

        /// <summary>
        /// Updates VM CPU count
        /// </summary>
        public async Task<bool> UpdateVMCPU(string vmId, int cpuCores)
        {
            return await Task.Run(() =>
            {
                try
                {
                    string vmName = GetVMNameById(vmId);
                    if (string.IsNullOrEmpty(vmName))
                    {
                        throw new Exception("VM not found");
                    }

                    RunPowerShell($"Set-VMProcessor -VMName '{vmName}' -Count {cpuCores}");
                    return true;
                }
                catch (Exception ex)
                {
                    throw new Exception($"Error updating VM CPU: {ex.Message}", ex);
                }
            });
        }

        /// <summary>
        /// Stops all running VMs
        /// </summary>
        public async Task StopAllVMs()
        {
            try
            {
                Debug.WriteLine("Stopping all VMs...");
                var vms = GetAllVMs();

                foreach (var vm in vms)
                {
                    if (vm.Status == HoneypotStatus.Running)
                    {
                        try
                        {
                            await StopVM(vm.HyperVVMId);
                        }
                        catch (Exception ex)
                        {
                            Debug.WriteLine($"Error stopping {vm.Name}: {ex.Message}");
                        }
                    }
                }

                Debug.WriteLine("All VMs stopped");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error in StopAllVMs: {ex.Message}");
            }
        }

        /// <summary>
        /// Converts Hyper-V EnabledState to HoneypotStatus
        /// </summary>
        private HoneypotStatus ConvertToHoneypotStatus(ushort enabledState)
        {
            return enabledState switch
            {
                2 => HoneypotStatus.Running,      // Enabled/Running
                3 => HoneypotStatus.Stopped,      // Disabled/Off
                6 => HoneypotStatus.Paused,       // Saved
                9 => HoneypotStatus.Starting,     // Starting
                4 => HoneypotStatus.Stopping,     // Shutting Down
                10 => HoneypotStatus.Stopping,    // Stopping
                32768 => HoneypotStatus.Paused,   // Paused
                32769 => HoneypotStatus.Paused,   // Suspended
                _ => HoneypotStatus.Error         // Unknown
            };
        }
    }
}