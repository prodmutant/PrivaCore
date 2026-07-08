using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Renci.SshNet;
using PROSCANNERCONT.Models;

namespace PROSCANNERCONT.Services
{
    /// <summary>
    /// Manages SSH connections to honeypot VMs
    /// Handles command execution, file transfer, and connection pooling
    /// </summary>
    public class SSHConnectionManager
    {
        private readonly Dictionary<string, SshClient> _activeConnections;
        private readonly Dictionary<string, ShellStream> _activeShells;
        private readonly object _lockObject = new object();

        public event EventHandler<SSHConnectionEventArgs> ConnectionEstablished;
        public event EventHandler<SSHConnectionEventArgs> ConnectionClosed;
        public event EventHandler<SSHCommandEventArgs> CommandExecuted;

        public SSHConnectionManager()
        {
            _activeConnections = new Dictionary<string, SshClient>();
            _activeShells = new Dictionary<string, ShellStream>();
        }

        // ============================================================
        // CONNECTION MANAGEMENT
        // ============================================================

        /// <summary>
        /// Connect to a honeypot VM via SSH
        /// </summary>
        public async Task<SshClient?> ConnectAsync(HoneypotVM vm, string? password = null, CancellationToken cancellationToken = default)
        {
            return await Task.Run(() =>
            {
                try
                {
                    Debug.WriteLine($"SSH: Connecting to {vm.SSHUsername}@{vm.SSHHost}:{vm.SSHPort}");

                    // Check if already connected
                    if (_activeConnections.ContainsKey(vm.HyperVVMId) && _activeConnections[vm.HyperVVMId].IsConnected)
                    {
                        Debug.WriteLine("SSH: Already connected, returning existing connection");
                        return _activeConnections[vm.HyperVVMId];
                    }

                    SshClient client;

                    // Determine authentication method
                    if (vm.UseSSHKey && !string.IsNullOrEmpty(vm.SSHKeyPath))
                    {
                        // SSH Key authentication
                        var keyFile = new PrivateKeyFile(vm.SSHKeyPath);
                        var keyAuth = new PrivateKeyAuthenticationMethod(vm.SSHUsername, keyFile);
                        var connectionInfo = new ConnectionInfo(vm.SSHHost, vm.SSHPort, vm.SSHUsername, keyAuth);
                        client = new SshClient(connectionInfo);
                    }
                    else
                    {
                        // Password authentication
                        string pass = password ?? DecryptPassword(vm.SSHPasswordEncrypted);

                        if (string.IsNullOrEmpty(pass))
                        {
                            throw new Exception("No password provided");
                        }

                        client = new SshClient(vm.SSHHost, vm.SSHPort, vm.SSHUsername, pass);
                    }

                    // Set timeout
                    client.ConnectionInfo.Timeout = TimeSpan.FromSeconds(10);

                    // Connect
                    client.Connect();

                    if (!client.IsConnected)
                    {
                        throw new Exception("Failed to establish SSH connection");
                    }

                    // Store connection
                    lock (_lockObject)
                    {
                        _activeConnections[vm.HyperVVMId] = client;
                    }

                    Debug.WriteLine($"SSH: Connected successfully to {vm.SSHHost}");

                    // Fire event
                    ConnectionEstablished?.Invoke(this, new SSHConnectionEventArgs
                    {
                        VMId = vm.HyperVVMId,
                        Host = vm.SSHHost,
                        Username = vm.SSHUsername,
                        Success = true
                    });

                    return client;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"SSH: Connection failed - {ex.Message}");

                    ConnectionEstablished?.Invoke(this, new SSHConnectionEventArgs
                    {
                        VMId = vm.HyperVVMId,
                        Host = vm.SSHHost,
                        Username = vm.SSHUsername,
                        Success = false,
                        Error = ex.Message
                    });

                    throw new Exception($"SSH connection failed: {ex.Message}", ex);
                }
            }, cancellationToken);
        }

        /// <summary>
        /// Disconnect from a VM
        /// </summary>
        public void Disconnect(string vmId)
        {
            try
            {
                lock (_lockObject)
                {
                    // Close shell stream
                    if (_activeShells.ContainsKey(vmId))
                    {
                        _activeShells[vmId]?.Dispose();
                        _activeShells.Remove(vmId);
                    }

                    // Disconnect SSH client
                    if (_activeConnections.ContainsKey(vmId))
                    {
                        var client = _activeConnections[vmId];
                        if (client.IsConnected)
                        {
                            client.Disconnect();
                        }
                        client.Dispose();
                        _activeConnections.Remove(vmId);

                        Debug.WriteLine($"SSH: Disconnected from VM {vmId}");

                        ConnectionClosed?.Invoke(this, new SSHConnectionEventArgs
                        {
                            VMId = vmId,
                            Success = true
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"SSH: Error disconnecting - {ex.Message}");
            }
        }

        /// <summary>
        /// Check if connected to a VM
        /// </summary>
        public bool IsConnected(string vmId)
        {
            lock (_lockObject)
            {
                return _activeConnections.ContainsKey(vmId) && _activeConnections[vmId].IsConnected;
            }
        }

        /// <summary>
        /// Get active SSH client for a VM
        /// </summary>
        public SshClient GetClient(string vmId)
        {
            lock (_lockObject)
            {
                if (_activeConnections.ContainsKey(vmId) && _activeConnections[vmId].IsConnected)
                {
                    return _activeConnections[vmId];
                }
                return null;
            }
        }

        // ============================================================
        // COMMAND EXECUTION
        // ============================================================

        /// <summary>
        /// Execute a single command and return output
        /// </summary>
        public async Task<SSHCommandResult> ExecuteCommandAsync(string vmId, string command, CancellationToken cancellationToken = default)
        {
            return await Task.Run(() =>
            {
                try
                {
                    var client = GetClient(vmId);
                    if (client == null || !client.IsConnected)
                    {
                        throw new Exception("Not connected to VM");
                    }

                    Debug.WriteLine($"SSH: Executing command: {command}");

                    var cmd = client.CreateCommand(command);
                    var result = cmd.Execute();

                    var cmdResult = new SSHCommandResult
                    {
                        Command = command,
                        Output = result,
                        Error = cmd.Error,
                        ExitCode = cmd.ExitStatus ?? 0,
                        Success = cmd.ExitStatus == 0
                    };

                    Debug.WriteLine($"SSH: Command completed - Exit code: {cmd.ExitStatus}");

                    CommandExecuted?.Invoke(this, new SSHCommandEventArgs
                    {
                        VMId = vmId,
                        Command = command,
                        Result = cmdResult
                    });

                    return cmdResult;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"SSH: Command execution failed - {ex.Message}");

                    var errorResult = new SSHCommandResult
                    {
                        Command = command,
                        Error = ex.Message,
                        Success = false
                    };

                    CommandExecuted?.Invoke(this, new SSHCommandEventArgs
                    {
                        VMId = vmId,
                        Command = command,
                        Result = errorResult
                    });

                    return errorResult;
                }
            }, cancellationToken);
        }

        /// <summary>
        /// Execute command with sudo (prompts for password if needed)
        /// </summary>
        public async Task<SSHCommandResult> ExecuteSudoCommandAsync(string vmId, string command, string? password = null, CancellationToken cancellationToken = default)
        {
            // Prepend sudo -S to read password from stdin
            string sudoCommand = $"echo '{password}' | sudo -S {command}";
            return await ExecuteCommandAsync(vmId, sudoCommand, cancellationToken);
        }

        // ============================================================
        // INTERACTIVE SHELL
        // ============================================================

        /// <summary>
        /// Create an interactive shell stream
        /// </summary>
        public ShellStream CreateShellStream(string vmId)
        {
            try
            {
                var client = GetClient(vmId);
                if (client == null || !client.IsConnected)
                {
                    throw new Exception("Not connected to VM");
                }

                // Check if shell already exists
                lock (_lockObject)
                {
                    if (_activeShells.ContainsKey(vmId))
                    {
                        return _activeShells[vmId];
                    }
                }

                // Create new shell stream
                var shell = client.CreateShellStream("terminal", 80, 24, 800, 600, 1024);

                lock (_lockObject)
                {
                    _activeShells[vmId] = shell;
                }

                Debug.WriteLine($"SSH: Shell stream created for VM {vmId}");

                return shell;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"SSH: Failed to create shell stream - {ex.Message}");
                throw;
            }
        }

        /// <summary>
        /// Get existing shell stream
        /// </summary>
        public ShellStream GetShellStream(string vmId)
        {
            lock (_lockObject)
            {
                if (_activeShells.ContainsKey(vmId))
                {
                    return _activeShells[vmId];
                }
                return null;
            }
        }

        /// <summary>
        /// Close shell stream
        /// </summary>
        public void CloseShellStream(string vmId)
        {
            lock (_lockObject)
            {
                if (_activeShells.ContainsKey(vmId))
                {
                    _activeShells[vmId]?.Dispose();
                    _activeShells.Remove(vmId);
                    Debug.WriteLine($"SSH: Shell stream closed for VM {vmId}");
                }
            }
        }

        // ============================================================
        // FILE OPERATIONS
        // ============================================================

        /// <summary>
        /// Upload file to VM
        /// </summary>
        public async Task UploadFileAsync(string vmId, string localPath, string remotePath, CancellationToken cancellationToken = default)
        {
            await Task.Run(() =>
            {
                try
                {
                    var client = GetClient(vmId);
                    if (client == null || !client.IsConnected)
                    {
                        throw new Exception("Not connected to VM");
                    }

                    using var sftp = new SftpClient(client.ConnectionInfo);
                    sftp.Connect();

                    using var fileStream = File.OpenRead(localPath);
                    sftp.UploadFile(fileStream, remotePath);

                    sftp.Disconnect();

                    Debug.WriteLine($"SSH: File uploaded - {localPath} → {remotePath}");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"SSH: File upload failed - {ex.Message}");
                    throw;
                }
            }, cancellationToken);
        }

        /// <summary>
        /// Download file from VM
        /// </summary>
        public async Task DownloadFileAsync(string vmId, string remotePath, string localPath, CancellationToken cancellationToken = default)
        {
            await Task.Run(() =>
            {
                try
                {
                    var client = GetClient(vmId);
                    if (client == null || !client.IsConnected)
                    {
                        throw new Exception("Not connected to VM");
                    }

                    using var sftp = new SftpClient(client.ConnectionInfo);
                    sftp.Connect();

                    using var fileStream = File.Create(localPath);
                    sftp.DownloadFile(remotePath, fileStream);

                    sftp.Disconnect();

                    Debug.WriteLine($"SSH: File downloaded - {remotePath} → {localPath}");
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"SSH: File download failed - {ex.Message}");
                    throw;
                }
            }, cancellationToken);
        }

        // ============================================================
        // HELPER METHODS
        // ============================================================

        /// <summary>
        /// Test SSH connection without storing it
        /// </summary>
        public async Task<bool> TestConnectionAsync(string host, int port, string username, string password)
        {
            return await Task.Run(() =>
            {
                SshClient testClient = null;
                try
                {
                    testClient = new SshClient(host, port, username, password);
                    testClient.ConnectionInfo.Timeout = TimeSpan.FromSeconds(5);
                    testClient.Connect();

                    bool success = testClient.IsConnected;
                    testClient.Disconnect();

                    return success;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"SSH: Connection test failed - {ex.Message}");
                    return false;
                }
                finally
                {
                    testClient?.Dispose();
                }
            });
        }

        /// <summary>
        /// Encrypt password for storage
        /// </summary>
        public string EncryptPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                return null;

            try
            {
                byte[] data = Encoding.UTF8.GetBytes(password);
                byte[] encrypted = System.Security.Cryptography.ProtectedData.Protect(
                    data, null, System.Security.Cryptography.DataProtectionScope.CurrentUser);
                return Convert.ToBase64String(encrypted);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Password encryption failed: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Decrypt password from storage
        /// </summary>
        public string DecryptPassword(string encryptedPassword)
        {
            if (string.IsNullOrEmpty(encryptedPassword))
                return null;

            try
            {
                byte[] data = Convert.FromBase64String(encryptedPassword);
                byte[] decrypted = System.Security.Cryptography.ProtectedData.Unprotect(
                    data, null, System.Security.Cryptography.DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(decrypted);
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Password decryption failed: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Disconnect all active connections
        /// </summary>
        public void DisconnectAll()
        {
            lock (_lockObject)
            {
                var vmIds = new List<string>(_activeConnections.Keys);
                foreach (var vmId in vmIds)
                {
                    Disconnect(vmId);
                }
            }
        }
    }

    // ============================================================
    // SUPPORTING CLASSES
    // ============================================================

    /// <summary>
    /// Result of SSH command execution
    /// </summary>
    public class SSHCommandResult
    {
        public string Command { get; set; }
        public string Output { get; set; }
        public string Error { get; set; }
        public int ExitCode { get; set; }
        public bool Success { get; set; }

        public string CombinedOutput => string.IsNullOrEmpty(Error) ? Output : $"{Output}\n{Error}";
    }

    /// <summary>
    /// SSH connection event args
    /// </summary>
    public class SSHConnectionEventArgs : EventArgs
    {
        public string VMId { get; set; }
        public string Host { get; set; }
        public string Username { get; set; }
        public bool Success { get; set; }
        public string Error { get; set; }
    }

    /// <summary>
    /// SSH command execution event args
    /// </summary>
    public class SSHCommandEventArgs : EventArgs
    {
        public string VMId { get; set; }
        public string Command { get; set; }
        public SSHCommandResult Result { get; set; }
    }
}