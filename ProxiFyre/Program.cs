using Newtonsoft.Json;
using NLog;
using NLog.Config;
using Socksifier;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using Topshelf;
using LogLevel = Socksifier.LogLevel;

namespace ProxiFyre
{
    /// <summary>
    /// Main class for the SOCKS proxy application.
    /// Handles service lifecycle, configuration loading, and proxy association.
    /// </summary>
    public class ProxiFyreService
    {
        private const string DnsHijackEnvVar = "PROXIFYRE_DNS_HIJACK";
        private const string FakeIpEnabledEnvVar = "PROXIFYRE_FAKEIP_ENABLED";
        private const string FakeIpRangesEnvVar = "PROXIFYRE_FAKEIP_RANGES";

        /// <summary>
        /// NLog logger instance for logging service events.
        /// </summary>
        private static readonly Logger LoggerInstance = LogManager.GetCurrentClassLogger();

        /// <summary>
        /// The current log level for the service.
        /// </summary>
        private static LogLevel _logLevel;

        /// <summary>
        /// The Socksifier instance used to manage SOCKS5 proxies.
        /// </summary>
        private Socksifier.Socksifier _socksify;

        /// <summary>
        /// Starts the ProxiFyre service, loads configuration, and initializes proxies.
        /// </summary>
        public void Start()
        {
            // Get the current executable path
            var executablePath = Assembly.GetExecutingAssembly().Location;
            var directoryPath = Path.GetDirectoryName(executablePath);

            // Form the path to app-config.json
            var configFilePath = Path.Combine(directoryPath ?? string.Empty, "app-config.json");

            // Form the path to NLog.config
            var logConfigFilePath = Path.Combine(directoryPath ?? string.Empty, "NLog.config");

            // Load the configuration from JSON
            var serviceSettings = JsonConvert.DeserializeObject<ProxiFyreSettings>(File.ReadAllText(configFilePath));

            LogManager.Configuration = new XmlLoggingConfiguration(logConfigFilePath);

            // Handle the global log level from the configuration
            _logLevel = Enum.TryParse<LogLevel>(serviceSettings.LogLevel, true, out var globalLogLevel)
                ? globalLogLevel
                : LogLevel.Info;

            ConfigureDnsHijackAndFakeIp(serviceSettings);

            // Get an instance of the Socksifier
            _socksify = Socksifier.Socksifier.GetInstance(_logLevel);

            // Attach the LogPrinter method to the LogEvent event
            _socksify.LogEvent += LogPrinter;

            // Set the limit for logging and the interval between logs
            _socksify.LogLimit = 100;
            _socksify.LogEventInterval = 1000;

            // Configure LAN bypass if enabled
            if (serviceSettings.BypassLan)
            {
                _socksify.SetBypassLan();
                if (_logLevel >= LogLevel.Info)
                    LoggerInstance.Info("LAN bypass enabled - local network traffic will not be proxied.");
            }

            foreach (var appSettings in serviceSettings.Proxies)
            {
                // Warn if HTTP proxy is configured with UDP (HTTP CONNECT only supports TCP)
                if (appSettings.ProxyTypeParse == ProxyType.HTTP && appSettings.SupportedProtocols.Contains("UDP"))
                    LoggerInstance.Warn(
                        $"HTTP CONNECT proxy {appSettings.ProxyEndpoint} does not support UDP. UDP protocol will be ignored.");

                // Add the proxy based on its type
                var proxy = _socksify.AddProxy(
                    appSettings.ProxyEndpoint, appSettings.Username,
                    appSettings.Password, appSettings.ProxyTypeParse,
                    appSettings.SupportedProtocolsParse,
                    true);

                foreach (var appName in appSettings.AppNames)
                    // Associate the defined application names to the proxies
                    if (proxy.ToInt64() != -1 && _socksify.AssociateProcessNameToProxy(appName, proxy) && _logLevel >= LogLevel.Info)
                        LoggerInstance.Info(
                            $"Successfully associated {appName} to {appSettings.ProxyEndpoint} {appSettings.ProxyTypeString} proxy with protocols {string.Join(", ", appSettings.SupportedProtocols)}!");
            }

            foreach (var excludedEntry in serviceSettings.ExcludedList)
            {
                // Add the relevant entries dynamically to the excluded list
                if (_socksify.ExcludeProcessName(excludedEntry)) {
                    LoggerInstance.Info($"Successfully excluded {excludedEntry} from being proxied.");
                } else {
                    LoggerInstance.Warn($"Failed to exclude {excludedEntry} from being proxied.");
                }
            }

            _socksify.Start();

            // Inform user that the application is running
            if (_logLevel >= LogLevel.Info)
                LoggerInstance.Info("ProxiFyre Service is running...");
        }

        /// <summary>
        /// Stops the ProxiFyre service and disposes of resources.
        /// </summary>
        public void Stop()
        {
            // Dispose of the Socksifier before exiting
            _socksify.Dispose();
            if (_logLevel >= LogLevel.Info)
                LoggerInstance.Info("ProxiFyre Service has stopped.");
            LogManager.Shutdown();
        }

        /// <summary>
        /// Handles logging events from the Socksifier and logs them using NLog.
        /// </summary>
        /// <param name="sender">The event sender.</param>
        /// <param name="e">The log event arguments.</param>
        private static void LogPrinter(object sender, LogEventArgs e)
        {
            // Loop through each log entry and log it using NLog
            foreach (var entry in e.Log.Where(entry => entry != null))
            {
                // Format log entry with ISO 8601 timestamp, event, description, and data.
                //var logMessage =
                //    $"{DateTimeOffset.FromUnixTimeMilliseconds(entry.TimeStamp):u} | Event: {entry.Event} | Description: {entry.Description ?? string.Empty} | Data: {entry.Data}";
                LoggerInstance.Info(entry.Description?.Replace("\n", "").Replace("\r", ""));
            }
        }

        /// <summary>
        /// Configures DNS hijack and fake IP settings for the unmanaged router.
        /// </summary>
        /// <param name="serviceSettings">The parsed service settings.</param>
        private static void ConfigureDnsHijackAndFakeIp(ProxiFyreSettings serviceSettings)
        {
            var dnsHijackEnabled = serviceSettings.Dns?.Hijack == true;
            var fakeIpEnabled = serviceSettings.FakeIp?.Enabled == true;
            var fakeIpRanges = (serviceSettings.FakeIp?.Ranges ?? new List<string>())
                .Where(range => !string.IsNullOrWhiteSpace(range))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (fakeIpEnabled && fakeIpRanges.Count == 0)
                fakeIpRanges.Add("198.18.0.0/15");

            Environment.SetEnvironmentVariable(
                DnsHijackEnvVar,
                dnsHijackEnabled ? "1" : null,
                EnvironmentVariableTarget.Process);
            Environment.SetEnvironmentVariable(
                FakeIpEnabledEnvVar,
                fakeIpEnabled ? "1" : null,
                EnvironmentVariableTarget.Process);
            Environment.SetEnvironmentVariable(
                FakeIpRangesEnvVar,
                fakeIpRanges.Count > 0 ? string.Join(";", fakeIpRanges) : null,
                EnvironmentVariableTarget.Process);

            if (dnsHijackEnabled && _logLevel >= LogLevel.Info)
                LoggerInstance.Info("DNS hijack is enabled.");

            if (fakeIpEnabled && _logLevel >= LogLevel.Info)
                LoggerInstance.Info($"FakeIP is enabled with ranges: {string.Join(", ", fakeIpRanges)}");
        }

        //{
        //    "logLevel": "Warning",
        //    "proxies": [
        //        {
        //            "appNames": ["chrome", "chrome_canary"],
        //            "socks5ProxyEndpoint": "158.101.205.51:1080",
        //            "username": "username1",
        //            "password": "password1",
        //            "supportedProtocols": ["TCP", "UDP"]
        //        },
        //        {
        //            "appNames": ["firefox", "firefox_dev"],
        //            "proxyEndpoint": "159.101.205.52:1080",
        //            "proxyType": "socks5h",
        //            "username": "username2",
        //            "password": "password2",
        //            "supportedProtocols": ["TCP"]
        //        },
        //        {
        //            "appNames": ["curl"],
        //            "proxyEndpoint": "10.0.0.1:8080",
        //            "proxyType": "http",
        //            "username": "username3",
        //            "password": "password3",
        //            "supportedProtocols": ["TCP"]
        //        }
        //    ],
        //    "excludes": [
        //        "notepad.exe",
        //        "calc.exe",
        //        "C:\\Windows\\System32\\svchost.exe",
        //        "Windows\\System32\\",
        //        "antivirus"
        //    ]
        //}

        /// <summary>
        /// Represents the root configuration settings for ProxiFyre.
        /// </summary>
        private class ProxiFyreSettings
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="ProxiFyreSettings"/> class.
            /// </summary>
            /// <param name="logLevel">The log level as a string.</param>
            /// <param name="proxies">The list of proxy application settings.</param>
            /// <param name="excludedList">The list of process names or paths to exclude from proxying.</param>
            /// <param name="bypassLan">Whether to bypass LAN traffic.</param>
            public ProxiFyreSettings(string logLevel, List<AppSettings> proxies, List<string> excludedList = null,
                bool bypassLan = false, DnsSettings dns = null, FakeIpSettings fakeIp = null)
            {
                LogLevel = logLevel;
                Proxies = proxies;
                ExcludedList = excludedList ?? new List<string>();
                BypassLan = bypassLan;
                Dns = dns ?? new DnsSettings();
                FakeIp = fakeIp ?? new FakeIpSettings();
            }

            /// <summary>
            /// Gets the log level for the service.
            /// </summary>
            public string LogLevel { get; }

            /// <summary>
            /// Gets the list of proxy application settings.
            /// </summary>
            public List<AppSettings> Proxies { get; }

            /// <summary>
            /// Gets the list of app names to exclude.
            /// </summary>
            [JsonProperty("excludes", NullValueHandling = NullValueHandling.Ignore)]
            public List<string> ExcludedList { get; }

            /// <summary>
            /// Gets a value indicating whether LAN traffic should bypass the proxy.
            /// </summary>
            [JsonProperty("bypassLan", NullValueHandling = NullValueHandling.Ignore)]
            public bool BypassLan { get; }

            /// <summary>
            /// Gets DNS hijack settings.
            /// </summary>
            [JsonProperty("dns", NullValueHandling = NullValueHandling.Ignore)]
            public DnsSettings Dns { get; }

            /// <summary>
            /// Gets fake IP settings.
            /// </summary>
            [JsonProperty("fakeip", NullValueHandling = NullValueHandling.Ignore)]
            public FakeIpSettings FakeIp { get; }
        }

        /// <summary>
        /// Represents DNS hijack settings.
        /// </summary>
        private class DnsSettings
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="DnsSettings"/> class.
            /// </summary>
            /// <param name="hijack">Whether DNS hijack is enabled.</param>
            public DnsSettings(bool hijack = false)
            {
                Hijack = hijack;
            }

            /// <summary>
            /// Gets a value indicating whether DNS hijack is enabled.
            /// </summary>
            [JsonProperty("hijack", NullValueHandling = NullValueHandling.Ignore)]
            public bool Hijack { get; }
        }

        /// <summary>
        /// Represents fake IP settings.
        /// </summary>
        private class FakeIpSettings
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="FakeIpSettings"/> class.
            /// </summary>
            /// <param name="enabled">Whether fake IP is enabled.</param>
            /// <param name="ranges">The fake IP CIDR ranges.</param>
            public FakeIpSettings(bool enabled = false, List<string> ranges = null)
            {
                Enabled = enabled;
                Ranges = ranges ?? new List<string>();
            }

            /// <summary>
            /// Gets a value indicating whether fake IP is enabled.
            /// </summary>
            [JsonProperty("enabled", NullValueHandling = NullValueHandling.Ignore)]
            public bool Enabled { get; }

            /// <summary>
            /// Gets the fake IP CIDR ranges.
            /// </summary>
            [JsonProperty("ranges", NullValueHandling = NullValueHandling.Ignore)]
            public List<string> Ranges { get; }
        }

        /// <summary>
        /// Represents the settings for a single proxy and its associated applications.
        /// </summary>
        internal class AppSettings
        {
            /// <summary>
            /// Initializes a new instance of the <see cref="AppSettings"/> class.
            /// </summary>
            /// <param name="appNames">List of application names to associate with the proxy.</param>
            /// <param name="socks5ProxyEndpoint">SOCKS5 proxy endpoint address (legacy).</param>
            /// <param name="proxyEndpoint">Proxy endpoint address (new format).</param>
            /// <param name="proxyType">Proxy type: socks5, socks5h, or http.</param>
            /// <param name="username">Username for proxy authentication.</param>
            /// <param name="password">Password for proxy authentication.</param>
            /// <param name="supportedProtocols">List of supported protocols (e.g., TCP, UDP).</param>
            public AppSettings(List<string> appNames, string socks5ProxyEndpoint, string proxyEndpoint,
                string proxyType, string username, string password, List<string> supportedProtocols)
            {
                AppNames = appNames;
                Socks5ProxyEndpoint = socks5ProxyEndpoint;
                ProxyEndpointSetting = proxyEndpoint;
                ProxyTypeSetting = proxyType;
                Username = username;
                Password = password;
                SupportedProtocols = supportedProtocols ?? new List<string>();
            }

            /// <summary>
            /// Gets or sets the list of application names to associate with the proxy.
            /// </summary>
            public List<string> AppNames { get; set; }

            /// <summary>
            /// Gets the SOCKS5 proxy endpoint address (legacy, kept for backward compatibility).
            /// </summary>
            public string Socks5ProxyEndpoint { get; }

            /// <summary>
            /// Gets the proxy endpoint address (new format, takes precedence over Socks5ProxyEndpoint).
            /// </summary>
            [JsonProperty("proxyEndpoint", NullValueHandling = NullValueHandling.Ignore)]
            public string ProxyEndpointSetting { get; }

            /// <summary>
            /// Gets the proxy type string from configuration. Defaults to "socks5".
            /// Valid values: "socks5", "socks5h", "http".
            /// </summary>
            [JsonProperty("proxyType", NullValueHandling = NullValueHandling.Ignore)]
            public string ProxyTypeSetting { get; }

            /// <summary>
            /// Gets the effective proxy endpoint, preferring proxyEndpoint over socks5ProxyEndpoint.
            /// </summary>
            public string ProxyEndpoint => !string.IsNullOrEmpty(ProxyEndpointSetting)
                ? ProxyEndpointSetting
                : Socks5ProxyEndpoint;

            /// <summary>
            /// Gets the proxy type string for display purposes.
            /// </summary>
            public string ProxyTypeString => string.IsNullOrEmpty(ProxyTypeSetting) ? "socks5" : ProxyTypeSetting.ToLowerInvariant();

            /// <summary>
            /// Gets the username for proxy authentication.
            /// </summary>
            public string Username { get; }

            /// <summary>
            /// Gets the password for proxy authentication.
            /// </summary>
            public string Password { get; }

            /// <summary>
            /// Gets the list of supported protocols (e.g., TCP, UDP).
            /// </summary>
            public List<string> SupportedProtocols { get; }

            /// <summary>
            /// Gets the proxy type as an enum value.
            /// </summary>
            public ProxyType ProxyTypeParse
            {
                get
                {
                    switch (ProxyTypeString)
                    {
                        case "socks5h":
                            return ProxyType.SOCKS5H;
                        case "http":
                            return ProxyType.HTTP;
                        case "socks5":
                        default:
                            return ProxyType.SOCKS5;
                    }
                }
            }

            /// <summary>
            /// Gets the supported protocols as an enum value.
            /// </summary>
            public SupportedProtocolsEnum SupportedProtocolsParse
            {
                get
                {
                    if (SupportedProtocols.Count == 0 ||
                        (SupportedProtocols.Contains("TCP") && SupportedProtocols.Contains("UDP")))
                        return SupportedProtocolsEnum.BOTH;
                    if (SupportedProtocols.Contains("TCP"))
                        return SupportedProtocolsEnum.TCP;
                    return SupportedProtocols.Contains("UDP")
                        ? SupportedProtocolsEnum.UDP
                        : SupportedProtocolsEnum.BOTH;
                }
            }
        }
    }

    /// <summary>
    /// Entry point for the ProxiFyre service application.
    /// </summary>
    internal class Program
    {
        /// <summary>
        /// Main method. Configures and runs the ProxiFyre service using Topshelf.
        /// </summary>
        private static void Main()
        {
            HostFactory.Run(x =>
            {
                x.Service<ProxiFyreService>(s =>
                {
                    s.ConstructUsing(name => new ProxiFyreService());
                    s.WhenStarted(tc => tc.Start());
                    s.WhenStopped(tc => tc.Stop());
                });

                x.RunAsLocalSystem();

                x.SetDescription("ProxiFyre - SOCKS5 Proxifyre Service");
                x.SetDisplayName("ProxiFyre Service");
                x.SetServiceName("ProxiFyreService");
            });
        }
    }
}
