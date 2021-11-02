using Ludicrypt;
using Ludicrypt.Backend.Interface;
using Ludicrypt.Services;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using System.Reflection;

//var socketPath = Path.Combine(Path.GetTempPath(), "ludicrypt.sock");

var builder = WebApplication.CreateBuilder(args);

if (OperatingSystem.IsWindows())
{
    builder.Host.UseWindowsService();
}
else if (OperatingSystem.IsLinux())
{
    builder.Host.UseSystemd();
}

builder.WebHost.ConfigureKestrel(options =>
{
    if (OperatingSystem.IsMacOS())
    {
        // Setup an HTTP/2 endpoint without TLS on macOS only.
        //options.ListenLocalhost(5000, o => o.Protocols = HttpProtocols.Http2);
    }

    //if (File.Exists(socketPath))
    //{
    //    File.Delete(socketPath);
    //}

    // Swetup an HTTP/s UDS endpoint that isn't configured to use HTTPS
    //options.ListenUnixSocket(socketPath, listenOptions =>
    //{
    //    listenOptions.Protocols = HttpProtocols.Http2;
    //});
});

// Additional configuration is required to successfully run gRPC on macOS.
// For instructions on how to configure Kestrel and gRPC clients on macOS, visit https://go.microsoft.com/fwlink/?linkid=2099682

// Add services to the container.
builder.Services.AddGrpc();


//builder.Services.AddSingleton<ICryptoProvider>(provider);
builder.Services.AddSingleton<ICryptoProvider>(serviceProvider =>
{
    var providerType = LoadCryptoProvider(Environment.GetEnvironmentVariable("LUDICRYPT_BACKEND")!);

    //var logger = serviceProvider.GetRequiredService<ILogger>();
    //var loggerFactory = LoggerFactory.Create(logging =>
    //    {
    //        logging.AddDebug();
    //        logging.AddConsole();
    //        logging.AddFilter<DebugLoggerProvider>(null, LogLevel.Debug);
    //        logging.AddFilter<ConsoleLoggerProvider>(null, LogLevel.Debug);
    //    });

    if (Activator.CreateInstance(providerType) is ICryptoProvider result)
    {
        return result;
    }

    throw new Exception($"Type '{providerType.FullName}' does not implement a compatible constructor");
});

var app = builder.Build();

// Configure the HTTP request pipeline.
app.MapGrpcService<CryptoProviderService>();
app.MapGet("/", () => "Communication with gRPC endpoints must be made through a gRPC client. To learn how to create a client, visit: https://go.microsoft.com/fwlink/?linkid=2086909");

app.Run();

static Type LoadCryptoProvider(string path)
{
    var loadContext = new PluginLoadContext(path);
    var assembly = loadContext.LoadFromAssemblyName(new AssemblyName(Path.GetFileNameWithoutExtension(path)));

    foreach (Type type in assembly.GetTypes())
    {
        if (typeof(ICryptoProvider).IsAssignableFrom(type))
        {
            return type;
            //if (Activator.CreateInstance(type) is ICryptoProvider result)
            //{
            //    return result;
            //}
        }
    }

    throw new Exception($"Assembly '{path}' does not implement '{nameof(ICryptoProvider)}'");
}
