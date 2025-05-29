// File: Program.cs
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace SipClientApp
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var config = new SipConfig
            {
                Username = "512431-100",
                Password = "8mtcRms28U",
                Domain = "pbx.zadarma.com",
                Port = 5060,
                Expiry = 300
            };

            using var loggerFactory = LoggerFactory.Create(builder =>
                builder.AddConsole().SetMinimumLevel(LogLevel.Debug));

            var logger = loggerFactory.CreateLogger<SipRegistrationClient>();

            var sipClient = new SipRegistrationClient(config, logger);

            var cancellationTokenSource = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                cancellationTokenSource.Cancel();
            };

            try
            {
                if (await sipClient.StartAsync(cancellationTokenSource.Token))
                {
                    logger.LogInformation("Cliente SIP iniciado. Presiona Ctrl+C para salir");

                    try
                    {
                        await Task.Delay(Timeout.Infinite, cancellationTokenSource.Token);
                    }
                    catch (OperationCanceledException)
                    {
                        logger.LogInformation("Shutdown solicitado...");
                    }

                    await sipClient.StopAsync();
                }
                else
                {
                    logger.LogError("No se pudo iniciar el cliente SIP");
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error fatal en la aplicación");
            }

            logger.LogInformation("Aplicación terminada");
        }
    }
}
