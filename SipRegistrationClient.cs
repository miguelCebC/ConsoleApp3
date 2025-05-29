using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SIPSorcery.SIP;
using SIPSorcery.SIP.App;

public class SipRegistrationClient
{
    private readonly ILogger<SipRegistrationClient> _logger;
    private readonly SipConfig _config;

    private SIPTransport? _sipTransport;
    private SIPEndPoint? _registrarEndPoint;
    private SIPURI? _registrarUri;
    private SIPURI? _contactUri;
    private string? _localIp;
    private string _authorizationHeader = "";
    private int _cseq = 1;
    private int _authAttempts = 0;
    private Timer? _reRegistrationTimer;
    private bool _isRegistered = false;
    private readonly CancellationTokenSource _cancellationTokenSource = new();
    private string _callId = "";
    private string _fromTag = "";

    private const int MAX_AUTH_ATTEMPTS = 3;
    private const int REREGISTRATION_BUFFER_SECONDS = 50;

    public SipRegistrationClient(SipConfig config, ILogger<SipRegistrationClient> logger)
    {
        _config = config ?? throw new ArgumentNullException(nameof(config));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _callId = Guid.NewGuid().ToString();
        _fromTag = Guid.NewGuid().ToString().Substring(0, 8);
    }

    public async Task<bool> StartAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            _logger.LogInformation("Iniciando cliente SIP...");

            if (!await InitializeSipTransportAsync())
                return false;

            _logger.LogInformation("Enviando REGISTER inicial...");
            await SendRegisterAsync();

            var reRegistrationInterval = TimeSpan.FromSeconds(_config.Expiry - REREGISTRATION_BUFFER_SECONDS);
            _reRegistrationTimer = new Timer(async _ => await ReRegisterAsync(), null,
                reRegistrationInterval, reRegistrationInterval);

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al iniciar cliente SIP");
            return false;
        }
    }

    private async Task<bool> InitializeSipTransportAsync()
    {
        try
        {
            _sipTransport = new SIPTransport();
            _localIp = GetLocalIPAddress();

            var sipChannel = new SIPUDPChannel(new IPEndPoint(IPAddress.Parse(_localIp), 0));
            _sipTransport.AddSIPChannel(sipChannel);

            var registrarIPs = await Dns.GetHostAddressesAsync(_config.Domain);
            if (registrarIPs.Length == 0)
            {
                _logger.LogError("No se pudo resolver la dirección del registrar: {Domain}", _config.Domain);
                return false;
            }

            var registrarIP = registrarIPs[0];
            _registrarEndPoint = new SIPEndPoint(SIPProtocolsEnum.udp, registrarIP, _config.Port);
            _registrarUri = SIPURI.ParseSIPURI($"sip:{_config.Domain}");
            _contactUri = SIPURI.ParseSIPURI($"sip:{_config.Username}@{_localIp}");

            _sipTransport.SIPTransportResponseReceived += OnSipResponseReceivedAsync;

            _logger.LogInformation("Transport SIP inicializado. IP local: {LocalIp}, Registrar: {RegistrarIp}:{Port}",
                _localIp, registrarIP, _config.Port);

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al inicializar transport SIP");
            return false;
        }
    }

    private async Task SendRegisterAsync()
    {
        try
        {
            var currentCSeq = Interlocked.Increment(ref _cseq);

            var fromUri = SIPURI.ParseSIPURI($"sip:{_config.Username}@{_config.Domain}");
            var toUri = SIPURI.ParseSIPURI($"sip:{_config.Username}@{_config.Domain}");

            var toHeader = new SIPToHeader(_config.Username, toUri, null);
            var fromHeader = new SIPFromHeader(_config.Username, fromUri, _fromTag);

            var registerRequest = SIPRequest.GetRequest(SIPMethodsEnum.REGISTER, _registrarUri, toHeader, fromHeader);

            registerRequest.Header.CallId = _callId;
            registerRequest.Header.Contact = new List<SIPContactHeader> { new SIPContactHeader(null, _contactUri) };
            registerRequest.Header.Expires = _config.Expiry;
            registerRequest.Header.MaxForwards = 70;
            registerRequest.Header.CSeq = currentCSeq;
            registerRequest.Header.UserAgent = "SIPSorcery-Client/1.0";

            if (!string.IsNullOrEmpty(_authorizationHeader))
            {
                registerRequest.Header.UnknownHeaders.Add("Authorization: " + _authorizationHeader);
                _logger.LogDebug("Enviando REGISTER con autenticación");
            }
            else
            {
                _logger.LogDebug("Enviando REGISTER inicial sin autenticación");
            }

            _logger.LogTrace(">> Enviando REGISTER:\n{Request}", registerRequest.ToString());

            if (_sipTransport != null && _registrarEndPoint != null)
            {
                await _sipTransport.SendRequestAsync(_registrarEndPoint, registerRequest);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al enviar REGISTER");
        }
    }

    private async Task OnSipResponseReceivedAsync(SIPEndPoint localEP, SIPEndPoint remoteEP, SIPResponse sipResponse)
    {
        try
        {
            _logger.LogInformation("<< Recibido {StatusCode} {ReasonPhrase}", sipResponse.StatusCode, sipResponse.ReasonPhrase);
            _logger.LogTrace("Respuesta SIP completa:\n{Response}", sipResponse.ToString());

            switch (sipResponse.StatusCode)
            {
                case 401:
                    await HandleUnauthorizedResponseAsync(sipResponse);
                    break;

                case >= 200 and < 300:
                    await HandleSuccessResponseAsync(sipResponse);
                    break;

                case >= 400:
                    _logger.LogWarning("Error SIP: {StatusCode} {ReasonPhrase}", sipResponse.StatusCode, sipResponse.ReasonPhrase);
                    break;

                default:
                    _logger.LogInformation("Estado SIP: {StatusCode} {ReasonPhrase}", sipResponse.StatusCode, sipResponse.ReasonPhrase);
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al procesar respuesta SIP");
        }
    }

    private async Task HandleUnauthorizedResponseAsync(SIPResponse sipResponse)
    {
        if (_authAttempts >= MAX_AUTH_ATTEMPTS)
        {
            _logger.LogError("❌ Máximo número de intentos de autenticación alcanzado ({MaxAttempts})", MAX_AUTH_ATTEMPTS);
            return;
        }

        var wwwAuthHeader = ExtractWwwAuthenticateHeader(sipResponse);

        if (string.IsNullOrEmpty(wwwAuthHeader))
        {
            _logger.LogError("No se encontró el header WWW-Authenticate en respuesta 401");
            return;
        }

        _logger.LogDebug("WWW-Authenticate header recibido: {AuthHeader}", wwwAuthHeader);

        var newNonce = ExtractNonceFromAuthHeader(wwwAuthHeader);
        var oldNonce = ExtractNonceFromAuthHeader(_authorizationHeader);

        if (newNonce != oldNonce || string.IsNullOrEmpty(_authorizationHeader))
        {
            _logger.LogInformation("Construyendo nueva autenticación...");
            _authorizationHeader = BuildAuthorizationHeader(wwwAuthHeader);
            _authAttempts++;

            _logger.LogDebug("Authorization header construido (intento {Attempt}/{MaxAttempts}): {AuthHeader}",
                _authAttempts, MAX_AUTH_ATTEMPTS, _authorizationHeader);

            await Task.Delay(1000, _cancellationTokenSource.Token);
            await SendRegisterAsync();
        }
        else
        {
            _logger.LogError("❌ Falló el registro con autenticación. Credenciales inválidas.");
            _authAttempts = MAX_AUTH_ATTEMPTS;
        }
    }

    private async Task HandleSuccessResponseAsync(SIPResponse sipResponse)
    {
        _logger.LogInformation("✅ Registro SIP exitoso!");
        _isRegistered = true;
        _authAttempts = 0;

        if (sipResponse.Header.Expires > 0)
        {
            var actualExpiry = sipResponse.Header.Expires;
            _logger.LogInformation("Registro válido por {Expiry} segundos", actualExpiry);

            var reRegistrationInterval = TimeSpan.FromSeconds(Math.Max(actualExpiry - REREGISTRATION_BUFFER_SECONDS, 60));
            _reRegistrationTimer?.Change(reRegistrationInterval, reRegistrationInterval);
        }

        await Task.CompletedTask;
    }

    private async Task ReRegisterAsync()
    {
        if (_cancellationTokenSource.Token.IsCancellationRequested)
            return;

        _logger.LogInformation("🔄 Realizando re-registro automático...");
        await SendRegisterAsync();
    }

    private string? ExtractWwwAuthenticateHeader(SIPResponse sipResponse)
    {
        foreach (var unknownHeader in sipResponse.Header.UnknownHeaders)
        {
            if (unknownHeader.StartsWith("WWW-Authenticate:", StringComparison.OrdinalIgnoreCase))
            {
                return unknownHeader.Substring("WWW-Authenticate:".Length).Trim();
            }
        }

        var lines = sipResponse.ToString().Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var line in lines)
        {
            if (line.StartsWith("WWW-Authenticate:", StringComparison.OrdinalIgnoreCase))
            {
                return line.Substring("WWW-Authenticate:".Length).Trim();
            }
        }

        return null;
    }

    private static string? ExtractNonceFromAuthHeader(string? header)
    {
        if (string.IsNullOrEmpty(header))
            return null;

        try
        {
            var parameters = ParseDigestParameters(header);
            return parameters.TryGetValue("nonce", out var nonce) ? nonce : null;
        }
        catch
        {
            return null;
        }
    }

    private static Dictionary<string, string> ParseDigestParameters(string header)
    {
        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        string cleanHeader = header.StartsWith("Digest ", StringComparison.OrdinalIgnoreCase)
            ? header.Substring(7).Trim()
            : header.Trim();

        var inQuotes = false;
        var currentParam = new StringBuilder();
        var currentKey = "";
        var currentValue = new StringBuilder();
        var parsingValue = false;

        for (int i = 0; i < cleanHeader.Length; i++)
        {
            char c = cleanHeader[i];

            if (c == '"')
            {
                inQuotes = !inQuotes;
                continue;
            }

            if (!inQuotes && c == '=')
            {
                currentKey = currentParam.ToString().Trim();
                currentParam.Clear();
                parsingValue = true;
                continue;
            }

            if (!inQuotes && c == ',')
            {
                if (!string.IsNullOrEmpty(currentKey))
                {
                    parameters[currentKey] = currentValue.ToString().Trim();
                    currentKey = "";
                    currentValue.Clear();
                    parsingValue = false;
                }
                continue;
            }

            if (parsingValue)
            {
                currentValue.Append(c);
            }
            else
            {
                currentParam.Append(c);
            }
        }

        if (!string.IsNullOrEmpty(currentKey))
        {
            parameters[currentKey] = currentValue.ToString().Trim();
        }

        return parameters;
    }

    private string BuildAuthorizationHeader(string wwwAuthenticateHeader)
    {
        try
        {
            var parameters = ParseDigestParameters(wwwAuthenticateHeader);

            string realm = parameters.TryGetValue("realm", out var r) ? r : "";
            string nonce = parameters.TryGetValue("nonce", out var n) ? n : "";
            string algorithm = parameters.TryGetValue("algorithm", out var a) ? a : "MD5";
            string uri = $"sip:{_config.Domain}";
            string method = "REGISTER";

            _logger.LogDebug("Parámetros digest: realm='{Realm}', nonce='{Nonce}', algorithm='{Algorithm}'",
                realm, nonce, algorithm);

            string ha1 = CalculateMD5Hash($"{_config.Username}:{realm}:{_config.Password}");
            string ha2 = CalculateMD5Hash($"{method}:{uri}");
            string response = CalculateMD5Hash($"{ha1}:{nonce}:{ha2}");

            _logger.LogDebug("HA1: {Ha1}", ha1);
            _logger.LogDebug("HA2: {Ha2}", ha2);
            _logger.LogDebug("Response: {Response}", response);

            var authHeader = $"Digest username=\"{_config.Username}\", " +
                           $"realm=\"{realm}\", " +
                           $"nonce=\"{nonce}\", " +
                           $"uri=\"{uri}\", " +
                           $"response=\"{response}\"" +
                           (algorithm != "MD5" ? $", algorithm=\"{algorithm}\"" : "");

            _logger.LogDebug("Authorization header final: {AuthHeader}", authHeader);
            return authHeader;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error al construir Authorization header");
            return "";
        }
    }

    private static string CalculateMD5Hash(string input)
    {
        using (var md5 = MD5.Create())
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            byte[] hashBytes = md5.ComputeHash(inputBytes);
            return Convert.ToHexString(hashBytes).ToLowerInvariant();
        }
    }

    private static string GetLocalIPAddress()
    {
        try
        {
            foreach (var ip in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                {
                    return ip.ToString();
                }
            }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("No se pudo obtener dirección IP local", ex);
        }

        throw new InvalidOperationException("No se encontró una dirección IPv4 válida.");
    }

    public async Task StopAsync()
    {
        _logger.LogInformation("Deteniendo cliente SIP...");

        _cancellationTokenSource.Cancel();
        _reRegistrationTimer?.Dispose();

        if (_isRegistered && _sipTransport != null)
        {
            try
            {
                _logger.LogInformation("Enviando unregister...");
                var fromUri = SIPURI.ParseSIPURI($"sip:{_config.Username}@{_config.Domain}");
                var toUri = SIPURI.ParseSIPURI($"sip:{_config.Username}@{_config.Domain}");

                var toHeader = new SIPToHeader(_config.Username, toUri, null);
                var fromHeader = new SIPFromHeader(_config.Username, fromUri, _fromTag);

                var unregisterRequest = SIPRequest.GetRequest(SIPMethodsEnum.REGISTER, _registrarUri, toHeader, fromHeader);
                unregisterRequest.Header.CallId = _callId;
                unregisterRequest.Header.Contact = new List<SIPContactHeader> { new SIPContactHeader(null, _contactUri) };
                unregisterRequest.Header.Expires = 0;
                unregisterRequest.Header.MaxForwards = 70;
                unregisterRequest.Header.CSeq = Interlocked.Increment(ref _cseq);
                unregisterRequest.Header.UserAgent = "SIPSorcery-Client/1.0";

                if (!string.IsNullOrEmpty(_authorizationHeader))
                {
                    unregisterRequest.Header.UnknownHeaders.Add("Authorization: " + _authorizationHeader);
                }

                _logger.LogTrace(">> Enviando unregister:\n{Request}", unregisterRequest.ToString());

                await _sipTransport.SendRequestAsync(_registrarEndPoint, unregisterRequest);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error al enviar unregister");
            }
        }

        _sipTransport?.Shutdown();
        _logger.LogInformation("Cliente SIP detenido.");
    }
}
