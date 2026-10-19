using System;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;

// .NET startup hook entry point. Attach with:
//   DOTNET_STARTUP_HOOKS=/opt/ly-agent/rasp/dotnet/LyRaspProfiler.dll dotnet app.dll
public static class StartupHook
{
    private static string bridgeToken = "";
    private static string bridgeAgentId = "";

    public static void Initialize()
    {
        LoadConfig();
        Emit("rasp.dotnet.lifecycle", "lifecycle", "LyFlow .NET RASP startup hook attached");
    }

    private static void LoadConfig()
    {
        try
        {
            var bridge = Environment.GetEnvironmentVariable("LY_RASP_BRIDGE")
                ?? "http://127.0.0.1:17891/v1/rasp/events";
            var token = Environment.GetEnvironmentVariable("LY_RASP_TOKEN") ?? "";
            var agent = Environment.GetEnvironmentVariable("LY_RASP_AGENT_ID") ?? "g5-real-agent";
            var request = (HttpWebRequest)WebRequest.Create(bridge.Replace("/events", "/config"));
            request.Method = "GET";
            request.Headers["X-Ly-RASP-Token"] = token;
            request.Headers["X-Lyflow-Agent-ID"] = agent;
            request.Timeout = 1000;
            using var response = (HttpWebResponse)request.GetResponse();
            using var reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8);
            using var document = JsonDocument.Parse(reader.ReadToEnd());
            if (document.RootElement.TryGetProperty("bridge_token", out var bridgeTokenValue))
                bridgeToken = bridgeTokenValue.GetString() ?? "";
            if (document.RootElement.TryGetProperty("agent_id", out var agentValue))
                bridgeAgentId = agentValue.GetString() ?? "";
        }
        catch
        {
        }
    }

    public static void EmitCommand(string command)
    {
        Emit("rasp.dotnet.command_exec", "command_exec", command ?? "");
    }

    public static void Emit(string eventType, string hookType, string evidence)
    {
        try
        {
            var bridge = Environment.GetEnvironmentVariable("LY_RASP_BRIDGE")
                ?? "http://127.0.0.1:17891/v1/rasp/events";
            var token = string.IsNullOrEmpty(bridgeToken)
                ? Environment.GetEnvironmentVariable("LY_RASP_TOKEN") ?? ""
                : bridgeToken;
            var agentId = string.IsNullOrEmpty(bridgeAgentId)
                ? Environment.GetEnvironmentVariable("LY_RASP_AGENT_ID") ?? "g5-real-agent"
                : bridgeAgentId;
            var application = Environment.GetEnvironmentVariable("LY_APP_NAME") ?? "dotnet-app";
            var body = "{"
                + "\"event_type\":\"" + Escape(eventType) + "\","
                + "\"hook_type\":\"" + Escape(hookType) + "\","
                + "\"language\":\"dotnet\","
                + "\"application\":\"" + Escape(application) + "\","
                + "\"command\":\"" + Escape(evidence) + "\","
                + "\"cmdline\":\"" + Escape(evidence) + "\","
                + "\"summary\":\"" + Escape(evidence) + "\","
                + "\"observed_at\":\"" + DateTime.UtcNow.ToString("o") + "\""
                + "}";
            var request = (HttpWebRequest)WebRequest.Create(bridge);
            request.Method = "POST";
            request.ContentType = "application/json";
            request.Headers["X-Ly-RASP-Token"] = token;
            request.Headers["X-Lyflow-Agent-ID"] = agentId;
            request.Timeout = 1000;
            var payload = Encoding.UTF8.GetBytes(body);
            request.ContentLength = payload.Length;
            using (var stream = request.GetRequestStream())
            {
                stream.Write(payload, 0, payload.Length);
            }
            using (var response = (HttpWebResponse)request.GetResponse())
            {
                response.Close();
            }
        }
        catch
        {
            // RASP telemetry must never break the host process.
        }
    }

    private static string Escape(string value)
    {
        return (value ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
    }
}
