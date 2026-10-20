using System;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.Loader;
using System.Text;

[assembly: System.Runtime.Versioning.SupportedOSPlatform("linux")]
[assembly: System.Runtime.Versioning.SupportedOSPlatform("windows")]

namespace LyFlow.Rasp
{
    public static class LyRaspBridge
    {
        private static readonly string BridgeUrl = Environment.GetEnvironmentVariable("LY_RASP_BRIDGE") ?? "http://127.0.0.1:17891/v1/rasp/events";
        private static readonly string AppName = Environment.GetEnvironmentVariable("LY_RASP_APP") ?? "dotnet-app";
        private static readonly string Token = Environment.GetEnvironmentVariable("LY_RASP_TOKEN") ?? "";
        private static readonly string AgentId = Environment.GetEnvironmentVariable("LY_RASP_AGENT_ID") ?? "g5-real-agent";

        public static void SendEvent(string hookType, string[] fields)
        {
            try
            {
                var payload = new StringBuilder("{\"event_type\":\"rasp.dotnet.");
                payload.Append(Escape(hookType));
                payload.Append("\",\"hook_type\":\"");
                payload.Append(Escape(hookType));
                payload.Append("\",\"language\":\"dotnet");
                payload.Append("\",\"application\":\"");
                payload.Append(Escape(AppName));
                payload.Append("\",\"occurred_at\":\"");
                payload.Append(DateTime.UtcNow.ToString("o"));
                payload.Append('"');
                foreach (var field in fields)
                {
                    var parts = field.Split('=', 2);
                    if (parts.Length == 2)
                    {
                        payload.Append(",\"");
                        payload.Append(Escape(parts[0]));
                        payload.Append("\":\"");
                        payload.Append(Escape(parts[1]));
                        payload.Append('"');
                    }
                }
                payload.Append('}');
                using var wc = new WebClient();
                wc.Headers[HttpRequestHeader.ContentType] = "application/json";
                wc.Headers["X-Lyflow-Agent-ID"] = AgentId;
                if (!string.IsNullOrEmpty(Token))
                    wc.Headers["X-Ly-RASP-Token"] = Token;
                wc.UploadString(BridgeUrl, payload.ToString());
            }
            catch { }
        }

        private static string Escape(string s) => (s ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
    }

    public class LyRaspHook
    {
        public static void Initialize()
        {
            AppDomain.CurrentDomain.ProcessExit += (s, e) => { };
            AppDomain.CurrentDomain.UnhandledException += (s, e) => { };
        }

        public static Process OnProcessStart(ProcessStartInfo startInfo)
        {
            LyRaspBridge.SendEvent("command_exec", new[] { $"command={startInfo.FileName} {startInfo.Arguments}" });
            return Process.Start(startInfo);
        }

        public static int OnSqlCommandExecuteNonQuery(SqlCommand cmd)
        {
            LyRaspBridge.SendEvent("sql", new[] { $"query={cmd.CommandText}", $"connection={cmd.Connection?.ConnectionString?.Split(';')[0] ?? "unknown"}" });
            return cmd.ExecuteNonQuery();
        }

        public static SqlDataReader OnSqlCommandExecuteReader(SqlCommand cmd)
        {
            LyRaspBridge.SendEvent("sql", new[] { $"query={cmd.CommandText}" });
            return cmd.ExecuteReader();
        }

        public static object OnSqlCommandExecuteScalar(SqlCommand cmd)
        {
            LyRaspBridge.SendEvent("sql", new[] { $"query={cmd.CommandText}" });
            return cmd.ExecuteScalar();
        }

        public static string OnFileReadAllText(string path)
        {
            LyRaspBridge.SendEvent("file_read", new[] { $"path={path}" });
            return File.ReadAllText(path);
        }

        public static byte[] OnFileReadAllBytes(string path)
        {
            LyRaspBridge.SendEvent("file_read", new[] { $"path={path}" });
            return File.ReadAllBytes(path);
        }

        public static HttpWebResponse OnHttpWebRequest(HttpWebRequest request)
        {
            LyRaspBridge.SendEvent("ssrf", new[] { $"url={request.RequestUri}" });
            return (HttpWebResponse)request.GetResponse();
        }
    }
}
