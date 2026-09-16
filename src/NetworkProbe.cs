using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace FalconPreflight {
    public sealed class ProbeResult {
        public string Target, Route, Address, Stage, Error, Protocol, Subject, Issuer, Thumbprint, CertificateErrors;
        public string NotAfterUtc;
        public bool Success;
        public long ElapsedMs;
    }
    public static class NetworkProbe {
        private static void Await(Task task, int milliseconds) {
            if (!task.Wait(milliseconds)) throw new TimeoutException("Operation timed out.");
            task.GetAwaiter().GetResult();
        }
        public static IPAddress[] Resolve(string name, int milliseconds) {
            Task<IPAddress[]> task = Dns.GetHostAddressesAsync(name);
            Await(task, milliseconds);
            return task.Result;
        }
        public static Uri SystemProxy(string target, int milliseconds) {
            Task<Uri> task = Task.Run(() => {
                Uri destination = new Uri("https://" + target + "/");
                IWebProxy proxy = WebRequest.GetSystemWebProxy();
                if (proxy == null || proxy.IsBypassed(destination)) return (Uri)null;
                Uri route = proxy.GetProxy(destination);
                return route == destination ? null : route;
            });
            Await(task, milliseconds);
            return task.Result;
        }
        public static ProbeResult Test(string target, int port, IPAddress address, Uri proxy, int milliseconds, bool revocation) {
            ProbeResult result = new ProbeResult();
            result.Target = target;
            result.Route = proxy == null ? "Direct" : "http://" + proxy.Host + ":" + proxy.Port;
            result.Address = address.ToString();
            result.Stage = "TCP";
            Stopwatch watch = Stopwatch.StartNew();
            TcpClient client = new TcpClient(address.AddressFamily);
            SslStream tls = null;
            try {
                if (proxy != null && (proxy.Scheme != "http" || !String.IsNullOrEmpty(proxy.UserInfo)))
                    throw new NotSupportedException("Only an existing HTTP proxy without embedded credentials is supported.");
                Await(client.ConnectAsync(address, proxy == null ? port : proxy.Port), milliseconds);
                NetworkStream stream = client.GetStream();
                stream.ReadTimeout = milliseconds;
                stream.WriteTimeout = milliseconds;
                if (proxy != null) {
                    result.Stage = "ProxyCONNECT";
                    byte[] request = Encoding.ASCII.GetBytes("CONNECT " + target + ":" + port + " HTTP/1.1\r\nHost: " + target + ":" + port + "\r\n\r\n");
                    stream.Write(request, 0, request.Length);
                    List<byte> header = new List<byte>();
                    Stopwatch headerWatch = Stopwatch.StartNew();
                    while (header.Count < 16384) {
                        int remaining = milliseconds - (int)headerWatch.ElapsedMilliseconds;
                        if (remaining <= 0) throw new TimeoutException("Proxy CONNECT timed out.");
                        stream.ReadTimeout = remaining;
                        int value = stream.ReadByte();
                        if (value < 0) throw new IOException("Proxy closed the connection.");
                        header.Add((byte)value);
                        int n = header.Count;
                        if (n >= 4 && header[n-4] == 13 && header[n-3] == 10 && header[n-2] == 13 && header[n-1] == 10) break;
                    }
                    string response = Encoding.ASCII.GetString(header.ToArray());
                    if (!response.EndsWith("\r\n\r\n")) throw new IOException("Proxy response header too large.");
                    string first = response.Split('\r')[0];
                    string[] parts = first.Split(' ');
                    if (parts.Length < 2 || !parts[0].StartsWith("HTTP/") || parts[1] != "200")
                        throw new IOException("Proxy CONNECT rejected: " + first + ". No proxy credentials were sent.");
                }
                result.Stage = "TLS";
                tls = new SslStream(stream, false, (sender, certificate, chain, errors) => {
                    result.CertificateErrors = errors.ToString();
                    if (certificate != null) {
                        using (X509Certificate2 cert = new X509Certificate2(certificate)) {
                            result.Subject = cert.Subject;
                            result.Issuer = cert.Issuer;
                            result.Thumbprint = cert.Thumbprint;
                            result.NotAfterUtc = cert.NotAfter.ToUniversalTime().ToString("o");
                        }
                    }
                    if (chain != null) {
                        foreach (X509ChainStatus status in chain.ChainStatus)
                            result.CertificateErrors += "; " + status.Status + ": " + status.StatusInformation.Trim();
                    }
                    return errors == SslPolicyErrors.None;
                });
                // SNI and hostname verification use the FQDN even when connecting to an IP.
                Await(tls.AuthenticateAsClientAsync(target, new X509CertificateCollection(), SslProtocols.Tls12, revocation), milliseconds);
                result.Protocol = tls.SslProtocol.ToString();
                result.Success = true;
                result.Stage = "Complete";
            } catch (Exception exception) {
                while (exception.InnerException != null) exception = exception.InnerException;
                result.Error = exception.Message;
            } finally {
                if (tls != null) tls.Dispose();
                client.Close();
                result.ElapsedMs = watch.ElapsedMilliseconds;
            }
            return result;
        }
    }
}
