using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
public sealed class PreflightTestServer : IDisposable {
    private TcpListener listener;
    private Task worker;
    public int Port;
    public PreflightTestServer(X509Certificate2 certificate, string mode) {
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        worker = Task.Run(() => {
            try {
                using (TcpClient client = listener.AcceptTcpClient()) {
                    NetworkStream stream = client.GetStream();
                    stream.ReadTimeout = 5000;
                    if (mode == "silent") { Thread.Sleep(1500); return; }
                    if (mode.StartsWith("proxy")) {
                        string header = "";
                        while (!header.EndsWith("\r\n\r\n") && header.Length < 16384) {
                            int b = stream.ReadByte();
                            if (b < 0) return;
                            header += (char)b;
                        }
                        string response = mode == "proxy407" ? "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n" : "HTTP/1.1 200 Connection Established\r\n\r\n";
                        byte[] bytes = Encoding.ASCII.GetBytes(response);
                        stream.Write(bytes, 0, bytes.Length);
                        if (mode == "proxy407") return;
                    }
                    using (SslStream tls = new SslStream(stream, false)) {
                        tls.AuthenticateAsServer(certificate, false, SslProtocols.Tls12, false);
                    }
                }
            } catch (Exception) { /* Client rejection is expected in negative tests. */ }
        });
    }
    public void Dispose() { listener.Stop(); worker.Wait(6000); }
}
