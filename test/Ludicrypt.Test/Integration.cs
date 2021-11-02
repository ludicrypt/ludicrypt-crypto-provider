using Grpc.Net.Client;
using System.IO;
using System.Net.Http;
using System.Net.Sockets;
using Xunit;

namespace Ludicrypt.Test
{
    public class Integration
    {
        //public static readonly string SocketPath = Path.Combine(Path.GetTempPath(), "ludicrypt.sock");

        [Fact]
        public void GetKey()
        {
            //using var channel = CreateChannel();
            using var channel = GrpcChannel.ForAddress("https://localhost:7191");
            var client = new CryptoProvider.CryptoProviderClient(channel);

            var response = client.GetKey(new GetKeyRequest { Name = "TestRSA" });
        }

        //public static GrpcChannel CreateChannel()
        //{
        //    var udsEndPoint = new UnixDomainSocketEndPoint(SocketPath);
        //    var connectionFactory = new UnixDomainSocketConnectionFactory(udsEndPoint);
        //    var socketsHttpHandler = new SocketsHttpHandler
        //    {
        //        ConnectCallback = connectionFactory.ConnectAsync
        //    };

        //    return GrpcChannel.ForAddress("http://localhost", new GrpcChannelOptions
        //    {
        //        HttpHandler = socketsHttpHandler
        //    });
        //}
    }
}