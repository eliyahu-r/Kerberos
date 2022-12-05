using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Util;

namespace KerberosServer
{
    class Server
    {
        private static String username;
        private static String password;
        const int PORT = 22222;


        static void Main(string[] args)
        {
            Console.WriteLine("Welcome client! Please insert your kerberos identity.");
            InitializeUser();
            ExecuteServer();
        }
        private static void InitializeUser()
        {
            Console.WriteLine("Username: ");
            username = Console.ReadLine();
            Console.WriteLine("Password: ");
            password = Console.ReadLine();
            password = StringHash.CalculateHash(password);
        }

        private static void ExecuteServer()
        {
            // Establish the local endpoint
            // for the socket. Dns.GetHostName
            // returns the name of the host
            // running the application.
            IPHostEntry ipHost = Dns.GetHostEntry(Dns.GetHostName());
            IPAddress ipAddr = ipHost.AddressList[0];
            IPEndPoint localEndPoint = new IPEndPoint(ipAddr, PORT);

            // Creation TCP/IP Socket using
            // Socket Class Constructor
            Socket listener = new Socket(ipAddr.AddressFamily,
                         SocketType.Stream, ProtocolType.Tcp);

            try
            {

                // Using Bind() method we associate a
                // network address to the Server Socket
                // All client that will connect to this
                // Server Socket must know this network
                // Address
                listener.Bind(localEndPoint);

                // Using Listen() method we create
                // the Client list that will want
                // to connect to Server
                listener.Listen(10);

                while (true)
                {
                    Console.WriteLine("Waiting connection ... ");

                    // Suspend while waiting for
                    // incoming connection Using
                    // Accept() method the server
                    // will accept connection of client
                    Socket clientSocket = listener.Accept();
                    Console.WriteLine("Connection found");

                    string data = null;
                    data = GetSocketMessage(clientSocket);
                    Console.WriteLine("Text received -> {0} ", data);
                    
                    try
                    {
                        data = StringCipher.Decrypt(data, password);
                        String[] values = data.Split('|');
                        String client = values[0];
                        String sa = values[1];
                        String sent_msg;
                        String recv_msg;
                        while (true)
                        {
                            Console.Write(username + ": ");
                            sent_msg = Console.ReadLine();
                            sent_msg = StringCipher.Encrypt(sent_msg, sa);
                            SendSocketMessage(clientSocket, sent_msg);
                            recv_msg = GetSocketMessage(clientSocket);
                            recv_msg = StringCipher.Decrypt(recv_msg, sa);
                            Console.WriteLine(client + ": " + recv_msg);
                        }
                    }
                    catch(Exception ex)
                    {
                        SendSocketMessage(clientSocket, "Can't read msg from Kerberos.");
                    }

                    // Close client Socket using the
                    // Close() method. After closing,
                    // we can use the closed Socket
                    // for a new Client Connection
                    clientSocket.Shutdown(SocketShutdown.Both);
                    clientSocket.Close();
                }
            }

            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }

        private static void SendSocketMessage(Socket socket, String message)
        {
            byte[] messageSent = Encoding.ASCII.GetBytes(message + "<EOF>");
            int byteSent = socket.Send(messageSent);
        }

        private static string GetSocketMessage(Socket clientSocket)
        {
            byte[] bytes = new Byte[1024];
            string data = null;
            while (true)
            {
                int numByte = clientSocket.Receive(bytes);

                data += Encoding.ASCII.GetString(bytes, 0, numByte);

                if (data.IndexOf("<EOF>") > -1)
                {
                    data = data.Replace("<EOF>", "");
                    break;
                }
            }
            return data;
        }
    }
}
