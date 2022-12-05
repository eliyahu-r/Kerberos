using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using Util;

namespace KerberosClient
{
    class Client
    {
        private static String username;
        private static String password;
        private static String SA = null;
        private static String TGT = null;

        private static readonly Dictionary<String, int> Users = new Dictionary<String, int>()
        {
            { "Bob", 22222 }
        };


        static void Main(string[] args)
        {
            Console.WriteLine("Welcome client! Please insert your kerberos identity.");
            InitializeUser();
            Console.WriteLine("What would you like to do?");
            DisplayMenu();
            while (true)
            {
                if (!int.TryParse(Console.ReadLine(), out int cmdId))
                {
                    cmdId = -1;
                }
                switch (cmdId)
                {
                    case 1:
                        GetTGT();
                        break;
                    case 2:
                        TalkToServer();
                        break;
                    case 3:
                        InitializeUser();
                        break;
                    case 4:
                        DisplayMenu();
                        break;
                    case 0:
                        Console.WriteLine("Goodbye! o/ CatBoo");
                        break;
                    default:
                        Console.WriteLine("Invalid input. Press 4 to see help message.");
                        break;
                }
                if (cmdId == 0)
                    break;
                Console.WriteLine("Please press another number to perform the next operation.");
            }

        }

        private static void InitializeUser()
        {
            Console.WriteLine("Username: ");
            username = Console.ReadLine();
            Console.WriteLine("Password: ");
            password = Console.ReadLine();
            password = StringHash.CalculateHash(password);
        }

        static void DisplayMenu()
        {
            Console.WriteLine("Press 1 in order to get a TGT from Kerberos host. (This step is necessery in order to use the network).");
            Console.WriteLine("Press 2 in order to communicate with a server in the network.");
            Console.WriteLine("Press 3 in order to switch to a different user.");
            Console.WriteLine("Press 4 to display this message again.");
            Console.WriteLine("Press 0 to exit.");
        }

        private static void GetTGT()
        {
            ExecuteClient("TGT", "Kerberos");
        }

        private static void TalkToServer()
        {
            if(TGT == null)
            {
                Console.WriteLine("Didn't get TGT from Kerberos server yet.");
                return;
            }
            Console.WriteLine("Which server would you like to talk to? Please write one of the following names:");
            foreach (string key in Users.Keys)
            {
                Console.WriteLine(key);
            }
            String ServerName = Console.ReadLine();
            while(!Users.Keys.Contains(ServerName))
            {
                Console.WriteLine("This server doesn't exist in your net. Please try again.");
                ServerName = Console.ReadLine();
            }

            ExecuteClient("MSG", ServerName);
        }

        private static void ExecuteClient(String cmd, String servname)
        {
            try
            {
                // Establish the remote endpoint
                // for the socket. This example
                // uses port 11111 on the local
                // computer.
                IPHostEntry ipHost = Dns.GetHostEntry(Dns.GetHostName());
                IPAddress ipAddr = ipHost.AddressList[0];
                IPEndPoint localEndPoint = new IPEndPoint(ipAddr, 11111);

                // Creation TCP/IP Socket using
                // Socket Class Constructor
                Socket sender = new Socket(ipAddr.AddressFamily,
                           SocketType.Stream, ProtocolType.Tcp);

                try
                {
                    // Connect Socket to the remote
                    // endpoint using method Connect()
                    sender.Connect(localEndPoint);

                    // We print EndPoint information
                    // that we are connected
                    Console.WriteLine("Connected to Kerberos successfully. Address -> {0} ",
                                  sender.RemoteEndPoint.ToString());

                    switch(cmd)
                    {
                        case "TGT":
                            String message;
                            message = "TGT|" + username + '|' + StringCipher.Encrypt(username, password) + '|' +
                                StringCipher.Encrypt(DateTime.Now.ToString(), password);
                            Console.WriteLine("Sending Kerberos login message");
                            SendSocketMessage(sender, message);

                            String response = GetSocketMessage(sender);
                            try
                            {
                                response = StringCipher.Decrypt(response, password);
                                String[] resps = response.Split('|');
                                Console.WriteLine("Message from Server -> {0}", resps[0]);
                                SA = resps[1];
                                Console.WriteLine("Session key -> {0}", SA);
                                TGT = resps[2];
                                Console.WriteLine("TGT -> {0}", TGT);
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine(ex.Message);
                                Console.WriteLine("Message from Server -> {0}", response);
                            }
                            break;
                        case "MSG":
                            message = "MSG|" + TGT + '|' + StringCipher.Encrypt(servname, SA);
                            Console.WriteLine("Sending Kerberos request message");
                            SendSocketMessage(sender, message);

                            response = GetSocketMessage(sender);
                            try
                            {
                                response = StringCipher.Decrypt(response, SA);
                                String[] responses = response.Split('|');
                                String new_sa = responses[0];
                                String msg_to_server = responses[1];
                                Console.WriteLine("New sa -> {0}", new_sa);
                                Console.WriteLine("Msg to " + servname + " -> {0}", msg_to_server);
                                Console.WriteLine("Press anything to start chat with " + servname);
                                Console.ReadKey();
                                StartChatWithServer(servname, new_sa, msg_to_server);
                            }
                            catch (Exception ex)
                            {
                                Console.WriteLine("Message from Server -> {0}", response);
                            }
                            break;
                    }
                        
                    
                }

                // Manage of Socket's Exceptions
                catch (ArgumentNullException ane)
                {

                    Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
                }

                catch (SocketException se)
                {

                    Console.WriteLine("SocketException : {0}", se.ToString());
                }

                catch (Exception e)
                {
                    Console.WriteLine("Unexpected exception : {0}", e.ToString());
                }
            }

            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
        }

        private static void StartChatWithServer(string servname, string sa, string msg_to_server)
        {
            try
            {
                // Establish the remote endpoint
                // for the socket. This example
                // uses port 11111 on the local
                // computer.
                IPHostEntry ipHost = Dns.GetHostEntry(Dns.GetHostName());
                IPAddress ipAddr = ipHost.AddressList[0];
                IPEndPoint localEndPoint = new IPEndPoint(ipAddr, Users[servname]);

                // Creation TCP/IP Socket using
                // Socket Class Constructor
                Socket sender = new Socket(ipAddr.AddressFamily,
                           SocketType.Stream, ProtocolType.Tcp);

                try
                {
                    // Connect Socket to the remote
                    // endpoint using method Connect()
                    sender.Connect(localEndPoint);

                    // We print EndPoint information
                    // that we are connected
                    Console.WriteLine("Connected to server successfully. Address -> {0} ",
                                  sender.RemoteEndPoint.ToString());
                    String sent_msg = msg_to_server;
                    String recv_msg;
                    while(true)
                    {
                        SendSocketMessage(sender, sent_msg);
                        recv_msg = GetSocketMessage(sender);
                        recv_msg = StringCipher.Decrypt(recv_msg, sa);
                        Console.WriteLine(servname + ": " + recv_msg);
                        Console.Write(username + ": ");
                        sent_msg = Console.ReadLine();
                        sent_msg = StringCipher.Encrypt(sent_msg, sa);
                    }


                }

                // Manage of Socket's Exceptions
                catch (ArgumentNullException ane)
                {

                    Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
                }

                catch (SocketException se)
                {

                    Console.WriteLine("SocketException : {0}", se.ToString());
                }

                catch (Exception e)
                {
                    Console.WriteLine("Unexpected exception : {0}", e.ToString());
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

        private static string GetSocketMessage(Socket socket)
        {
            byte[] bytes = new Byte[1024];
            string data = null;
            while (true)
            {
                int numByte = socket.Receive(bytes);

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
