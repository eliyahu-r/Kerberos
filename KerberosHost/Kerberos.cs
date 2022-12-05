using Intel.Dal;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Util;

namespace KerberosHost
{
    class Kerberos
    {
        public static Jhi jhi = Jhi.Instance;
        public static JhiSession session;
        public static string appletID = "20ed36ef-cf57-45ca-a2a8-990e2c8a7df9";
        public static string appletPath = "C:/kabab\\Kerberos\\bin\\Kerberos.dalp";

        const int PORT = 11111;
        const int GETSTORAGECMD = 1;
        const int EDITSTORAGECMD = 2;
        const int GETRANDCMD = 3;
        const String KDCKEY = "Admin";


        static void Main(string[] args)
        {
            Jhi.DisableDllValidation = true;
            jhi = Jhi.Instance;
            jhi.Install(appletID, appletPath);

            // Start a session with the Trusted Application
            byte[] initBuffer = new byte[] { }; // Data to send to the applet onInit function
            Console.WriteLine("Opening a session.");
            jhi.CreateSession(appletID, JHI_SESSION_FLAGS.None, initBuffer, out session);

            Console.WriteLine("Welcome Kerberos Host! What would you like to do?");
            Console.WriteLine("What would you like to do?");
            DisplayMenu();
            while (true)
            {
                if (!int.TryParse(Console.ReadLine(), out int choice))
                {
                    choice = -1;
                }
                switch (choice)
                {
                    case 1:
                        ExecuteServer();
                        break;
                    case 2:
                        AddUser();
                        break;
                    case 3:
                        RemoveUser();
                        break;
                    case 4:
                        DisplayCurrentUsers();
                        break;
                    case 5:
                        DisplayMenu();
                        break;
                    case 0:
                        Console.WriteLine("Goodbye! o/ CatBoo");
                        break;
                    default:
                        Console.WriteLine("Invalid input. Press 4 to see help message.");
                        break;
                }
                if (choice == 0)
                    break;
                Console.WriteLine("Please press another number to perform the next operation.");
            }
            // Close the session
            Console.WriteLine("Closing the session.");
            jhi.CloseSession(session);

            //Uninstall the Trusted Application
            Console.WriteLine("Uninstalling the applet.");
            jhi.Uninstall(appletID);
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
                    String command = data.Split('|')[0];

                    String response;
                    switch (command)
                    {
                        case "TGT":
                            response = VerifyUser(data);
                            break;
                        case "MSG":
                            String[] info = data.Split('|');
                            String tgt = info[1];
                            String msg = info[2];
                            try 
                            {
                                tgt = StringCipher.Decrypt(tgt, KDCKEY);
                            }
                            catch(Exception ex)
                            {
                                Console.WriteLine(ex.Message);
                                response = "Error tgt";
                                break;
                            }
                            String sa = tgt.Split('|')[0];
                            String user = tgt.Split('|')[1];
                            String string_time = tgt.Split('|')[2];
                            Console.WriteLine("Message -> {0}", StringCipher.Decrypt(msg, sa));
                            
                            String user2 = StringCipher.Decrypt(msg, sa);

                            String stored_data = GetDataFromApplet();
                            String[] users = stored_data.Split('|');
                            response = "User doesn't exist in the system."; // Unless it is found
                            foreach (String server in users)
                            {
                                if (server.Split('@')[0] == user2)
                                {
                                    Console.WriteLine("Username found.");
                                    String password = server.Split('@')[1];
                                    String new_sa = GetRandBytesFromApplet();
                                    String MsgForServer = StringCipher.Encrypt(user + '|' + new_sa, password);
                                    response = new_sa + '|' + MsgForServer;
                                    response = StringCipher.Encrypt(response, sa);
                                    break;
                                }
                            }
                            break;
                        default:
                            response = "Invalid command type";
                            break;
                    }

                    SendSocketMessage(clientSocket, response);
                    
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

        private static String VerifyUser(string data)
        {
            String[] data_splitted = data.Split('|');
            if (data_splitted.Length != 4)
                return "User is not verified."; // Invalid message format
            String claimed_user = data_splitted[1];
            String encrypted_user = data_splitted[2];
            String encrypted_time = data_splitted[3];
            String stored_data = GetDataFromApplet();
            String[] users = stored_data.Split('|');
            foreach (String user in users)
            {
                if (user.Split('@')[0] == claimed_user)
                {
                    Console.WriteLine("Username found.");
                    String password = user.Split('@')[1];
                    String decrypted_user;
                    try
                    {
                        decrypted_user = StringCipher.Decrypt(encrypted_user, password);
                    }
                    catch(Exception e)
                    {
                        Console.WriteLine(e.Message);
                        return "User is not verified."; // Invalid encryption
                    }
                    if(claimed_user == decrypted_user)
                    {
                        Console.WriteLine("User's password is correct.");
                        String sent_time_string = StringCipher.Decrypt(encrypted_time, password);
                        try
                        {
                            DateTime sent_time = DateTime.Parse(sent_time_string);
                            Console.WriteLine("The specified date is valid: " + sent_time);
                            if (sent_time.AddMinutes(5) > DateTime.Now)
                            {
                                String SA = GetRandBytesFromApplet();
                                String TGT = SA + '|' + claimed_user + '|' + DateTime.Now.ToString();
                                TGT = StringCipher.Encrypt(TGT, KDCKEY);
                                String response = "User verified|" + SA + '|' + TGT;
                                response = StringCipher.Encrypt(response, password);
                                return response;
                            }
                            else
                                return "User is not verified."; // Date sent is too old, might be reply attack
                        }
                        catch (FormatException)
                        {
                            return "User is not verified."; // Date sent is invalid
                        }
                    }
                    else
                    {
                        return "User is not verified."; // Incorrect password
                    }
                }
            }
            return "User is not verified."; // User was not found in Database
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

        private static void AddUser()
        {
            Console.WriteLine("Please insert the new user's username: ");
            String username = Console.ReadLine();
            String stored_data = GetDataFromApplet();
            String[] users = stored_data.Split('|');
            foreach (String user in users)
            {
                if(user.Split('@')[0] == username)
                {
                    Console.WriteLine("This username already exists in the database.");
                    return;
                }
            }

            Console.WriteLine("Please insert the new user's password: ");
            String password = Console.ReadLine();
            password = StringHash.CalculateHash(password);
            String store = username + '@' + password + "|";
            stored_data += store;
            UpdateAplletStoredData(stored_data);
        }
        private static void RemoveUser()
        {
            Console.WriteLine("Please insert the username you would like to remove: ");
            String username = Console.ReadLine();
            String stored_data = GetDataFromApplet();
            String[] users = stored_data.Split('|');
            String new_stored_data = "";
            bool flag = false;
            foreach (String user in users)
            {
                Console.WriteLine(user);
                if (user.Split('@')[0] == username)
                    flag = true;
                else if (user != "")
                    new_stored_data += user + "|";
            }
            if(flag)
            {
                Console.WriteLine("User to delete was found. Updating the storage.");
                UpdateAplletStoredData(new_stored_data);
            }
            else
                Console.WriteLine("User to delete doesn't exist in the database.");
        }

        private static string GetDataFromApplet()
        {
            // Send and Receive data to/from the Trusted Application
            byte[] sendBuff = UTF32Encoding.UTF8.GetBytes("Hello"); // A message to send to the TA
            byte[] recvBuff = new byte[2000]; // A buffer to hold the output data from the TA
            int responseCode; // The return value that the TA provides using the IntelApplet.setResponseCode method
            int cmdId = GETSTORAGECMD; // The ID of the command to be performed by the TA
            jhi.SendAndRecv2(session, cmdId, sendBuff, ref recvBuff, out responseCode);
            return UTF32Encoding.UTF8.GetString(recvBuff);
        }

        private static void UpdateAplletStoredData(string store)
        {
            // Send and Receive data to/from the Trusted Application
            byte[] sendBuff = UTF32Encoding.UTF8.GetBytes(store); // A message to send to the TA
            byte[] recvBuff = new byte[2000]; // A buffer to hold the output data from the TA
            int responseCode; // The return value that the TA provides using the IntelApplet.setResponseCode method
            int cmdId = EDITSTORAGECMD; // The ID of the command to be performed by the TA
            Console.WriteLine("Performing send and receive operation.");
            jhi.SendAndRecv2(session, cmdId, sendBuff, ref recvBuff, out responseCode);
            Console.Out.WriteLine("Response buffer is " + UTF32Encoding.UTF8.GetString(recvBuff));
        }

        private static String GetRandBytesFromApplet()
        {
            // Send and Receive data to/from the Trusted Application
            byte[] sendBuff = UTF32Encoding.UTF8.GetBytes("Bytes"); // A message to send to the TA
            byte[] recvBuff = new byte[2000]; // A buffer to hold the output data from the TA
            int responseCode; // The return value that the TA provides using the IntelApplet.setResponseCode method
            int cmdId = GETRANDCMD; // The ID of the command to be performed by the TA
            Console.WriteLine("Performing send and receive operation.");
            jhi.SendAndRecv2(session, cmdId, sendBuff, ref recvBuff, out responseCode);
            String response = UTF32Encoding.UTF8.GetString(recvBuff);
            Console.Out.WriteLine("Response buffer is " + response);
            return response;
        }

        private static void DisplayCurrentUsers()
        {
            String data = GetDataFromApplet();
            Console.WriteLine("The current data stored in applet atm is: " + data);
            if (data == "")
                Console.WriteLine("There's no data stored in the MVM.");
        }

        static void DisplayMenu()
        {
            Console.WriteLine("Press 1 to execute server.");
            Console.WriteLine("Press 2 to add a user.");
            Console.WriteLine("Press 3 to remove a user.");
            Console.WriteLine("Press 4 to display current users stored in TEE.");
            Console.WriteLine("Press 5 to display this message again.");
            Console.WriteLine("Press 0 to exit.");
        }
    }
}